from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .models import LoyaltyAccount, LoyaltyTransaction, PointRedemption
from booking.models import Booking, FlightSchedule
from django.db import transaction
from .serializers import (
    LoyaltyAccountSerializer, LoyaltyTransactionSerializer, 
    PointRedemptionSerializer, RedemptionCreateSerializer
)

User = get_user_model()

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_points(request):
    """Get user's current points"""
    user_id = request.GET.get('user_id')
    if not user_id:
        return Response({'error': 'User ID required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Allow users to only access their own points, unless they're admin
    if not request.user.is_staff and str(request.user.id) != str(user_id):
        return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        user = User.objects.get(id=user_id)
        loyalty_account, created = LoyaltyAccount.objects.get_or_create(user=user)
        return Response({
            'points': loyalty_account.points,
            'lifetime_points': loyalty_account.lifetime_points,
            'tier': loyalty_account.tier,
            'can_redeem_free_flight': loyalty_account.can_redeem_free_flight()
        })
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_transactions(request):
    """Get user's loyalty transactions"""
    user_id = request.GET.get('user_id')
    if not user_id:
        return Response({'error': 'User ID required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Allow users to only access their own transactions, unless they're admin
    if not request.user.is_staff and str(request.user.id) != str(user_id):
        return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        user = User.objects.get(id=user_id)
        transactions = LoyaltyTransaction.objects.filter(user=user).order_by('-created_at')
        serializer = LoyaltyTransactionSerializer(transactions, many=True)
        return Response(serializer.data)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def redemption_view(request):
    """Get user's redemption history or create new redemption"""
    user_id = request.GET.get('user_id') or request.data.get('user_id')
    if not user_id:
        return Response({'error': 'User ID required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Allow users to only access their own redemptions, unless they're admin
    if not request.user.is_staff and str(request.user.id) != str(user_id):
        return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        redemptions = PointRedemption.objects.filter(user=user).order_by('-created_at')
        serializer = PointRedemptionSerializer(redemptions, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        # Create new redemption request
        serializer = RedemptionCreateSerializer(data=request.data, context={'request': type('obj', (object,), {'user': user})()})
        if serializer.is_valid():
            redemption = serializer.save(user=user)
            return Response({
                'message': 'Redemption request submitted successfully',
                'redemption_id': redemption.id,
                'status': 'pending'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_redemptions(request):
    """Get all redemption requests for admin"""
    if not request.user.is_staff:
        return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
    
    redemptions = PointRedemption.objects.all().order_by('-created_at')
    serializer = PointRedemptionSerializer(redemptions, many=True)
    return Response(serializer.data)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def admin_redemption_action(request, redemption_id):
    """Approve or reject redemption"""
    if not request.user.is_staff:
        return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        redemption = PointRedemption.objects.get(id=redemption_id)
        action = request.data.get('action')
        notes = request.data.get('notes', '')
        
        admin_user = request.user
        
        if action == 'approve':
            # For free flight, optionally create booking immediately if flight_schedule_id provided
            flight_schedule_id = request.data.get('flight_schedule_id')
            with transaction.atomic():
                redemption.approve(admin_user, notes)
                created_booking_ref = None
                if redemption.redemption_type == 'free_flight' and flight_schedule_id:
                    try:
                        schedule = FlightSchedule.objects.select_for_update().get(id=flight_schedule_id)
                        loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=redemption.user)
                        if not loyalty_account.can_redeem_free_flight():
                            return Response({'error':'User no longer has enough points'}, status=status.HTTP_400_BAD_REQUEST)
                        # Reserve 1 seat (assuming single passenger free ticket)
                        if schedule.available_seats <= 0:
                            return Response({'error':'Selected flight has no available seats'}, status=status.HTTP_400_BAD_REQUEST)
                        schedule.available_seats -= 1
                        schedule.save()
                        # Deduct points
                        if not loyalty_account.deduct_points(1000, description='Free flight redemption'):
                            return Response({'error':'Point deduction failed'}, status=status.HTTP_400_BAD_REQUEST)
                        # Create booking (one_way, 1 adult)
                        booking = Booking.objects.create(
                            user=redemption.user,
                            trip_type='one_way',
                            outbound_schedule=schedule,
                            base_price=0,
                            total_price=0,
                            currency=schedule.route.currency,
                            payment_method='points',
                            payment_status='paid',
                            points_used=1000,
                            points_earned=0,
                            is_installment=False,
                            status='confirmed',
                            adult_count=1,
                            child_count=0,
                        )
                        created_booking_ref = booking.booking_reference
                    except FlightSchedule.DoesNotExist:
                        return Response({'error':'Flight schedule not found'}, status=status.HTTP_404_NOT_FOUND)
                return Response({'message': 'Redemption approved successfully', 'booking_reference': created_booking_ref})
        elif action == 'reject':
            redemption.reject(admin_user, notes)
            return Response({'message': 'Redemption rejected successfully'})
        else:
            return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
    except PointRedemption.DoesNotExist:
        return Response({'error': 'Redemption not found'}, status=status.HTTP_404_NOT_FOUND)
