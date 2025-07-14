from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .models import LoyaltyAccount, LoyaltyTransaction, PointRedemption
from .serializers import (
    LoyaltyAccountSerializer, LoyaltyTransactionSerializer, 
    PointRedemptionSerializer, RedemptionCreateSerializer
)

User = get_user_model()

@api_view(['GET'])
def get_user_points(request):
    """Get user's current points"""
    user_id = request.GET.get('user_id')
    if not user_id:
        return Response({'error': 'User ID required'}, status=status.HTTP_400_BAD_REQUEST)
    
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
def get_user_transactions(request):
    """Get user's loyalty transactions"""
    user_id = request.GET.get('user_id')
    if not user_id:
        return Response({'error': 'User ID required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(id=user_id)
        transactions = LoyaltyTransaction.objects.filter(user=user)
        serializer = LoyaltyTransactionSerializer(transactions, many=True)
        return Response(serializer.data)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET', 'POST'])
def redemption_view(request):
    """Get user's redemption history or create new redemption"""
    user_id = request.GET.get('user_id') or request.data.get('user_id')
    if not user_id:
        return Response({'error': 'User ID required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        redemptions = PointRedemption.objects.filter(user=user)
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
def admin_redemptions(request):
    """Get all redemption requests for admin"""
    redemptions = PointRedemption.objects.all()
    serializer = PointRedemptionSerializer(redemptions, many=True)
    return Response(serializer.data)

@api_view(['PATCH'])
def admin_redemption_action(request, redemption_id):
    """Approve or reject redemption"""
    try:
        redemption = PointRedemption.objects.get(id=redemption_id)
        action = request.data.get('action')
        notes = request.data.get('notes', '')
        
        # For now, we'll use a dummy admin user
        admin_user = User.objects.filter(is_staff=True).first()
        if not admin_user:
            admin_user = User.objects.first()  # Fallback
        
        if action == 'approve':
            redemption.approve(admin_user, notes)
            return Response({'message': 'Redemption approved successfully'})
        elif action == 'reject':
            redemption.reject(admin_user, notes)
            return Response({'message': 'Redemption rejected successfully'})
        else:
            return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
    except PointRedemption.DoesNotExist:
        return Response({'error': 'Redemption not found'}, status=status.HTTP_404_NOT_FOUND)
