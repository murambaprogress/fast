from django.shortcuts import render
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.views import View
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
import json
from datetime import datetime, timedelta
from .models import Booking, Flight, FlightSchedule
from .serializers import BookingSerializer, FlightSerializer, FlightScheduleSerializer, FlightScheduleCreateSerializer

# Flight Management Views
class FlightListCreateView(generics.ListCreateAPIView):
    queryset = Flight.objects.all()
    serializer_class = FlightSerializer

class FlightDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Flight.objects.all()
    serializer_class = FlightSerializer

class FlightScheduleListCreateView(generics.ListCreateAPIView):
    queryset = FlightSchedule.objects.all()

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return FlightScheduleCreateSerializer
        return FlightScheduleSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save()

class FlightScheduleDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = FlightSchedule.objects.all()
    serializer_class = FlightScheduleSerializer

# Flight Search View
class FlightSearchView(APIView):
    def post(self, request):
        from_destination = request.data.get('from_destination')
        to_destination = request.data.get('to_destination')
        departure_date = request.data.get('departure_date')
        return_date = request.data.get('return_date')
        trip_type = request.data.get('trip_type')
        adult_count = request.data.get('adult_count', 1)
        child_count = request.data.get('child_count', 0)

        flights = FlightSchedule.objects.filter(is_active=True)

        if from_destination:
            flights = flights.filter(flight__route__from_destination__name=from_destination)
        if to_destination:
            flights = flights.filter(flight__route__to_destination__name=to_destination)
        if departure_date:
            flights = flights.filter(departure_time__date=departure_date)

        outbound_serializer = FlightScheduleSerializer(flights, many=True)

        return Response({
            "trip_type": trip_type,
            "from_destination": from_destination,
            "to_destination": to_destination,
            "departure_date": departure_date,
            "return_date": return_date,
            "passenger_count": {
                "adults": adult_count,
                "children": child_count,
                "total": int(adult_count) + int(child_count)
            },
            "outbound_flights": outbound_serializer.data,
            "return_flights": [],
        })

User = get_user_model()

# Enhanced Booking Views with Loyalty Points
class CreateBookingView(APIView):
    def post(self, request):
        try:
            data = request.data
            user_id = data.get('user_id')
            if not user_id:
                return Response({'error': 'User ID is required'}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.get(id=user_id)
            flight_schedule_id = data.get('flight_schedule_id')
            return_schedule_id = data.get('return_schedule_id')
            adult_count = int(data.get('adult_count', 1))
            child_count = int(data.get('child_count', 0))
            payment_method = data.get('payment_method')
            trip_type = data.get('trip_type')

            total_passengers = adult_count + child_count
            flight_schedule = FlightSchedule.objects.get(id=flight_schedule_id)

            if flight_schedule.available_seats < total_passengers:
                return Response({'error': 'Not enough seats available'}, status=status.HTTP_400_BAD_REQUEST)

            return_schedule = None
            if return_schedule_id:
                return_schedule = FlightSchedule.objects.get(id=return_schedule_id)

            total_price = float(flight_schedule.route.price) * total_passengers
            if trip_type == "round_trip" and return_schedule:
                total_price += float(return_schedule.route.price) * total_passengers

            # Create booking
            booking = Booking.objects.create(
                user=user,
                trip_type=trip_type,
                outbound_schedule=flight_schedule,
                return_schedule=return_schedule,
                adult_count=adult_count,
                child_count=child_count,
                base_price=total_price,
                total_price=total_price,
                currency=flight_schedule.route.currency,
                payment_method=payment_method,
                contact_phone=data.get('contact_phone', ''),
                contact_email=data.get('contact_email', ''),
                special_requests=data.get('special_requests', '')
            )

            # Award loyalty points (50 points for wallet payments)
            earned_points = 0
            if payment_method == 'wallet':
                earned_points = 50
                from loyalty.models import LoyaltyAccount, LoyaltyTransaction
                
                loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
                loyalty_account.add_points(earned_points, f'Earned 50 points for booking {booking.booking_reference}')

                booking.points_earned = earned_points
                booking.save()

            return Response({
                'booking_id': booking.id,
                'booking_reference': booking.booking_reference,
                'status': booking.status,
                'points_earned': earned_points,
                'total_price': total_price
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except FlightSchedule.DoesNotExist:
            return Response({'error': 'Flight schedule not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProcessPaymentView(APIView):
    def post(self, request):
        try:
            data = request.data
            booking_id = data.get('booking_id')
            payment_method = data.get('payment_method')
            
            booking = Booking.objects.get(id=booking_id)
            
            if payment_method == 'points':
                # Handle points payment
                from loyalty.models import LoyaltyAccount
                loyalty_account = LoyaltyAccount.objects.get(user=booking.user)
                
                POINTS_FOR_FREE_FLIGHT = 1000  # Fixed points required for a free flight
                
                if loyalty_account.points < POINTS_FOR_FREE_FLIGHT:
                    return Response({
                        'error': 'Insufficient points',
                        'required': POINTS_FOR_FREE_FLIGHT,
                        'available': loyalty_account.points
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Deduct ALL available points, as per user's request "all the points are reset to 0"
                points_to_deduct = loyalty_account.points 
                
                loyalty_account.deduct_points(
                    points_to_deduct, 
                    f'Payment for booking {booking.booking_reference} (Free Flight)'
                )
                
                booking.payment_status = 'paid'
                booking.status = 'confirmed'
                booking.points_used = points_to_deduct # Record how many points were actually used
                booking.save()
                
                return Response({
                    'payment_id': booking.id,
                    'status': 'completed',
                    'booking_id': booking_id,
                    'points_used': points_to_deduct
                })
            
            # Handle other payment methods
            booking.payment_status = 'paid'
            booking.status = 'confirmed'
            booking.save()
            
            return Response({
                'payment_id': booking.id,
                'status': 'completed',
                'booking_id': booking_id
            })
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# User Booking Views
@api_view(['GET'])
def get_user_bookings(request):
    try:
        user_id = request.GET.get('user_id')
        if user_id:
            bookings = Booking.objects.filter(user_id=user_id).order_by('-created_at')
        else:
            bookings = Booking.objects.all().order_by('-created_at')
        
        serializer = BookingSerializer(bookings, many=True)
        return Response(serializer.data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def get_booking_detail(request, booking_id):
    try:
        booking = Booking.objects.get(id=booking_id)
        serializer = BookingSerializer(booking)
        return Response(serializer.data)
    except Booking.DoesNotExist:
        return Response({'error': 'Booking not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def cancel_booking(request, booking_id):
    try:
        booking = Booking.objects.get(id=booking_id)
        booking.status = 'cancelled'
        booking.save()
        return Response({'status': 'cancelled'})
    except Booking.DoesNotExist:
        return Response({'error': 'Booking not found'}, status=status.HTTP_404_NOT_FOUND)

# Reference Data Views
@api_view(['GET'])
def get_destinations(request):
    try:
        from destinations.models import Destination
        destinations = Destination.objects.all()
        data = [
            {
                'id': dest.id,
                'name': dest.name,
                'code': dest.code,
                'country': dest.country
            }
            for dest in destinations
        ]
        return Response(data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def get_routes(request):
    try:
        from routes.models import Route
        routes = Route.objects.all()
        data = [
            {
                'id': route.id,
                'from_destination': {
                    'id': route.from_destination.id,
                    'name': route.from_destination.name,
                    'code': route.from_destination.code
                },
                'to_destination': {
                    'id': route.to_destination.id,
                    'name': route.to_destination.name,
                    'code': route.to_destination.code
                },
                'price': str(route.price),
                'currency': route.currency,
                'estimated_time': route.estimated_time,
                'distance': route.distance,
                'point_threshold': route.point_threshold
            }
            for route in routes
        ]
        return Response(data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def get_flights(request):
    try:
        flights = Flight.objects.all()
        serializer = FlightSerializer(flights, many=True)
        return Response(serializer.data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
