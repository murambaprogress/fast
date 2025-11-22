from rest_framework import serializers
from django.utils import timezone
from datetime import datetime, timedelta
from .models import (
    Flight, FlightSchedule, Booking, Passenger, BookingPayment, BookingHistory
)
from routes.models import Route, Destination
from routes.serializers import RouteSerializer
from wallets.models import Wallet, WalletBalance

class FlightCreateSerializer(serializers.ModelSerializer):
    route_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = Flight
        fields = [
            'flight_number', 'route_id', 'aircraft_type', 'aircraft_registration',
            'flight_duration', 'max_passengers', 
            'has_business_class', 'has_economy_class', 
            'business_class_seats', 'economy_class_seats',
            'is_active', 'is_seasonal', 'operational_days', 'notes'
        ]
    
    def validate_route_id(self, value):
        try:
            Route.objects.get(id=value)
            return value
        except Route.DoesNotExist:
            raise serializers.ValidationError("Route not found")
    
    def validate_flight_number(self, value):
        # Check if flight number already exists
        if Flight.objects.filter(flight_number=value).exists():
            raise serializers.ValidationError("Flight number already exists")
        return value
    
    def validate(self, data):
        # Validate seat configuration
        if data.get('has_business_class') and data.get('business_class_seats', 0) <= 0:
            raise serializers.ValidationError("Business class seats must be greater than 0 if business class is enabled")
        
        if data.get('has_economy_class') and data.get('economy_class_seats', 0) <= 0:
            raise serializers.ValidationError("Economy class seats must be greater than 0 if economy class is enabled")
        
        # Ensure at least one class is enabled
        if not data.get('has_business_class') and not data.get('has_economy_class'):
            raise serializers.ValidationError("At least one service class must be enabled")
        
        # Validate total seats don't exceed max passengers
        total_seats = data.get('business_class_seats', 0) + data.get('economy_class_seats', 0)
        if total_seats > data.get('max_passengers', 0):
            raise serializers.ValidationError("Total seats cannot exceed maximum passenger capacity")
        
        return data
    
    def create(self, validated_data):
        route_id = validated_data.pop('route_id')
        route = Route.objects.get(id=route_id)
        flight = Flight.objects.create(route=route, **validated_data)
        return flight

class FlightSerializer(serializers.ModelSerializer):
    route = serializers.PrimaryKeyRelatedField(queryset=Route.objects.all())
    operational_days_display = serializers.SerializerMethodField()
    
    class Meta:
        model = Flight
        fields = '__all__'
    
    def get_route(self, obj):
        try:
            if obj.route:  # The flight object itself has a route attribute
                route = obj.route
                return {
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
        except Exception:
            pass  # Optionally log the error here for debugging
        return None

    def get_operational_days_display(self, obj):
        if obj.operational_days:
            days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            return ', '.join([days[day] for day in obj.operational_days])
        return 'Daily'

    def update(self, instance, validated_data):
        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        return instance

class FlightScheduleCreateSerializer(serializers.ModelSerializer):
    flight_id = serializers.PrimaryKeyRelatedField(queryset=Flight.objects.all(), source='flight')

    class Meta:
        model = FlightSchedule
        fields = [
            'flight_id', 'departure_time', 'arrival_time', 
            'total_seats', 'price_multiplier',
            'gate_number', 'check_in_time', 'boarding_time',
            'is_active'
        ]

    def validate(self, data):
        if data['departure_time'] >= data['arrival_time']:
            raise serializers.ValidationError("Departure time must be before arrival time")
        return data

    def create(self, validated_data):
        return FlightSchedule.objects.create(**validated_data)

class FlightScheduleSerializer(serializers.ModelSerializer):
    flight = FlightSerializer(read_only=True)
    price = serializers.SerializerMethodField()
    currency = serializers.SerializerMethodField()
    estimated_time = serializers.SerializerMethodField()
    distance = serializers.SerializerMethodField()
    point_threshold = serializers.SerializerMethodField()
    # Convenience flattened fields expected by some frontend components
    route = serializers.SerializerMethodField()
    from_destination = serializers.SerializerMethodField()
    to_destination = serializers.SerializerMethodField()

    class Meta:
        model = FlightSchedule
        fields = '__all__'

    def get_route(self, obj):
        try:
            r = obj.flight.route
            return {
                'id': r.id,
                'from_destination': {
                    'id': r.from_destination.id,
                    'name': r.from_destination.name,
                },
                'to_destination': {
                    'id': r.to_destination.id,
                    'name': r.to_destination.name,
                },
                'price': str(r.price),
                'currency': r.currency,
                'estimated_time': r.estimated_time,
                'distance': r.distance,
                'point_threshold': r.point_threshold,
            }
        except Exception:
            return None

    def get_from_destination(self, obj):
        try:
            return obj.flight.route.from_destination.name
        except Exception:
            return ''

    def get_to_destination(self, obj):
        try:
            return obj.flight.route.to_destination.name
        except Exception:
            return ''

    def get_price(self, obj):
        try:
            return str(obj.flight.route.price)
        except:
            return "0.00"

    def get_currency(self, obj):
        try:
            return obj.flight.route.currency
        except:
            return "USD"

    def get_estimated_time(self, obj):
        try:
            return obj.flight.route.estimated_time
        except:
            return ""

    def get_distance(self, obj):
        try:
            return obj.flight.route.distance
        except:
            return ""

    def get_point_threshold(self, obj):
        try:
            return obj.flight.route.point_threshold
        except:
            return 0

class PassengerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Passenger
        fields = '__all__'

class BookingPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = BookingPayment
        fields = '__all__'

class BookingSerializer(serializers.ModelSerializer):
    flight_schedule = FlightScheduleSerializer(read_only=True)
    
    class Meta:
        model = Booking
        fields = '__all__'

class FlightSearchSerializer(serializers.Serializer):
    from_destination = serializers.CharField(max_length=100)
    to_destination = serializers.CharField(max_length=100)
    departure_date = serializers.DateField()
    return_date = serializers.DateField(required=False, allow_null=True)
    trip_type = serializers.ChoiceField(choices=[('one_way', 'One Way'), ('round_trip', 'Round Trip')])
    adult_count = serializers.IntegerField(min_value=1, default=1)
    child_count = serializers.IntegerField(min_value=0, default=0)

    def validate(self, data):
        # Validate return date for round trips
        if data['trip_type'] == 'round_trip':
            if not data.get('return_date'):
                raise serializers.ValidationError("Return date is required for round trips")
            if data['return_date'] <= data['departure_date']:
                raise serializers.ValidationError("Return date must be after departure date")
        
        # Validate dates are not in the past
        if data['departure_date'] < timezone.now().date():
            raise serializers.ValidationError("Departure date cannot be in the past")
            
        return data

from django.contrib.auth import get_user_model

class BookingCreateSerializer(serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=get_user_model().objects.all(),
        source='user',  # map to model's 'user' field
        write_only=True
    )

    class Meta:
        model = Booking
        fields = [
            'user_id',
            'trip_type',
            'adult_count',
            'child_count',
            'payment_method',
            'special_requests',
            'contact_phone',
            'contact_email'
        ]

class PaymentProcessSerializer(serializers.Serializer):
    booking_id = serializers.IntegerField()
    payment_method = serializers.ChoiceField(choices=[
        ('wallet', 'FastJet Wallet'),
        ('cash', 'Cash at Office'),
        ('points', 'Redeemed Points')
    ])
