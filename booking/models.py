from django.db import models
from django.contrib.auth import get_user_model
from routes.models import Route
from decimal import Decimal
from django.core.validators import MinValueValidator
import uuid
from datetime import timedelta, datetime
from django.utils import timezone

User = get_user_model()

TRIP_TYPE_CHOICES = [
    ('one_way', 'One Way'),
    ('round_trip', 'Round Trip'),
]

PASSENGER_TYPE_CHOICES = [
    ('adult', 'Adult'),
    ('child', 'Child'),
]

PAYMENT_METHOD_CHOICES = [
    ('wallet', 'FastJet Wallet'),
    ('cash', 'Cash at Office'),
    ('points', 'Redeemed Points'),
    ('installment', 'Installment Payment'),
]

BOOKING_STATUS_CHOICES = [
    ('pending', 'Pending'),
    ('confirmed', 'Confirmed'),
    ('cancelled', 'Cancelled'),
    ('completed', 'Completed'),
    ('laybuy', 'Laybuy'), # New status for installment bookings
    ('under_payment', 'Under Payment'), # Legacy status for installment bookings
]

PAYMENT_STATUS_CHOICES = [
    ('pending', 'Pending'),
    ('paid', 'Paid'),
    ('failed', 'Failed'),
    ('refunded', 'Refunded'),
    ('partial', 'Partially Paid'), # New status for installments
]

class Flight(models.Model):
    """Flight model that references routes"""
    flight_number = models.CharField(max_length=10, unique=True, help_text="Unique flight identifier (e.g., FJ001)")
    route = models.ForeignKey(Route, on_delete=models.CASCADE, related_name='flights')
    aircraft_type = models.CharField(max_length=50, default='Boeing 737', help_text="Type of aircraft")
    aircraft_registration = models.CharField(max_length=20, blank=True, help_text="Aircraft registration number")
    
    # Flight details
    flight_duration = models.DurationField(help_text="Actual flight duration")
    max_passengers = models.IntegerField(default=150, help_text="Maximum passenger capacity")
    
    # Operational details
    is_active = models.BooleanField(default=True, help_text="Whether this flight is currently operational")
    is_seasonal = models.BooleanField(default=False, help_text="Whether this is a seasonal flight")
    
    # Service class options
    has_business_class = models.BooleanField(default=False)
    has_economy_class = models.BooleanField(default=True)
    business_class_seats = models.IntegerField(default=0)
    economy_class_seats = models.IntegerField(default=150)
    
    # Operational days (JSON field to store days of week)
    operational_days = models.JSONField(
        default=list,
        help_text="Days of the week this flight operates (0=Monday, 6=Sunday)",
        blank=True
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Additional metadata
    notes = models.TextField(blank=True, help_text="Additional notes about this flight")

    class Meta:
        ordering = ['flight_number']
        verbose_name = 'Flight'
        verbose_name_plural = 'Flights'

    def __str__(self):
        return f"{self.flight_number} - {self.route}"

    @property
    def total_seats(self):
        """Calculate total available seats"""
        return self.business_class_seats + self.economy_class_seats

    @property
    def from_destination(self):
        """Get departure destination"""
        return self.route.from_destination

    @property
    def to_destination(self):
        """Get arrival destination"""
        return self.route.to_destination

    @property
    def base_price(self):
        """Get base price from route"""
        return self.route.price

    @property
    def currency(self):
        """Get currency from route"""
        return self.route.currency

    def get_operational_days_display(self):
        """Get human-readable operational days"""
        days_map = {
            0: 'Monday', 1: 'Tuesday', 2: 'Wednesday', 3: 'Thursday',
            4: 'Friday', 5: 'Saturday', 6: 'Sunday'
        }
        if not self.operational_days:
            return "Daily"
        return ", ".join([days_map.get(day, str(day)) for day in sorted(self.operational_days)])

    def is_operational_on_day(self, day_of_week):
        """Check if flight operates on a specific day (0=Monday, 6=Sunday)"""
        if not self.operational_days:
            return True  # If no specific days set, assume daily operation
        return day_of_week in self.operational_days

    def clean(self):
        """Validate the model"""
        from django.core.exceptions import ValidationError
        
        # Ensure total seats don't exceed max passengers
        if self.total_seats > self.max_passengers:
            raise ValidationError("Total seats cannot exceed maximum passenger capacity")
        
        # Ensure at least one class is available
        if not self.has_business_class and not self.has_economy_class:
            raise ValidationError("At least one service class must be available")
        
        # Validate operational days
        if self.operational_days:
            for day in self.operational_days:
                if not isinstance(day, int) or day < 0 or day > 6:
                    raise ValidationError("Operational days must be integers between 0 (Monday) and 6 (Sunday)")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

class FlightSchedule(models.Model):
    """Available flight schedules for flights"""
    flight = models.ForeignKey(Flight, on_delete=models.CASCADE, related_name='schedules')
    departure_time = models.DateTimeField()
    arrival_time = models.DateTimeField()
    available_seats = models.IntegerField(default=50)
    total_seats = models.IntegerField(default=50)
    
    # Pricing can vary by schedule
    price_multiplier = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=Decimal('1.00'),
        help_text="Multiplier for base route price (e.g., 1.5 for peak times)"
    )
    
    # Schedule-specific details
    gate_number = models.CharField(max_length=10, blank=True)
    check_in_time = models.DurationField(
        default=timedelta(hours=2),
        help_text="Check-in time before departure"
    )
    boarding_time = models.DurationField(
        default=timedelta(minutes=30),
        help_text="Boarding time before departure"
    )
    
    # Status
    is_active = models.BooleanField(default=True)
    is_delayed = models.BooleanField(default=False)
    delay_reason = models.CharField(max_length=200, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['departure_time']
        unique_together = ['flight', 'departure_time']
        verbose_name = 'Flight Schedule'
        verbose_name_plural = 'Flight Schedules'

    def __str__(self):
        return f"{self.flight.flight_number} - {self.departure_time.strftime('%Y-%m-%d %H:%M')}"

    @property
    def route(self):
        """Get route from flight"""
        return self.flight.route

    @property
    def actual_price(self):
        """Calculate actual price with multiplier"""
        return self.flight.base_price * self.price_multiplier

    @property
    def is_available(self):
        return self.available_seats > 0 and self.is_active and not self.is_delayed

    @property
    def check_in_deadline(self):
        """Calculate check-in deadline"""
        return self.departure_time - self.check_in_time

    @property
    def boarding_deadline(self):
        """Calculate boarding deadline"""
        return self.departure_time - self.boarding_time

    def reserve_seats(self, count):
        """Reserve seats for booking"""
        if self.available_seats >= count:
            self.available_seats -= count
            self.save()
            return True
        return False

    def release_seats(self, count):
        """Release seats when booking is cancelled"""
        self.available_seats = min(self.total_seats, self.available_seats + count)
        self.save()

    def clean(self):
        """Validate the model"""
        from django.core.exceptions import ValidationError
        
        # Ensure departure is before arrival
        if self.departure_time >= self.arrival_time:
            raise ValidationError("Departure time must be before arrival time")
        
        # Ensure total seats don't exceed flight capacity
        if self.total_seats > self.flight.max_passengers:
            raise ValidationError("Total seats cannot exceed flight capacity")
        
        # Validate operational day
        day_of_week = self.departure_time.weekday()
        if not self.flight.is_operational_on_day(day_of_week):
            raise ValidationError(f"Flight {self.flight.flight_number} does not operate on {self.departure_time.strftime('%A')}")

    def save(self, *args, **kwargs):
        # Set total_seats from flight if not specified
        if not self.total_seats:
            self.total_seats = self.flight.total_seats
        
        # Set available_seats to total_seats if not specified
        if not self.available_seats:
            self.available_seats = self.total_seats
            
        self.full_clean()
        super().save(*args, **kwargs)

class Booking(models.Model):
    """Main booking model"""
    booking_reference = models.CharField(max_length=20, unique=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bookings')
    trip_type = models.CharField(max_length=20, choices=TRIP_TYPE_CHOICES, default='one_way')
    
    # Outbound flight
    outbound_schedule = models.ForeignKey(
        FlightSchedule, 
        on_delete=models.CASCADE, 
        related_name='outbound_bookings'
    )
    
    # Return flight (for round trips)
    return_schedule = models.ForeignKey(
        FlightSchedule, 
        on_delete=models.CASCADE, 
        related_name='return_bookings',
        null=True, 
        blank=True
    )
    
    # Passenger counts
    adult_count = models.IntegerField(default=1, validators=[MinValueValidator(1)])
    child_count = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    
    # Pricing
    base_price = models.DecimalField(max_digits=10, decimal_places=2)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    
    # Payment
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES)
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    points_used = models.IntegerField(default=0)
    points_earned = models.IntegerField(default=0)
    
    # Installment fields
    is_installment = models.BooleanField(default=False)
    installment_total = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    installment_count = models.IntegerField(default=0)
    installment_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    installment_deadline = models.DateTimeField(null=True, blank=True)
    
    # Status
    status = models.CharField(max_length=20, choices=BOOKING_STATUS_CHOICES, default='pending')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Additional info
    special_requests = models.TextField(blank=True)
    contact_phone = models.CharField(max_length=20, blank=True)
    contact_email = models.EmailField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.booking_reference:
            self.booking_reference = self.generate_booking_reference()
        super().save(*args, **kwargs)

    def generate_booking_reference(self):
        """Generate unique booking reference"""
        import random
        import string
        while True:
            ref = 'FJ' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not Booking.objects.filter(booking_reference=ref).exists():
                return ref

    def __str__(self):
        return f"Booking {self.booking_reference} - {self.user.phone_number}"

    @property
    def total_passengers(self):
        return self.adult_count + self.child_count

    @property
    def remaining_installment_amount(self):
        """Calculate remaining amount to be paid in installments"""
        if not self.is_installment:
            return Decimal('0.00')
        
        paid_amount = sum(payment.amount for payment in self.installment_payments.filter(status='completed'))
        return self.installment_total - paid_amount

    @property
    def is_installment_eligible(self):
        """Check if booking is eligible for installment payment"""
        if not self.outbound_schedule:
            return False
        
        # Check if departure is at least 3 months away
        departure_date = self.outbound_schedule.departure_time.date()
        today = timezone.now().date()
        months_difference = (departure_date.year - today.year) * 12 + departure_date.month - today.month
        
        return months_difference >= 3

    @property
    def is_laybuy_complete(self):
        """Check if all installments are paid and booking should move from laybuy to confirmed"""
        if not self.is_installment:
            return False
        
        pending_installments = self.installment_payments.filter(status='pending').count()
        return pending_installments == 0

    def calculate_total_price(self):
        """Calculate total price including return trip if applicable"""
        outbound_price = self.outbound_schedule.route.price * self.total_passengers
        total = outbound_price
        
        if self.trip_type == 'round_trip' and self.return_schedule:
            return_price = self.return_schedule.route.price * self.total_passengers
            total += return_price
            
        self.base_price = total
        self.total_price = total
        return total

    def calculate_points_required(self):
        """Calculate points required for full payment"""
        return 500  # Updated to 500 points for free flight

    def can_pay_with_points(self, user_points):
        """Check if user has enough points for payment"""
        required_points = self.calculate_points_required()
        return user_points >= required_points

    def update_status_after_installment_payment(self):
        """Update booking status after installment payment"""
        if self.is_laybuy_complete:
            self.status = 'confirmed'
            self.payment_status = 'paid'
            self.save()
            
            # Create history record for status change
            BookingHistory.objects.create(
                booking=self,
                status_from='laybuy',
                status_to='confirmed',
                reason='All installments completed'
            )

class InstallmentPayment(models.Model):
    """Track installment payments for bookings"""
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='installment_payments')
    installment_number = models.IntegerField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    due_date = models.DateTimeField()
    payment_date = models.DateTimeField(null=True, blank=True)
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES)
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('overdue', 'Overdue'),
        ('failed', 'Failed')
    ], default='pending')
    points_earned = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['installment_number']
        unique_together = ['booking', 'installment_number']

    def __str__(self):
        return f"Installment {self.installment_number} for {self.booking.booking_reference}"

    def is_overdue(self):
        """Check if installment is overdue"""
        return self.status == 'pending' and timezone.now() > self.due_date

    def save(self, *args, **kwargs):
        # Update overdue status
        if self.status == 'pending' and timezone.now() > self.due_date:
            self.status = 'overdue'
        super().save(*args, **kwargs)

class Passenger(models.Model):
    """Individual passenger details"""
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='passengers')
    passenger_type = models.CharField(max_length=10, choices=PASSENGER_TYPE_CHOICES)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.DateField(null=True, blank=True)
    passport_number = models.CharField(max_length=50, blank=True)
    nationality = models.CharField(max_length=100, blank=True)
    special_requirements = models.TextField(blank=True)
    seat_preference = models.CharField(max_length=50, blank=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.booking.booking_reference}"

class BookingPayment(models.Model):
    """Payment tracking for bookings"""
    booking = models.OneToOneField(Booking, on_delete=models.CASCADE, related_name='payment_details')
    payment_reference = models.CharField(max_length=50, unique=True, editable=False)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    payment_date = models.DateTimeField(null=True, blank=True)
    payment_method_details = models.JSONField(default=dict, blank=True)
    transaction_id = models.CharField(max_length=100, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.payment_reference:
            self.payment_reference = f"PAY{uuid.uuid4().hex[:10].upper()}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Payment {self.payment_reference} - {self.booking.booking_reference}"

class BookingHistory(models.Model):
    """Track booking status changes"""
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='history')
    status_from = models.CharField(max_length=20, choices=BOOKING_STATUS_CHOICES)
    status_to = models.CharField(max_length=20, choices=BOOKING_STATUS_CHOICES)
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    reason = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.booking.booking_reference}: {self.status_from} → {self.status_to}"
