from django.contrib import admin
from .models import (
    FlightSchedule, Booking, Passenger, BookingPayment, BookingHistory, Flight
)

@admin.register(Flight)
class FlightAdmin(admin.ModelAdmin):
    list_display = [
        'flight_number', 'route', 'aircraft_type', 'total_seats', 
        'is_active', 'is_seasonal', 'get_operational_days_display'
    ]
    list_filter = [
        'is_active', 'is_seasonal', 'has_business_class', 'has_economy_class',
        'aircraft_type', 'route__from_destination', 'route__to_destination'
    ]
    search_fields = ['flight_number', 'aircraft_registration', 'route__from_destination__name', 'route__to_destination__name']
    readonly_fields = ['created_at', 'updated_at', 'total_seats']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('flight_number', 'route', 'aircraft_type', 'aircraft_registration')
        }),
        ('Capacity & Service', {
            'fields': (
                'max_passengers', 
                ('has_business_class', 'business_class_seats'),
                ('has_economy_class', 'economy_class_seats'),
                'total_seats'
            )
        }),
        ('Operations', {
            'fields': ('flight_duration', 'operational_days', 'is_active', 'is_seasonal')
        }),
        ('Additional Information', {
            'fields': ('notes',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

    def get_operational_days_display(self, obj):
        return obj.get_operational_days_display()
    get_operational_days_display.short_description = 'Operational Days'

@admin.register(FlightSchedule)
class FlightScheduleAdmin(admin.ModelAdmin):
    list_display = [
        'flight', 'departure_time', 'arrival_time', 'available_seats', 
        'total_seats', 'actual_price', 'price_multiplier', 'is_active', 'is_delayed'
    ]
    list_filter = [
        'is_active', 'is_delayed', 'departure_time', 
        'flight__route__from_destination', 'flight__route__to_destination',
        'flight__aircraft_type'
    ]
    search_fields = [
        'flight__flight_number', 'flight__route__from_destination__name', 
        'flight__route__to_destination__name', 'gate_number'
    ]
    date_hierarchy = 'departure_time'
    readonly_fields = ['created_at', 'updated_at', 'actual_price']
    
    fieldsets = (
        ('Flight Information', {
            'fields': ('flight', 'gate_number')
        }),
        ('Schedule', {
            'fields': (
                ('departure_time', 'arrival_time'),
                ('check_in_time', 'boarding_time')
            )
        }),
        ('Capacity & Pricing', {
            'fields': (
                ('total_seats', 'available_seats'),
                ('price_multiplier', 'actual_price')
            )
        }),
        ('Status', {
            'fields': ('is_active', 'is_delayed', 'delay_reason')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

    def actual_price(self, obj):
        return f"{obj.actual_price} {obj.flight.currency}"
    actual_price.short_description = 'Actual Price'

class PassengerInline(admin.TabularInline):
    model = Passenger
    extra = 0

class BookingPaymentInline(admin.StackedInline):
    model = BookingPayment
    extra = 0

class BookingHistoryInline(admin.TabularInline):
    model = BookingHistory
    extra = 0
    readonly_fields = ['timestamp']

@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = [
        'booking_reference', 'user', 'trip_type', 'outbound_schedule',
        'total_passengers', 'total_price', 'payment_status', 'status', 'created_at'
    ]
    list_filter = ['trip_type', 'payment_method', 'payment_status', 'status', 'created_at']
    search_fields = ['booking_reference', 'user__phone_number', 'user__email']
    readonly_fields = ['booking_reference', 'created_at', 'updated_at']
    inlines = [PassengerInline, BookingPaymentInline, BookingHistoryInline]
    date_hierarchy = 'created_at'

@admin.register(Passenger)
class PassengerAdmin(admin.ModelAdmin):
    list_display = ['first_name', 'last_name', 'passenger_type', 'booking']
    list_filter = ['passenger_type']
    search_fields = ['first_name', 'last_name', 'booking__booking_reference']

@admin.register(BookingPayment)
class BookingPaymentAdmin(admin.ModelAdmin):
    list_display = ['payment_reference', 'booking', 'amount_paid', 'payment_date']
    search_fields = ['payment_reference', 'booking__booking_reference']
    readonly_fields = ['payment_reference']

@admin.register(BookingHistory)
class BookingHistoryAdmin(admin.ModelAdmin):
    list_display = ['booking', 'status_from', 'status_to', 'changed_by', 'timestamp']
    list_filter = ['status_from', 'status_to', 'timestamp']
    search_fields = ['booking__booking_reference']
    readonly_fields = ['timestamp']
