from django.contrib import admin
from django.urls import path
from django.template.response import TemplateResponse
from django.shortcuts import redirect
from django.contrib import messages
from django.utils.html import format_html
from django.db.models import Count, Q
from datetime import datetime, timedelta
from django.utils import timezone
from decimal import Decimal
from .models import (
    FlightSchedule, Booking, Passenger, BookingPayment, BookingHistory, 
    Flight, InstallmentPayment
)

@admin.register(Flight)
class FlightAdmin(admin.ModelAdmin):
    list_display = [
        'flight_number', 'route', 'aircraft_type', 'total_seats', 
        'is_active', 'is_seasonal', 'get_operational_days_display', 'schedule_actions'
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
    
    def schedule_actions(self, obj):
        """Add schedule management buttons"""
        schedule_count = obj.schedules.count()
        return format_html(
            '<a class="button" href="{}">Manage Schedules ({})</a> '
            '<a class="button" href="{}">Bulk Create</a>',
            f'/admin/booking/flightschedule/?flight__id__exact={obj.id}',
            schedule_count,
            f'/admin/booking/flight/{obj.id}/bulk-schedules/'
        )
    schedule_actions.short_description = 'Schedule Management'
    
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('<int:flight_id>/bulk-schedules/', 
                 self.admin_site.admin_view(self.bulk_schedule_view), 
                 name='flight-bulk-schedules'),
        ]
        return custom_urls + urls
    
    def bulk_schedule_view(self, request, flight_id):
        """Bulk schedule creation view for specific flight"""
        flight = Flight.objects.get(id=flight_id)
        
        if request.method == 'POST':
            return self.process_bulk_schedules(request, flight)
        
        context = {
            'title': f'Bulk Create Schedules - {flight.flight_number}',
            'flight': flight,
            'opts': self.model._meta,
        }
        return TemplateResponse(request, 'admin/booking/bulk_flight_schedules.html', context)
    
    def process_bulk_schedules(self, request, flight):
        """Process bulk schedule creation"""
        try:
            start_date = datetime.strptime(request.POST.get('start_date'), '%Y-%m-%d').date()
            end_date = datetime.strptime(request.POST.get('end_date'), '%Y-%m-%d').date()
            departure_time = request.POST.get('departure_time')
            total_seats = int(request.POST.get('total_seats', flight.total_seats))
            price_multiplier = Decimal(request.POST.get('price_multiplier', '1.00'))
            operational_days = request.POST.getlist('operational_days')
            
            schedules_created = 0
            current_date = start_date
            
            while current_date <= end_date:
                weekday = current_date.weekday()
                
                # Check operational days
                if not operational_days or str(weekday) in operational_days:
                    departure_datetime = datetime.combine(current_date, 
                                                        datetime.strptime(departure_time, '%H:%M').time())
                    departure_datetime = timezone.make_aware(departure_datetime)
                    arrival_datetime = departure_datetime + flight.flight_duration
                    
                    # Check if schedule already exists
                    if not FlightSchedule.objects.filter(
                        flight=flight,
                        departure_time=departure_datetime
                    ).exists():
                        FlightSchedule.objects.create(
                            flight=flight,
                            departure_time=departure_datetime,
                            arrival_time=arrival_datetime,
                            total_seats=total_seats,
                            available_seats=total_seats,
                            price_multiplier=price_multiplier
                        )
                        schedules_created += 1
                
                current_date += timedelta(days=1)
            
            messages.success(request, f'Created {schedules_created} schedules for {flight.flight_number}')
            return redirect(f'/admin/booking/flightschedule/?flight__id__exact={flight.id}')
            
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect(f'/admin/booking/flight/{flight.id}/bulk-schedules/')

@admin.register(FlightSchedule)
class FlightScheduleAdmin(admin.ModelAdmin):
    list_display = [
        'flight', 'departure_time', 'arrival_time', 'available_seats', 
        'total_seats', 'actual_price', 'price_multiplier', 'is_active', 'is_delayed',
        'booking_count'
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
    
    actions = ['mark_delayed', 'mark_active', 'duplicate_schedule']
    
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
    
    def booking_count(self, obj):
        """Show number of bookings for this schedule"""
        count = obj.outbound_bookings.count() + obj.return_bookings.count()
        return format_html(
            '<a href="/admin/booking/booking/?{}">{}</a>',
            f'outbound_schedule__id__exact={obj.id}',
            count
        )
    booking_count.short_description = 'Bookings'
    
    def mark_delayed(self, request, queryset):
        """Mark selected schedules as delayed"""
        count = queryset.update(is_delayed=True)
        self.message_user(request, f'{count} schedules marked as delayed.')
    mark_delayed.short_description = 'Mark selected schedules as delayed'
    
    def mark_active(self, request, queryset):
        """Mark selected schedules as active"""
        count = queryset.update(is_active=True, is_delayed=False, delay_reason='')
        self.message_user(request, f'{count} schedules marked as active.')
    mark_active.short_description = 'Mark selected schedules as active'
    
    def duplicate_schedule(self, request, queryset):
        """Duplicate selected schedules for next week"""
        duplicated = 0
        for schedule in queryset:
            new_departure = schedule.departure_time + timedelta(weeks=1)
            new_arrival = schedule.arrival_time + timedelta(weeks=1)
            
            if not FlightSchedule.objects.filter(
                flight=schedule.flight,
                departure_time=new_departure
            ).exists():
                FlightSchedule.objects.create(
                    flight=schedule.flight,
                    departure_time=new_departure,
                    arrival_time=new_arrival,
                    total_seats=schedule.total_seats,
                    available_seats=schedule.total_seats,
                    price_multiplier=schedule.price_multiplier,
                    gate_number=schedule.gate_number,
                    check_in_time=schedule.check_in_time,
                    boarding_time=schedule.boarding_time
                )
                duplicated += 1
        
        self.message_user(request, f'{duplicated} schedules duplicated for next week.')
    duplicate_schedule.short_description = 'Duplicate schedules for next week'

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

class InstallmentPaymentInline(admin.TabularInline):
    model = InstallmentPayment
    extra = 0
    readonly_fields = ['created_at', 'updated_at']
    fields = ['installment_number', 'amount', 'due_date', 'payment_date', 'status', 'points_earned']

@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = [
        'booking_reference', 'user', 'trip_type', 'outbound_schedule',
        'return_schedule', 'total_passengers', 'total_price', 'payment_status', 
        'status', 'is_installment', 'created_at'
    ]
    list_filter = [
        'trip_type', 'payment_method', 'payment_status', 'status', 
        'is_installment', 'created_at', 'outbound_schedule__flight__route__from_destination'
    ]
    search_fields = ['booking_reference', 'user__phone_number', 'user__email']
    readonly_fields = ['booking_reference', 'created_at', 'updated_at']
    inlines = [PassengerInline, InstallmentPaymentInline, BookingPaymentInline, BookingHistoryInline]
    date_hierarchy = 'created_at'
    
    actions = ['export_bookings', 'send_confirmation_emails']

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'user', 'outbound_schedule__flight__route',
            'return_schedule__flight__route'
        )
    
    def export_bookings(self, request, queryset):
        """Export selected bookings to CSV"""
        import csv
        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="bookings.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'Booking Reference', 'User', 'Trip Type', 'Departure', 'Arrival',
            'Passengers', 'Total Price', 'Status', 'Created'
        ])
        
        for booking in queryset:
            writer.writerow([
                booking.booking_reference,
                booking.user.phone_number,
                booking.trip_type,
                booking.outbound_schedule.departure_time.strftime('%Y-%m-%d %H:%M'),
                booking.outbound_schedule.arrival_time.strftime('%Y-%m-%d %H:%M'),
                booking.total_passengers,
                f"{booking.total_price} {booking.currency}",
                booking.status,
                booking.created_at.strftime('%Y-%m-%d %H:%M')
            ])
        
        return response
    export_bookings.short_description = 'Export selected bookings to CSV'

@admin.register(InstallmentPayment)
class InstallmentPaymentAdmin(admin.ModelAdmin):
    list_display = [
        'booking', 'installment_number', 'amount', 'due_date', 'payment_date', 
        'status', 'points_earned', 'created_at'
    ]
    list_filter = ['status', 'payment_method', 'due_date', 'payment_date']
    search_fields = ['booking__booking_reference', 'booking__user__phone_number']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'due_date'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('booking__user')

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
