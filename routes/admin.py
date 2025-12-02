from django.contrib import admin
from django.urls import path
from django.template.response import TemplateResponse
from django.shortcuts import redirect
from django.contrib import messages
from django.utils.html import format_html
from .models import Route
from booking.models import Flight, FlightSchedule
from datetime import datetime, timedelta
from django.utils import timezone
from decimal import Decimal

@admin.register(Route)
class RouteAdmin(admin.ModelAdmin):
    list_display = [
        'from_destination', 'to_destination', 'price', 'currency', 
        'point_threshold', 'estimated_time', 'distance', 'bulk_actions'
    ]
    list_filter = ['currency', 'from_destination', 'to_destination']
    search_fields = [
        'from_destination__name', 'to_destination__name',
        'from_destination__code', 'to_destination__code'
    ]
    
    fieldsets = (
        ('Route Information', {
            'fields': ('from_destination', 'to_destination')
        }),
        ('Pricing & Points', {
            'fields': ('price', 'currency', 'point_threshold')
        }),
        ('Flight Details', {
            'fields': ('estimated_time', 'distance')
        }),
    )
    
    def bulk_actions(self, obj):
        """Add bulk action buttons for each route"""
        return format_html(
            '<a class="button" href="{}">Create Monthly Schedules</a> '
            '<a class="button" href="{}">Create Round Trip</a>',
            f'/admin/routes/route/{obj.id}/bulk-schedules/',
            f'/admin/routes/route/{obj.id}/create-roundtrip/'
        )
    bulk_actions.short_description = 'Bulk Actions'
    
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('<int:route_id>/bulk-schedules/', 
                 self.admin_site.admin_view(self.bulk_schedule_creation_view), 
                 name='route-bulk-schedules'),
            path('<int:route_id>/create-roundtrip/', 
                 self.admin_site.admin_view(self.create_roundtrip_view), 
                 name='route-create-roundtrip'),
            path('bulk-operations/', 
                 self.admin_site.admin_view(self.bulk_operations_view), 
                 name='route-bulk-operations'),
        ]
        return custom_urls + urls
    
    def bulk_schedule_creation_view(self, request, route_id):
        """View for creating bulk monthly schedules for a route"""
        route = Route.objects.get(id=route_id)
        
        if request.method == 'POST':
            return self.process_bulk_schedule_creation(request, route)
        
        context = {
            'title': f'Create Monthly Schedules - {route}',
            'route': route,
            'opts': self.model._meta,
            'has_view_permission': self.has_view_permission(request),
        }
        return TemplateResponse(request, 'admin/routes/bulk_schedule_creation.html', context)
    
    def create_roundtrip_view(self, request, route_id):
        """View for creating round-trip route and schedules"""
        route = Route.objects.get(id=route_id)
        
        if request.method == 'POST':
            return self.process_roundtrip_creation(request, route)
        
        # Check if return route already exists
        return_route = Route.objects.filter(
            from_destination=route.to_destination,
            to_destination=route.from_destination
        ).first()
        
        context = {
            'title': f'Create Round Trip - {route}',
            'route': route,
            'return_route': return_route,
            'opts': self.model._meta,
            'has_view_permission': self.has_view_permission(request),
        }
        return TemplateResponse(request, 'admin/routes/create_roundtrip.html', context)
    
    def bulk_operations_view(self, request):
        """Main bulk operations dashboard"""
        context = {
            'title': 'Bulk Flight Operations',
            'opts': self.model._meta,
            'has_view_permission': self.has_view_permission(request),
            'routes': Route.objects.all().select_related('from_destination', 'to_destination'),
        }
        return TemplateResponse(request, 'admin/routes/bulk_operations.html', context)
    
    def process_bulk_schedule_creation(self, request, route):
        """Process bulk schedule creation form"""
        try:
            # Get form data
            start_date = datetime.strptime(request.POST.get('start_date'), '%Y-%m-%d').date()
            end_date = datetime.strptime(request.POST.get('end_date'), '%Y-%m-%d').date()
            departure_time = request.POST.get('departure_time')
            flight_duration_hours = int(request.POST.get('flight_duration_hours', 2))
            flight_duration_minutes = int(request.POST.get('flight_duration_minutes', 0))
            operational_days = request.POST.getlist('operational_days')  # List of weekday numbers
            total_seats = int(request.POST.get('total_seats', 150))
            price_multiplier = Decimal(request.POST.get('price_multiplier', '1.00'))
            
            # Get or create flight for this route
            flight_number = request.POST.get('flight_number')
            if not flight_number:
                # Auto-generate flight number
                existing_flights = Flight.objects.filter(
                    route__from_destination=route.from_destination,
                    route__to_destination=route.to_destination
                ).count()
                flight_number = f"FJ{route.from_destination.code}{route.to_destination.code}{existing_flights + 1:02d}"
            
            flight, created = Flight.objects.get_or_create(
                flight_number=flight_number,
                defaults={
                    'route': route,
                    'flight_duration': timedelta(hours=flight_duration_hours, minutes=flight_duration_minutes),
                    'max_passengers': total_seats,
                    'economy_class_seats': total_seats,
                    'operational_days': [int(day) for day in operational_days] if operational_days else [],
                }
            )
            
            if not created:
                # Update existing flight
                flight.route = route
                flight.flight_duration = timedelta(hours=flight_duration_hours, minutes=flight_duration_minutes)
                flight.max_passengers = total_seats
                flight.economy_class_seats = total_seats
                if operational_days:
                    flight.operational_days = [int(day) for day in operational_days]
                flight.save()
            
            # Create schedules for the specified period
            schedules_created = 0
            current_date = start_date
            
            while current_date <= end_date:
                # Check if this day is in operational days (if specified)
                weekday = current_date.weekday()  # Monday = 0, Sunday = 6
                
                if not operational_days or str(weekday) in operational_days:
                    # Parse departure time
                    departure_datetime = datetime.combine(current_date, 
                                                        datetime.strptime(departure_time, '%H:%M').time())
                    departure_datetime = timezone.make_aware(departure_datetime)
                    
                    # Calculate arrival time
                    arrival_datetime = departure_datetime + flight.flight_duration
                    
                    # Check if schedule already exists
                    existing_schedule = FlightSchedule.objects.filter(
                        flight=flight,
                        departure_time=departure_datetime
                    ).first()
                    
                    if not existing_schedule:
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
            
            messages.success(request, f'Successfully created {schedules_created} flight schedules for {flight.flight_number}')
            return redirect(f'/admin/booking/flightschedule/?flight__id__exact={flight.id}')
            
        except Exception as e:
            messages.error(request, f'Error creating schedules: {str(e)}')
            return redirect(f'/admin/routes/route/{route.id}/bulk-schedules/')
    
    def process_roundtrip_creation(self, request, route):
        """Process round-trip creation"""
        try:
            # Create return route if it doesn't exist
            return_route, created = Route.objects.get_or_create(
                from_destination=route.to_destination,
                to_destination=route.from_destination,
                defaults={
                    'price': route.price,
                    'currency': route.currency,
                    'point_threshold': route.point_threshold,
                    'estimated_time': route.estimated_time,
                    'distance': route.distance,
                }
            )
            
            if created:
                messages.success(request, f'Created return route: {return_route}')
            else:
                messages.info(request, f'Return route already exists: {return_route}')
            
            # If user wants to create schedules immediately
            if request.POST.get('create_schedules') == 'on':
                return redirect(f'/admin/routes/route/{return_route.id}/bulk-schedules/')
            
            return redirect('/admin/routes/route/')
            
        except Exception as e:
            messages.error(request, f'Error creating round trip: {str(e)}')
            return redirect(f'/admin/routes/route/{route.id}/create-roundtrip/')
