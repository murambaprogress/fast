from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
from booking.models import Flight, FlightSchedule
from routes.models import Route


class Command(BaseCommand):
    help = 'Create bulk flight schedules for routes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--route-id',
            type=int,
            help='Route ID to create schedules for'
        )
        parser.add_argument(
            '--flight-number',
            type=str,
            help='Flight number (will be created if not exists)'
        )
        parser.add_argument(
            '--start-date',
            type=str,
            required=True,
            help='Start date (YYYY-MM-DD format)'
        )
        parser.add_argument(
            '--end-date',
            type=str,
            required=True,
            help='End date (YYYY-MM-DD format)'
        )
        parser.add_argument(
            '--departure-time',
            type=str,
            required=True,
            help='Departure time (HH:MM format)'
        )
        parser.add_argument(
            '--operational-days',
            type=str,
            help='Comma-separated operational days (0=Monday, 6=Sunday). Example: 0,1,2,3,4'
        )
        parser.add_argument(
            '--total-seats',
            type=int,
            default=150,
            help='Total seats per flight (default: 150)'
        )
        parser.add_argument(
            '--price-multiplier',
            type=float,
            default=1.0,
            help='Price multiplier (default: 1.0)'
        )
        parser.add_argument(
            '--flight-duration-hours',
            type=int,
            default=2,
            help='Flight duration in hours (default: 2)'
        )
        parser.add_argument(
            '--flight-duration-minutes',
            type=int,
            default=0,
            help='Flight duration in minutes (default: 0)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without actually creating schedules'
        )

    def handle(self, *args, **options):
        try:
            # Parse dates
            start_date = datetime.strptime(options['start_date'], '%Y-%m-%d').date()
            end_date = datetime.strptime(options['end_date'], '%Y-%m-%d').date()
            departure_time_str = options['departure_time']
            
            # Get route
            route_id = options.get('route_id')
            if route_id:
                try:
                    route = Route.objects.get(id=route_id)
                except Route.DoesNotExist:
                    raise CommandError(f'Route with ID {route_id} does not exist')
            else:
                routes = Route.objects.all()
                if not routes.exists():
                    raise CommandError('No routes found. Please create routes first.')
                
                self.stdout.write('Available routes:')
                for route in routes:
                    self.stdout.write(f'  {route.id}: {route}')
                
                route_id = input('Enter route ID: ')
                try:
                    route = Route.objects.get(id=int(route_id))
                except (ValueError, Route.DoesNotExist):
                    raise CommandError(f'Invalid route ID: {route_id}')

            # Parse operational days
            operational_days = []
            if options.get('operational_days'):
                try:
                    operational_days = [int(day.strip()) for day in options['operational_days'].split(',')]
                    if any(day < 0 or day > 6 for day in operational_days):
                        raise ValueError('Days must be between 0-6')
                except ValueError as e:
                    raise CommandError(f'Invalid operational days: {e}')

            # Get or create flight
            flight_number = options.get('flight_number')
            if not flight_number:
                # Auto-generate flight number
                existing_flights = Flight.objects.filter(
                    route__from_destination=route.from_destination,
                    route__to_destination=route.to_destination
                ).count()
                flight_number = f"FJ{route.from_destination.code}{route.to_destination.code}{existing_flights + 1:02d}"

            flight_duration = timedelta(
                hours=options['flight_duration_hours'],
                minutes=options['flight_duration_minutes']
            )

            flight, created = Flight.objects.get_or_create(
                flight_number=flight_number,
                defaults={
                    'route': route,
                    'flight_duration': flight_duration,
                    'max_passengers': options['total_seats'],
                    'economy_class_seats': options['total_seats'],
                    'operational_days': operational_days if operational_days else [],
                }
            )

            if created:
                self.stdout.write(self.style.SUCCESS(f'Created flight: {flight.flight_number}'))
            else:
                self.stdout.write(f'Using existing flight: {flight.flight_number}')

            # Create schedules
            schedules_created = 0
            schedules_to_create = []
            current_date = start_date

            while current_date <= end_date:
                weekday = current_date.weekday()  # Monday = 0, Sunday = 6
                
                # Check if this day is in operational days (if specified)
                if not operational_days or weekday in operational_days:
                    # Parse departure time
                    departure_datetime = datetime.combine(current_date, 
                                                        datetime.strptime(departure_time_str, '%H:%M').time())
                    departure_datetime = timezone.make_aware(departure_datetime)
                    
                    # Calculate arrival time
                    arrival_datetime = departure_datetime + flight.flight_duration
                    
                    # Check if schedule already exists
                    existing_schedule = FlightSchedule.objects.filter(
                        flight=flight,
                        departure_time=departure_datetime
                    ).first()
                    
                    if not existing_schedule:
                        schedule_data = {
                            'flight': flight,
                            'departure_time': departure_datetime,
                            'arrival_time': arrival_datetime,
                            'total_seats': options['total_seats'],
                            'available_seats': options['total_seats'],
                            'price_multiplier': Decimal(str(options['price_multiplier']))
                        }
                        schedules_to_create.append(schedule_data)
                        schedules_created += 1
                    else:
                        self.stdout.write(f'Schedule already exists for {departure_datetime.strftime("%Y-%m-%d %H:%M")}')
                
                current_date += timedelta(days=1)

            # Show summary
            self.stdout.write('\n' + '='*50)
            self.stdout.write(f'Flight: {flight.flight_number}')
            self.stdout.write(f'Route: {route}')
            self.stdout.write(f'Date range: {start_date} to {end_date}')
            self.stdout.write(f'Departure time: {departure_time_str}')
            self.stdout.write(f'Operational days: {operational_days if operational_days else "All days"}')
            self.stdout.write(f'Total seats: {options["total_seats"]}')
            self.stdout.write(f'Price multiplier: {options["price_multiplier"]}')
            self.stdout.write(f'Schedules to create: {schedules_created}')

            if options['dry_run']:
                self.stdout.write(self.style.WARNING('\nDRY RUN - No schedules were created'))
                if schedules_to_create:
                    self.stdout.write('\nSchedules that would be created:')
                    for i, schedule in enumerate(schedules_to_create[:10]):  # Show first 10
                        dept_time = schedule['departure_time'].strftime('%Y-%m-%d %H:%M')
                        arr_time = schedule['arrival_time'].strftime('%Y-%m-%d %H:%M')
                        self.stdout.write(f'  {dept_time} → {arr_time}')
                    if len(schedules_to_create) > 10:
                        self.stdout.write(f'  ... and {len(schedules_to_create) - 10} more')
            else:
                # Create the schedules
                if schedules_to_create:
                    confirm = input(f'\nCreate {schedules_created} schedules? (y/N): ')
                    if confirm.lower() == 'y':
                        for schedule_data in schedules_to_create:
                            FlightSchedule.objects.create(**schedule_data)
                        self.stdout.write(self.style.SUCCESS(f'\nSuccessfully created {schedules_created} flight schedules'))
                    else:
                        self.stdout.write('Operation cancelled')
                else:
                    self.stdout.write('No new schedules to create')

        except Exception as e:
            raise CommandError(f'Error creating schedules: {str(e)}')