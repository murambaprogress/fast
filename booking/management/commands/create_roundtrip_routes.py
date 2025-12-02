from django.core.management.base import BaseCommand, CommandError
from routes.models import Route
from destinations.models import Destination


class Command(BaseCommand):
    help = 'Create round-trip routes for existing routes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--route-id',
            type=int,
            help='Specific route ID to create return route for'
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Create return routes for all existing routes that don\'t have them'
        )
        parser.add_argument(
            '--price-adjustment',
            type=float,
            default=1.0,
            help='Price adjustment multiplier for return routes (default: 1.0 - same price)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without actually creating routes'
        )

    def handle(self, *args, **options):
        if not options.get('route_id') and not options.get('all'):
            raise CommandError('Please specify either --route-id or --all')

        routes_to_process = []
        
        if options.get('route_id'):
            try:
                route = Route.objects.get(id=options['route_id'])
                routes_to_process = [route]
            except Route.DoesNotExist:
                raise CommandError(f'Route with ID {options["route_id"]} does not exist')
        else:
            # Get all routes
            routes_to_process = list(Route.objects.all())

        if not routes_to_process:
            self.stdout.write('No routes found.')
            return

        price_adjustment = options['price_adjustment']
        return_routes_created = 0
        return_routes_to_create = []

        for route in routes_to_process:
            # Check if return route already exists
            existing_return = Route.objects.filter(
                from_destination=route.to_destination,
                to_destination=route.from_destination
            ).first()

            if existing_return:
                self.stdout.write(f'Return route already exists: {existing_return}')
                continue

            # Prepare return route data
            return_route_data = {
                'from_destination': route.to_destination,
                'to_destination': route.from_destination,
                'price': route.price * price_adjustment,
                'currency': route.currency,
                'point_threshold': route.point_threshold,
                'estimated_time': route.estimated_time,
                'distance': route.distance,
            }

            return_routes_to_create.append({
                'original_route': route,
                'return_route_data': return_route_data
            })

        # Show summary
        self.stdout.write('\n' + '='*60)
        self.stdout.write('ROUND-TRIP ROUTE CREATION SUMMARY')
        self.stdout.write('='*60)

        if return_routes_to_create:
            self.stdout.write(f'Return routes to create: {len(return_routes_to_create)}')
            self.stdout.write(f'Price adjustment: {price_adjustment}x')
            
            self.stdout.write('\nRoutes to create:')
            for item in return_routes_to_create:
                original = item['original_route']
                return_data = item['return_route_data']
                self.stdout.write(f'  Original: {original}')
                self.stdout.write(f'  Return:   {return_data["from_destination"]} → {return_data["to_destination"]} '
                                f'({return_data["price"]} {return_data["currency"]})')
                self.stdout.write('')

            if options['dry_run']:
                self.stdout.write(self.style.WARNING('DRY RUN - No routes were created'))
            else:
                # Create the return routes
                confirm = input(f'Create {len(return_routes_to_create)} return routes? (y/N): ')
                if confirm.lower() == 'y':
                    for item in return_routes_to_create:
                        return_route = Route.objects.create(**item['return_route_data'])
                        self.stdout.write(f'Created: {return_route}')
                        return_routes_created += 1
                    
                    self.stdout.write(self.style.SUCCESS(f'\nSuccessfully created {return_routes_created} return routes'))
                else:
                    self.stdout.write('Operation cancelled')
        else:
            self.stdout.write('No return routes to create (all routes already have return routes)')

        # Show round-trip summary
        self.stdout.write('\n' + '='*40)
        self.stdout.write('ROUND-TRIP SUMMARY')
        self.stdout.write('='*40)

        destinations = Destination.objects.all()
        for dest in destinations:
            routes_from = Route.objects.filter(from_destination=dest)
            if routes_from.exists():
                self.stdout.write(f'\nFrom {dest.name} ({dest.code}):')
                for route in routes_from:
                    return_route = Route.objects.filter(
                        from_destination=route.to_destination,
                        to_destination=route.from_destination
                    ).first()
                    
                    status = '✓ Round-trip' if return_route else '✗ One-way only'
                    self.stdout.write(f'  → {route.to_destination.name} ({route.to_destination.code}) {status}')

        self.stdout.write(f'\nTotal round-trip pairs: {self.count_round_trip_pairs()}')

    def count_round_trip_pairs(self):
        """Count how many complete round-trip pairs exist"""
        pairs = 0
        routes = Route.objects.all()
        
        for route in routes:
            return_route = Route.objects.filter(
                from_destination=route.to_destination,
                to_destination=route.from_destination
            ).first()
            
            if return_route:
                # Only count each pair once (avoid counting both directions)
                if route.id < return_route.id:
                    pairs += 1
        
        return pairs