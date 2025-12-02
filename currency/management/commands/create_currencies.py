from django.core.management.base import BaseCommand
from currency.models import Currency


class Command(BaseCommand):
    help = 'Create default currencies for the system'

    def handle(self, *args, **options):
        currencies = ['USD', 'ZWL', 'ZAR']
        
        for code in currencies:
            currency, created = Currency.objects.get_or_create(code=code)
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Created currency: {code}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'- Currency already exists: {code}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(f'\nTotal currencies in database: {Currency.objects.count()}')
        )
