from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from users.models import PendingUser

class Command(BaseCommand):
    help = 'Clean up expired pending user registrations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Delete pending users older than this many days (default: 7)',
        )

    def handle(self, *args, **options):
        days = options['days']
        cutoff_date = timezone.now() - timedelta(days=days)
        
        expired_users = PendingUser.objects.filter(created_at__lt=cutoff_date)
        count = expired_users.count()
        
        if count > 0:
            expired_users.delete()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully deleted {count} expired pending user(s) older than {days} days.'
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f'No pending users older than {days} days found.'
                )
            )