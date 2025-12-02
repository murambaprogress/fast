from django.core.management.base import BaseCommand
from django.utils import timezone
from users.models import PendingUser

class Command(BaseCommand):
    help = 'Clean up expired verification codes and old pending users'

    def handle(self, *args, **options):
        now = timezone.now()
        
        # Delete pending users with expired verification codes (older than 1 hour)
        expired_codes = PendingUser.objects.filter(verification_code_expires__lt=now)
        expired_count = expired_codes.count()
        
        if expired_count > 0:
            expired_codes.delete()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Deleted {expired_count} pending user(s) with expired verification codes.'
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS('No expired verification codes found.')
            )