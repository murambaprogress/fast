from django.core.management.base import BaseCommand
from deployment_utils import backup_data, setup_cloud_environment, restore_data

class Command(BaseCommand):
    help = 'Handles cloud deployment tasks including data backup and restoration'

    def handle(self, *args, **options):
        self.stdout.write('Starting cloud deployment process...')
        
        try:
            # Backup existing data
            self.stdout.write('Backing up data...')
            backup_data()
            self.stdout.write(self.style.SUCCESS('Data backup completed'))

            # Set up cloud environment
            self.stdout.write('Setting up cloud environment...')
            setup_cloud_environment()
            self.stdout.write(self.style.SUCCESS('Cloud environment setup completed'))

            # Restore data
            self.stdout.write('Restoring data...')
            restore_data()
            self.stdout.write(self.style.SUCCESS('Data restoration completed'))

            self.stdout.write(self.style.SUCCESS('Cloud deployment process completed successfully'))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error during deployment: {str(e)}'))
            raise
