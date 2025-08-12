from django.core.management.base import BaseCommand
from creditbooking.models import DocumentType

class Command(BaseCommand):
    help = 'Initialize default document types for credit booking'

    def handle(self, *args, **kwargs):
        document_types = [
            {
                'name': 'ID',
                'description': 'Valid identification document (ID card, passport, driver\'s license)',
                'is_required': True
            },
            {
                'name': 'PAYSLIP',
                'description': 'Recent payslip (must be from the past 3 months)',
                'is_required': True
            },
            {
                'name': 'BANK STATEMENT',
                'description': 'Bank statement showing regular income (must be from the past 3 months)',
                'is_required': True
            }
        ]
        
        created_count = 0
        for doc_type in document_types:
            obj, created = DocumentType.objects.get_or_create(
                name=doc_type['name'],
                defaults={
                    'description': doc_type['description'],
                    'is_required': doc_type['is_required']
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f'Created document type: {obj.name}'))
            else:
                self.stdout.write(f'Document type already exists: {obj.name}')
        
        self.stdout.write(self.style.SUCCESS(f'Successfully created {created_count} document types'))
