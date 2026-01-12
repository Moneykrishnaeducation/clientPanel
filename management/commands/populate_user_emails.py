"""
Data migration script to populate user_email fields correctly
Run this after the makemigrations completes
"""

from django.core.management.base import BaseCommand
from clientPanel.models import UserDocument

class Command(BaseCommand):
    help = 'Populate user_email fields with correct email addresses'

    def handle(self, *args, **options):
        self.stdout.write('Starting email population...')
        
        updated_count = 0
        for doc in UserDocument.objects.filter(user_email='temp@example.com'):
            if doc.user and doc.user.email:
                doc.user_email = doc.user.email
                doc.save(update_fields=['user_email'])
                updated_count += 1
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully populated {updated_count} UserDocument records with correct email addresses'
            )
        )