from django.db import migrations

def sync_user_documents(apps, schema_editor):
    CustomUser = apps.get_model('adminPanel', 'CustomUser')
    UserDocument = apps.get_model('clientPanel', 'UserDocument')

    # Sync ID proofs
    for user in CustomUser.objects.filter(id_proof__isnull=False):
        UserDocument.objects.get_or_create(
            user=user,
            document_type='identity',
            defaults={
                'document': user.id_proof,
                'status': 'approved' if user.id_proof_verified else 'pending'
            }
        )

    # Sync address proofs
    for user in CustomUser.objects.filter(address_proof__isnull=False):
        UserDocument.objects.get_or_create(
            user=user,
            document_type='residence',
            defaults={
                'document': user.address_proof,
                'status': 'approved' if user.address_proof_verified else 'pending'
            }
        )

def reverse_sync(apps, schema_editor):
    # No reverse operation - we don't want to lose UserDocument data
    pass

class Migration(migrations.Migration):
    dependencies = [
        ('clientPanel', '0002_userdocument'),
        ('adminPanel', '0001_initial')  # Make sure this is your actual admin panel initial migration
    ]

    operations = [
        migrations.RunPython(sync_user_documents, reverse_sync),
    ]
