# Generated manually to handle branch_name column

from django.db import migrations, models
from django.db import connection


def check_column_exists(apps, schema_editor):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_name = 'clientPanel_bankdetails'
            AND column_name = 'branch_name';
        """)
        column_exists = cursor.fetchone()[0] > 0
        if column_exists:
            # Column already exists, don't try to add it again
            return

        cursor.execute("""
            ALTER TABLE clientPanel_bankdetails
            ADD COLUMN branch_name character varying(100) NULL;
        """)


class Migration(migrations.Migration):

    dependencies = [
        ('clientPanel', '0004_alter_userdocument_document'),
    ]

    operations = [
        migrations.RunPython(check_column_exists),
    ]
