# Generated by Django 2.2.18 on 2023-03-07 09:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_auto_20230307_1509'),
    ]

    operations = [
        migrations.RenameField(
            model_name='organizationmanager',
            old_name='created_user',
            new_name='created_by',
        ),
    ]