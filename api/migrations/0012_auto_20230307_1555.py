# Generated by Django 2.2.18 on 2023-03-07 10:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_sharingmanager'),
    ]

    operations = [
        migrations.AddField(
            model_name='sharingmanager',
            name='passwordid',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='sharingmanager',
            name='webname',
            field=models.CharField(max_length=255),
        ),
    ]
