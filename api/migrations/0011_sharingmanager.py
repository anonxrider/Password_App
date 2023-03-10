# Generated by Django 2.2.18 on 2023-03-07 10:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_auto_20230307_1517'),
    ]

    operations = [
        migrations.CreateModel(
            name='SharingManager',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('shared_to', models.CharField(max_length=255)),
                ('shared_by', models.CharField(max_length=255)),
                ('webname', models.CharField(max_length=255, unique=True)),
                ('webaddress', models.CharField(max_length=255)),
                ('webpassword', models.CharField(max_length=255)),
                ('permission', models.CharField(max_length=255)),
            ],
        ),
    ]
