# Generated by Django 2.2.18 on 2023-03-07 09:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_auto_20230307_1503'),
    ]

    operations = [
        migrations.AlterField(
            model_name='organizationmanager',
            name='orgname',
            field=models.CharField(max_length=255),
        ),
    ]
