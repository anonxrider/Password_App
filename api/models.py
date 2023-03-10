from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Item(models.Model):
    category = models.CharField(max_length = 255)
    name = models.CharField(max_length = 255)

    def __str__(self) -> str:
        return self.name
    

class PasswordManager(models.Model):
    web_name = models.CharField(max_length = 255,unique=True)
    web_address = models.CharField(max_length = 255)
    web_password = models.CharField(max_length = 255)
    created_user =  models.CharField(max_length = 255)

class OrganizationManager(models.Model):
    orgname = models.CharField(max_length = 255)
    created_by =  models.CharField(max_length = 255)

class SharingManager(models.Model):
    shared_to = models.CharField(max_length = 255)
    shared_by =  models.CharField(max_length = 255)
    passwordid =  models.CharField(max_length = 255, null=True)
    webname = models.CharField(max_length = 255)
    webaddress = models.CharField(max_length = 255)
    webpassword = models.CharField(max_length = 255)
    permission = models.CharField(max_length = 255)

class OrganizationMembersManager(models.Model):
    organization_name = models.CharField(max_length = 255)
    organization_id = models.CharField(max_length = 255)
    organization_members = models.CharField(max_length = 255)
    added_by =  models.CharField(max_length = 255)
