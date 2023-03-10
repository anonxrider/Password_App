from django.db.models import fields
from rest_framework import serializers
from .models import (
    Item,
    PasswordManager,
    OrganizationManager,
    SharingManager,
    OrganizationMembersManager,
)
from django.contrib.auth.models import User


class ItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = Item
        fields = ("category", "name")


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "password")


class PasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordManager
        fields = ("web_name", "web_address", "web_password")


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrganizationManager
        fields = ("orgname",)


class SharingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SharingManager
        fields = ("shared_to", "permission", "passwordid")

class SharingViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = SharingManager
        fields = ("id","shared_to", "permission", "passwordid")

class OrganizationMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrganizationMembersManager
        fields = ("organization_id", "organization_members")


class SharedWithMeSerializer(serializers.ModelSerializer):
    class Meta:
        model = SharingManager
        fields = (
            "shared_to",
            "shared_by",
            "webname",
            "webaddress",
            "webpassword",
            "permission",
            "passwordid",
        )


class SharedEditSerializer(serializers.ModelSerializer):
    class Meta:
        model = SharingManager
        fields = ("webaddress", "webpassword")
