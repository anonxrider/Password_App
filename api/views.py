from django.shortcuts import render, get_object_or_404


import json

from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import (
    Item,
    PasswordManager,
    OrganizationManager,
    SharingManager,
    OrganizationMembersManager,
)
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from .serializers import (
    ItemSerializer,
    UserSerializer,
    PasswordSerializer,
    OrganizationSerializer,
    SharedEditSerializer,
    SharingSerializer,
    OrganizationMemberSerializer,
    SharedWithMeSerializer,
    SharingViewSerializer
)
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import authentication_classes
from rest_framework.decorators import permission_classes

from rest_framework import serializers
from rest_framework import status

from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
import uuid
from rest_framework_simplejwt.backends import TokenBackend
from django.db.models import Q
from django.contrib import messages
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

@api_view(["GET"])
def ApiOverview(request):
    api_urls = {
        "all_items": "/",
        "Search by Category": "/?category=category_name",
        "Search by Subcategory": "/?subcategory=category_name",
        "Add": "/create",
        "Update": "/update/pk",
        "Delete": "/item/pk/delete",
    }

    return Response(api_urls)


@api_view(["POST"])

def add_items(request):
    item = ItemSerializer(data=request.data)

    # validating for already existing data
    if Item.objects.filter(**request.data).exists():
        raise serializers.ValidationError("This data already exists")

    if item.is_valid():
        item.save()
        return Response(item.data)
    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def view_items(request):
    # checking for the parameters from the URL
    if request.query_params:
        items = Item.objects.filter(**request.query_params.dict())
    else:
        items = Item.objects.all()
    # if there is something in items else raise error
    if items:
        serializer = ItemSerializer(items, many=True)
        return Response(serializer.data)
    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


"""
PUT METHOD
"""


@api_view(["POST"])
def update_items(request, pk):
    item = Item.objects.get(pk=pk)
    data = ItemSerializer(instance=item, data=request.data)

    if data.is_valid():
        data.save()
        return Response(data.data)
    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


"""  
DELETE METHOD
"""


@api_view(["DELETE"])
def delete_items(request, pk):
    item = get_object_or_404(Item, pk=pk)
    item.delete()
    return Response(status=status.HTTP_202_ACCEPTED)


"""
 USER RELATED FUNCTIONS
________________________________
CREATE
"""


@api_view(["POST"])
def create_user(request):
    user = UserSerializer(data=request.data)

    # validating for already existing data
    if User.objects.filter(**request.data).exists():
        raise serializers.ValidationError("This data already exists")

    if user.is_valid():
        user.save()
        return Response(user.data)
    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


""" 
VIEW METHOD
"""


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def view_users(request):

    # checking for the parameters from the URL
    if request.query_params:

        users = User.objects.filter(**request.query_params.dict())
    else:
        users = User.objects.all()

    # if there is something in items else raise error
    if users:
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


"""

PASSWORD RELATED FUNCTIONS

VIEW PASSWORDS
"""


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def view_password(request):
    current_user = request.user
    # checking for the parameters from the URL
    if request.query_params:
        password = PasswordManager.objects.filter(**request.query_params.dict())
    else:
        password = PasswordManager.objects.filter(created_user=current_user)
    # if there is something in items else raise error
    if password:
        serializer = PasswordSerializer(password, many=True)
        return Response(serializer.data)
    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


"""
 CREATE PASSWORDS!!!!!!!!!!!!
"""


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_password(request):
    password = PasswordSerializer(data=request.data)
    web_uname = request.data["web_name"]
    if PasswordManager.objects.filter(web_name=web_uname).exists():
        raise serializers.ValidationError("This data already exists")
    if password.is_valid():
        password.save(created_user=request.user)
        return Response(password.data)
    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


"""
UPDATE PASSWORD
"""


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_password(request, pk):
    current_user = request.user
    password = PasswordManager.objects.get(pk=pk)
    create_user = password.created_user
    data = PasswordSerializer(instance=password, data=request.data)
    if str(current_user) == str(create_user):
        if data.is_valid():
            data.save()
            return Response(data.data)
        else:
            raise serializers.ValidationError("provide any data please")
    else:
        raise serializers.ValidationError("incorrect user")


"""      
DELETE PASSWORD

"""


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_password(request, pk):
    current_user = request.user
    item = get_object_or_404(PasswordManager, pk=pk)
    created_user = item.created_user

    if str(created_user) == str(current_user):
        item.delete()
        raise messages.success( 'successfully delete')
    else:
        raise serializers.ValidationError("incorrect user")


"""

 ORGANIZATION RELATED FUNCTIONS
 CREATE ORGANIZATION
"""


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_organization(request):
    org = OrganizationSerializer(data=request.data)

    orgnames = request.data["orgname"]

    if OrganizationManager.objects.filter(orgname=orgnames).exists():
        raise serializers.ValidationError("This data already exists")
    else:
        if org.is_valid():
            org.save(created_by=request.user)
            return Response(org.data)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)


"""
 DELETE ORGANIZATION 
 """


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_organization(request, pk):
    current_user = request.user
    organization = get_object_or_404(OrganizationManager, pk=pk)
    created_user = organization.created_by
    if str(created_user) == str(current_user):
        organization.delete()
        raise messages.success('successfully delete')
        # return Response(status=status.HTTP_202_ACCEPTED)
    else:
        raise serializers.ValidationError("incorrect user")


"""  
UPDATE ORGANIZATION
"""


@api_view(["POST"])
# @permission_classes([IsAuthenticated])
def update_organization(request, pk):
    current_user = request.user
    organizations = OrganizationManager.objects.get(pk=pk)
    create_user = organizations.created_by
    data = OrganizationSerializer(instance=organizations, data=request.data)
    if str(current_user) == str(create_user):
        if data.is_valid():
            data.save()
            return Response(data.data)
        else:
            raise serializers.ValidationError("provide any data please")
    else:
        raise serializers.ValidationError("incorrect user")


""" 
VIEW PASSWORDS
"""


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def view_organization(request):
    current_user = request.user
    if request.query_params:
        organization = OrganizationManager.objects.filter(**request.query_params.dict())
    else:
        organization = OrganizationManager.objects.filter(created_by=current_user)
    if organization:
        serializer = OrganizationSerializer(organization, many=True)
        return Response(serializer.data)
    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


"""  
# PASSWORD SHARING MANAGER
#CREATE SHARING
"""


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_sharing(request):
    check_current_user = request.user
    req_data = request.data
    dumps = json.dumps(req_data)
    loaddata = json.loads(dumps)
    check_permission = loaddata["permission"]
    check_shared_to = loaddata["shared_to"]
    check_password_id = loaddata["passwordid"]
    user = User.objects.filter(username=check_shared_to).exists()

    if user:
        if str(check_current_user) == str(check_shared_to):
            raise serializers.ValidationError("cant share to you")
        else:

            passwords = PasswordManager.objects.filter(id=check_password_id).exists()
            if passwords:
                password = PasswordManager.objects.get(id=check_password_id)
                web_address = password.web_address
                web_password = password.web_password
                web_name = password.web_name
                if check_permission == "R" or check_permission == "W":
                    sharing = SharingSerializer(data=request.data)
                    if sharing.is_valid():
                        check_sharing = SharingManager.objects.filter(
                            passwordid=check_password_id,
                            shared_to=str(check_shared_to),
                            permission=check_permission,
                        ).exists()
                        # get_sharing_id =SharingManager.objects.get(Q(passwordid=check_password_id), Q(shared_to=str(check_shared_to)))

                        if check_sharing:

                            check_shared_to_user = SharingManager.objects.filter(
                                shared_to=str(check_shared_to)
                            ).exists()
                            if check_shared_to_user:
                                raise serializers.ValidationError(
                                    "already shared please change the permission"
                                )

                        else:
                            try:
                                get_sharing_id = SharingManager.objects.get(
                                    Q(passwordid=check_password_id),
                                    Q(shared_to=str(check_shared_to)),
                                )
                                sharing_uid = get_sharing_id.id
                                sharenew = SharingManager.objects.get(id=sharing_uid)
                                sharenew.permission = check_permission
                                sharenew.save()
                                return Response(
                                    {"message": "Jobs Retrieved Successfully."}
                                )
                            except:
                                sharing.save(
                                    shared_by=check_current_user,
                                    webaddress=web_address,
                                    webpassword=web_password,
                                    webname=web_name,
                                )
                                return Response(sharing.data)

                    else:
                        raise serializers.ValidationError("some error occured")
                else:
                    raise serializers.ValidationError("Check permission")
            else:
                raise serializers.ValidationError("not a present password id")
    else:
        raise serializers.ValidationError("not a user")


""" 
UPDATE SHARED PASSWORD
"""


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_shared_password(request, pk):
    req_data = request.data
    dumps = json.dumps(req_data)
    load_data = json.loads(dumps)
    webaddress = load_data["webaddress"]
    webpassword = load_data["webpassword"]

    current_user = request.user
    sharing_pass = SharingManager.objects.filter(id=pk).exists()
    if sharing_pass:
        sharing = SharingManager.objects.get(id=pk)
        shared_password_id = sharing.passwordid
        shared_to = sharing.shared_to
        shared_per = sharing.permission
        data = SharedEditSerializer(instance=sharing, data=request.data)
        if str(current_user) == str(shared_to):
            if shared_per == "W":
                if data.is_valid():
                    data.save()
                    pass_update = PasswordManager.objects.get(id=shared_password_id)
                    pass_update.web_address = webaddress
                    pass_update.web_password = webpassword
                    pass_update.save()
                    return Response(data.data)
                else:
                    raise serializers.ValidationError("error occured")
            else:
                raise serializers.ValidationError("sharing id read only. you cant edit")

        else:
            raise serializers.ValidationError("you cant edit")

    else:
        raise serializers.ValidationError("sharing id not exists")


""" 
DELETE PASSWORD SHARING

"""


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_sharing(request, pk):
    current_user = request.user
    share_password = get_object_or_404(SharingManager, pk=pk)
    created_user = share_password.shared_by
    if str(created_user) == str(current_user):
        share_password.delete()
        raise messages.success( 'successfully completed')
    else:
        raise serializers.ValidationError("incorrect user")


""" 
VIEW ALL SHARING
"""


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def view_sharing(request):
    current_user = request.user
    if request.query_params:
        share = SharingManager.objects.filter(**request.query_params.dict())
    else:
        share = SharingManager.objects.filter(shared_by=current_user)
    if share:
        serializer = SharingViewSerializer(share, many=True)
        return Response(serializer.data)
    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


# SHARED VIEW
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def shared_to_me(request):
    check_current_user = request.user
    shared_content = SharingManager.objects.filter(shared_to=str(check_current_user))
    if shared_content:
        serializer = SharedWithMeSerializer(shared_content, many=True)
        return Response(serializer.data)
    else:
        raise serializers.ValidationError("no shared contents")


"""  
ADD MEMBER TO ORGANIZATION
ADD MEMBERS

"""


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_org_members(request):
    check_current_user = request.user
    req_data = request.data
    dumps = json.dumps(req_data)
    load_data = json.loads(dumps)
    check_organization_id = load_data["organization_id"]
    check_organization_member = load_data["organization_members"]
    organization_check = OrganizationManager.objects.filter(
        id=check_organization_id
    ).exists()
    user_check = User.objects.filter(username=str(check_organization_member)).exists()
    if organization_check:
        org_user_check = OrganizationManager.objects.get(id=check_organization_id)
        org_created_user = org_user_check.created_by
        org_name = org_user_check.orgname
        if str(check_current_user) == str(org_created_user):
            if user_check:
                item = OrganizationMemberSerializer(data=request.data)
                if OrganizationMembersManager.objects.filter(**request.data).exists():
                    raise serializers.ValidationError("This data already exists")
                if item.is_valid():
                    if str(check_current_user) == str(check_organization_member):
                        raise serializers.ValidationError("Cannot save creator admin")
                    else:
                        item.save(
                            added_by=check_current_user, organization_name=org_name
                        )
                        return Response(item.data)
                else:
                    raise serializers.ValidationError("Error in saving")
            else:
                raise serializers.ValidationError("No member in this username")
        else:
            raise serializers.ValidationError(
                "You are not the creator of this organization"
            )
    else:
        raise serializers.ValidationError("No Organization in this ID")
