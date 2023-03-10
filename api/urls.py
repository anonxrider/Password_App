from django.urls import path
from . import views
from rest_framework_simplejwt import views as jwt_views


urlpatterns = [
    path('', views.ApiOverview, name='home'),
    path('create/', views.add_items, name='add-items'),
    path('all/', views.view_items, name='view_items'),
    path('update/<int:pk>/', views.update_items, name='update-items'),
    path('item/<int:pk>/delete/', views.delete_items, name='delete-items'),
  
    

    path('all-users/', views.view_users,name='view_users'),
    path('create-user/', views.create_user,name='create_user'),

     #passwords
    path('all-passwords/', views.view_password, name='all-password'),
    path('create-password/', views.add_password, name='add-password'),
    path('update-password/<int:pk>/', views.update_password, name='update-password'),
    path('password/<int:pk>/delete/', views.delete_password, name='delete-password'),
     #organization 
    path('all-organization/', views.view_organization, name='all-organization'),
    path('create-organization/', views.add_organization, name='add-organization'),
    path('organization/<int:pk>/delete/', views.delete_organization, name='delete-organization'),
    path('update-organization/<int:pk>/', views.update_organization, name='update-organization'),
    path('add-members-organization/', views.add_org_members,name='add-members-organization'),
    
    path('create-password-share/', views.add_sharing, name='create-password-share'),
    path('share-password/<int:pk>/delete/', views.delete_sharing, name='share-password'),
    path('share-password-update/<int:pk>/', views.update_shared_password, name='share-password-update'),
    path('all-shared/', views.view_sharing, name='all-shared'),
    path('shared-with-me/', views.shared_to_me, name='shared-with-me'),


    
     #token passing 

    path('token/',
         jwt_views.TokenObtainPairView.as_view(),
         name ='token_obtain_pair'),
    path('token/refresh/',
         jwt_views.TokenRefreshView.as_view(),
         name ='token_refresh'),

]