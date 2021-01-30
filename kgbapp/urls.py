from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('addserver/', views.add_server, name='add_server'),
    path('create_user/', views.create_user, name='create_user')
]
