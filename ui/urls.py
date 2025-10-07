from django.urls import path
from . import views

app_name = 'ui'

urlpatterns = [
    path('', views.index, name='index'),
    path('encrypt/', views.encrypt_ui, name='encrypt'),
    path('decrypt/', views.decrypt_ui, name='decrypt'),
    path('success/', views.success, name='success'),
]