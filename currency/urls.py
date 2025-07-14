from django.urls import path
from .views import currency_list_create

urlpatterns = [
    path('currencies/', currency_list_create, name='currency_list_create'),
]
