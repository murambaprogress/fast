from django.urls import path
from .views import get_destinations, create_destination

urlpatterns = [
    path('destinations/', get_destinations),
    path('upload/', create_destination),
]
