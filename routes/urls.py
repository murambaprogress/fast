from django.urls import path
from .views import routes_list_create, route_detail

urlpatterns = [
    path('routes/', routes_list_create, name='routes_list_create'),
    path('routes/<int:pk>/', route_detail, name='route_detail'),
]


