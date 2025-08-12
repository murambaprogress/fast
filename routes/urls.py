from django.urls import path
from .views import routes_list_create, route_detail, routes_for_selection

urlpatterns = [
    path('routes/', routes_list_create, name='routes_list_create'),
    path('routes/<int:pk>/', route_detail, name='route_detail'),
    path('routes-selection/', routes_for_selection, name='routes_for_selection'),
]


