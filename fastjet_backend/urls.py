
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/users/', include('users.urls')),
    path('api/destination/', include('destinations.urls')),
    path('api/routes/', include('routes.urls')),
    path('api/currency/', include('currency.urls')),
    path('api/wallets/',include('wallets.urls')),
    path('api/booking/',include('booking.urls')),
    path('api/loyalty/', include('loyalty.urls')),

]
