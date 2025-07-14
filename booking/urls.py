from django.urls import path
from .views import (
    FlightSearchView,
    CreateBookingView,
    ProcessPaymentView,
    get_user_bookings,
    get_booking_detail,
    cancel_booking,
    get_destinations,
    get_routes,
    get_flights,
    FlightListCreateView,
    FlightDetailView,
    FlightScheduleListCreateView,
    FlightScheduleDetailView,
)

urlpatterns = [
    # Flight management
    path('flights/', FlightListCreateView.as_view(), name='flight-list-create'),
    path('flights/<int:pk>/', FlightDetailView.as_view(), name='flight-detail'),
    path('flight-schedules/', FlightScheduleListCreateView.as_view(), name='flight-schedule-list-create'),
    path('flight-schedules/<int:pk>/', FlightScheduleDetailView.as_view(), name='flight-schedule-detail'),
    
    # Flight search and booking
    path('search-flights/', FlightSearchView.as_view(), name='search-flights'),
    path('create-booking/', CreateBookingView.as_view(), name='create-booking'),
    path('process-payment/', ProcessPaymentView.as_view(), name='process-payment'),
    
    # User bookings
    path('my-bookings/', get_user_bookings, name='user-bookings'),
    path('bookings/<int:booking_id>/', get_booking_detail, name='booking-detail'),
    path('bookings/<int:booking_id>/cancel/', cancel_booking, name='cancel-booking'),
    
    # Reference data
    path('destinations/', get_destinations, name='destinations'),
    path('routes/', get_routes, name='routes'),
]
