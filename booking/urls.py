from django.urls import path
from .views import (
    FlightSearchView,
    CreateBookingView,
    ProcessPaymentView,
    get_user_bookings,
    get_laybuy_bookings,
    get_booking_detail,
    cancel_booking,
    get_destinations,
    get_routes,
    get_flights,
    FlightListCreateView,
    FlightDetailView,
    FlightScheduleListCreateView,
    FlightScheduleDetailView,
    pay_installment,
    get_admin_bookings,
    update_booking_status,
    flight_statistics,
    booking_statistics,
)

urlpatterns = [
    # Flight management - Public access for viewing
    path('flights/', FlightListCreateView.as_view(), name='flight-list-create'),
    path('flights/<int:pk>/', FlightDetailView.as_view(), name='flight-detail'),
    path('flight-schedules/', FlightScheduleListCreateView.as_view(), name='flight-schedule-list-create'),
    path('flight-schedules/<int:pk>/', FlightScheduleDetailView.as_view(), name='flight-schedule-detail'),
    
    # Flight search - Public access
    path('search-flights/', FlightSearchView.as_view(), name='search-flights'),
    
    # Booking operations - Require authentication
    path('create-booking/', CreateBookingView.as_view(), name='create-booking'),
    path('process-payment/', ProcessPaymentView.as_view(), name='process-payment'),
    path('pay-installment/', pay_installment, name='pay-installment'),
    
    # User bookings - Require authentication  
    path('bookings/', get_user_bookings, name='user-bookings'),
    path('laybuy-bookings/', get_laybuy_bookings, name='laybuy-bookings'),
    path('bookings/<int:booking_id>/', get_booking_detail, name='booking-detail'),
    path('bookings/<int:booking_id>/cancel/', cancel_booking, name='cancel-booking'),
    
    # Admin booking management - Require staff authentication
    path('admin/bookings/', get_admin_bookings, name='admin-bookings'),
    path('admin/bookings/<int:booking_id>/status/', update_booking_status, name='update-booking-status'),
    
    # Reference data - Public access
    path('destinations/', get_destinations, name='destinations'),
    path('routes/', get_routes, name='routes'),
    path('flights-list/', get_flights, name='flights-list'),  # Renamed to avoid conflict
    
    # Admin statistics - Require staff authentication
    path('flights/stats/', flight_statistics, name='flight-statistics'),
    path('bookings/stats/', booking_statistics, name='booking-statistics'),
]
