from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from . import views_email

router = DefaultRouter()
router.register(r'document-types', views.DocumentTypeViewSet)
router.register(r'credit-bookings', views.CreditBookingViewSet)

urlpatterns = [
    path('send-document-email/', views.SendDocumentEmailView.as_view(), name='send-document-email'),
    path('send-booking-emails/', views_email.send_booking_emails, name='send-booking-emails'),
    path('', include(router.urls)),
]
