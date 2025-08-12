from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'document-types', views.DocumentTypeViewSet)
router.register(r'credit-bookings', views.CreditBookingViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
