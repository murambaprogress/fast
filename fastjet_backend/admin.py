from django.contrib import admin
from django.urls import path
from django.shortcuts import redirect
from django.contrib.admin import AdminSite
from django.template.response import TemplateResponse


class FastJetAdminSite(AdminSite):
    site_header = 'FastJet Admin'
    site_title = 'FastJet Admin Portal'
    index_title = 'Welcome to FastJet Administration'
    
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('bulk-operations/', self.admin_view(self.bulk_operations_view), name='bulk-operations'),
        ]
        return custom_urls + urls
    
    def bulk_operations_view(self, request):
        """Custom bulk operations dashboard"""
        # Import here to avoid circular imports
        from routes.models import Route
        from booking.models import Flight, FlightSchedule
        from destinations.models import Destination
        
        context = {
            'title': 'Bulk Flight Operations',
            'routes_count': Route.objects.count(),
            'flights_count': Flight.objects.count(),
            'schedules_count': FlightSchedule.objects.count(),
            'destinations_count': Destination.objects.count(),
            'recent_routes': Route.objects.all()[:10].select_related('from_destination', 'to_destination'),
            'recent_flights': Flight.objects.all()[:10].select_related('route'),
            'has_view_permission': True,
        }
        return TemplateResponse(request, 'admin/bulk_operations_dashboard.html', context)


# Create custom admin site instance
admin_site = FastJetAdminSite(name='fastjet_admin')