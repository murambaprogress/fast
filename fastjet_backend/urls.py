from django.conf import settings
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from django.views.static import serve as static_serve
import os
from django.http import HttpResponse
from django.conf import settings
from django.conf.urls.static import static
import logging

def spa_index(request):
    """Serve the built React index.html (Vite) for any non-API route."""
    index_path = os.path.join(settings.FRONTEND_DIST, 'index.html')
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8') as f:
            return HttpResponse(f.read())
    return HttpResponse('<h1>Frontend build not found</h1><p>Run the frontend build process.</p>', status=501)


# Serve built assets (JS/CSS). If file missing, return 404 instead of falling back to index.html
def _assets_serve(request, path):
    asset_root = os.path.join(settings.FRONTEND_DIST, 'assets')
    asset_path = os.path.join(asset_root, path)
    if not os.path.exists(asset_path):
        # Log and return 404 so browser doesn't receive index.html with text/html mime
        try:
            logging.getLogger(__name__).warning('Asset not found: %s', asset_path)
        except Exception:
            pass
        return HttpResponse('Not Found', status=404)
    return static_serve(request, path, document_root=asset_root)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/users/', include('users.urls')),
    path('api/destination/', include('destinations.urls')),
    path('api/routes/', include('routes.urls')),
    path('api/currency/', include('currency.urls')),
    path('api/wallets/',include('wallets.urls')),
    path('api/booking/',include('booking.urls')),
    path('api/loyalty/', include('loyalty.urls')),
    path('api/creditbooking/', include('creditbooking.urls')),
    # Serve built frontend asset bundle files (JS/CSS/images)
    re_path(r'^assets/(?P<path>.*)$', _assets_serve),
    # Serve public folder copied files (favicon, robots, etc.)
    re_path(r'^(?P<path>favicon\\.ico|robots\\.txt|placeholder\\.svg)$', static_serve, { 'document_root': settings.FRONTEND_DIST }),
    # Serve images (png/jpg/svg/webp/ico) located at dist root (public copied assets)
    re_path(r'^(?P<path>.*\\.(?:png|jpg|jpeg|gif|svg|webp|ico))$', static_serve, { 'document_root': settings.FRONTEND_DIST }),
    # Serve lovable-uploads (copied from public/lovable-uploads)
    re_path(r'^lovable-uploads/(?P<path>.*)$', static_serve, { 'document_root': os.path.join(settings.FRONTEND_DIST, 'lovable-uploads') }),
    # Catch-all for SPA (must be last, exclude anything starting with api/)
    re_path(r'^(?!api/).*$', spa_index, name='spa-index'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

