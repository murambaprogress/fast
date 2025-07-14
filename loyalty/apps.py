# loyalty/apps.py

from django.apps import AppConfig

class LoyaltyConfig(AppConfig):
    name = 'loyalty'

    def ready(self):
        import loyalty.signals
