# loyalty/signals.py

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import LoyaltyAccount

User = get_user_model()

@receiver(post_save, sender=User)
def create_loyalty_account(sender, instance, created, **kwargs):
    if created:
        LoyaltyAccount.objects.get_or_create(user=instance)
