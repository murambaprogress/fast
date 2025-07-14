from django.db import models
from destinations.models import Destination

CURRENCY_CHOICES = [
    ('USD', 'USD'),
    ('ZAR', 'ZAR'),
]

class Route(models.Model):
    from_destination = models.ForeignKey(Destination, on_delete=models.CASCADE, related_name='routes_from')
    to_destination = models.ForeignKey(Destination, on_delete=models.CASCADE, related_name='routes_to')
    point_threshold = models.IntegerField()
    currency = models.CharField(max_length=3, choices=CURRENCY_CHOICES, default='USD')  # 🆕
    price = models.DecimalField(max_digits=10, decimal_places=2)
    estimated_time = models.CharField(max_length=100)
    distance = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.from_destination.name} → {self.to_destination.name} ({self.currency})"
