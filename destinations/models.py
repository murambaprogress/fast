from django.db import models

class Destination(models.Model):
    name = models.CharField(max_length=100)
    subdestinations = models.TextField(blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    map_link = models.URLField(blank=True)
    picture = models.ImageField(upload_to='destinations/', blank=True, null=True)

    def __str__(self):
        return self.name
