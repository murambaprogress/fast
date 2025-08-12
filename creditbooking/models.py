from django.db import models
from django.conf import settings
from users.models import User
from booking.models import Booking
from destinations.models import Destination

class DocumentType(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    is_required = models.BooleanField(default=True)
    
    def __str__(self):
        return self.name

class CreditBooking(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='credit_bookings')
    booking = models.OneToOneField(Booking, on_delete=models.CASCADE, related_name='credit_booking')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reason = models.TextField()
    admin_notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Credit Booking {self.id} - {self.user.username}"

class CreditDocument(models.Model):
    credit_booking = models.ForeignKey(CreditBooking, on_delete=models.CASCADE, related_name='documents')
    document_type = models.ForeignKey(DocumentType, on_delete=models.PROTECT)
    file = models.FileField(upload_to='documents/credit_booking/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.document_type.name} - {self.credit_booking.id}"
