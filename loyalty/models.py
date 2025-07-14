from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

TRANSACTION_TYPE_CHOICES = [
    ('earn', 'Earned Points'),
    ('redeem', 'Redeemed Points'),
    ('bonus', 'Bonus Points'),
    ('expired', 'Expired Points'),
]

REDEMPTION_STATUS_CHOICES = [
    ('pending', 'Pending Admin Approval'),
    ('approved', 'Approved'),
    ('rejected', 'Rejected'),
    ('completed', 'Completed'),
]

REDEMPTION_TYPE_CHOICES = [
    ('free_flight', 'Free Economy Ticket'),
    ('wallet_credit', 'Wallet Credit'),
    ('priority_boarding', 'Priority Boarding'),
    ('lounge_access', 'Lounge Access'),
    ('extra_baggage', 'Extra Baggage'),
]

class LoyaltyAccount(models.Model):
    """User's loyalty account to track points"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='loyalty_account')
    points = models.IntegerField(default=0)
    lifetime_points = models.IntegerField(default=0)
    tier = models.CharField(max_length=20, default='Bronze')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.phone_number} - {self.points} points"

    def can_redeem_free_flight(self):
        """Check if user has enough points for free flight"""
        return self.points >= 1000

    def add_points(self, points, description=""):
        """Add points to account"""
        self.points += points
        self.lifetime_points += points
        self.save()
        
        # Create transaction record
        LoyaltyTransaction.objects.create(
            user=self.user,
            points=points,
            transaction_type='earn',
            description=description
        )

    def deduct_points(self, points, description=""):
        """Deduct points from account"""
        if self.points >= points:
            self.points -= points
            self.save()
            
            # Create transaction record
            LoyaltyTransaction.objects.create(
                user=self.user,
                points=-points,
                transaction_type='redeem',
                description=description
            )
            return True
        return False

class LoyaltyTransaction(models.Model):
    """Track all loyalty point transactions"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='loyalty_transactions')
    booking = models.ForeignKey('booking.Booking', on_delete=models.SET_NULL, null=True, blank=True)
    points = models.IntegerField()
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.phone_number} - {self.points} points ({self.transaction_type})"

class PointRedemption(models.Model):
    """Track point redemption requests"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='redemptions')
    redemption_type = models.CharField(max_length=20, choices=REDEMPTION_TYPE_CHOICES)
    points_required = models.IntegerField()
    status = models.CharField(max_length=20, choices=REDEMPTION_STATUS_CHOICES, default='pending')
    
    # Admin fields
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_redemptions')
    review_date = models.DateTimeField(null=True, blank=True)
    admin_notes = models.TextField(blank=True)
    
    # Redemption details
    flight_route = models.CharField(max_length=200, blank=True)  # For free flights
    preferred_date = models.DateField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.phone_number} - {self.redemption_type} ({self.status})"

    def approve(self, admin_user, notes=""):
        """Approve the redemption"""
        self.status = 'approved'
        self.reviewed_by = admin_user
        self.review_date = timezone.now()
        self.admin_notes = notes
        self.save()

        # Deduct points from user account
        loyalty_account = self.user.loyalty_account
        loyalty_account.deduct_points(
            self.points_required, 
            f"Redeemed for {self.get_redemption_type_display()}"
        )

    def reject(self, admin_user, notes=""):
        """Reject the redemption"""
        self.status = 'rejected'
        self.reviewed_by = admin_user
        self.review_date = timezone.now()
        self.admin_notes = notes
        self.save()
