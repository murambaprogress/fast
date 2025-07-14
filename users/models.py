from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from datetime import timedelta
import random
import string

class UserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, **extra_fields):
        if not phone_number:
            raise ValueError('The Phone Number must be set')
        
        # Handle email validation
        email = extra_fields.get('email')
        if email:
            extra_fields['email'] = self.normalize_email(email)
            
        user = self.model(phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_type', 'individual')
        extra_fields.setdefault('email_verified', True)  # Superusers are pre-verified
        
        return self.create_user(phone_number, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    # User type choices
    USER_TYPE_CHOICES = [
        ('individual', 'Individual'),
        ('corporate', 'Corporate'),
    ]
    
    # Basic user information
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='individual')
    
    # Email verification fields
    email_verified = models.BooleanField(default=False)
    email_verification_code = models.CharField(max_length=6, blank=True, null=True)
    email_verification_code_expires = models.DateTimeField(blank=True, null=True)
    email_verification_attempts = models.IntegerField(default=0)
    
    # Corporate information
    company_name = models.CharField(max_length=255, blank=True, null=True)
    company_address = models.TextField(blank=True, null=True)
    company_registration_number = models.CharField(max_length=50, blank=True, null=True)
    tin_tax_number = models.CharField(max_length=50, blank=True, null=True)
    
    # Wallet balance
    wallet_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    # Date fields
    date_joined = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    def __str__(self):
        if self.user_type == 'corporate' and self.company_name:
            return f"{self.company_name} ({self.phone_number})"
        return f"{self.first_name} {self.last_name} ({self.phone_number})"
    
    def get_full_name(self):
        if self.user_type == 'corporate' and self.company_name:
            return self.company_name
        return f"{self.first_name} {self.last_name}"
    
    def get_short_name(self):
        if self.user_type == 'corporate':
            return self.company_name
        return self.first_name
    
    def is_corporate(self):
        return self.user_type == 'corporate'
    
    def generate_email_verification_code(self):
        """Generate a 6-digit verification code"""
        self.email_verification_code = ''.join(random.choices(string.digits, k=6))
        self.email_verification_code_expires = timezone.now() + timedelta(minutes=15)  # 15 minutes expiry
        self.email_verification_attempts = 0
        self.save(update_fields=['email_verification_code', 'email_verification_code_expires', 'email_verification_attempts'])
        return self.email_verification_code
    
    def verify_email_code(self, code):
        """Verify the email verification code"""
        if not self.email_verification_code:
            return False, "No verification code found. Please request a new one."
        
        if self.email_verification_code_expires < timezone.now():
            return False, "Verification code has expired. Please request a new one."
        
        if self.email_verification_attempts >= 5:
            return False, "Too many verification attempts. Please request a new code."
        
        if self.email_verification_code != code:
            self.email_verification_attempts += 1
            self.save(update_fields=['email_verification_attempts'])
            return False, f"Invalid verification code. {5 - self.email_verification_attempts} attempts remaining."
        
        # Code is valid
        self.email_verified = True
        self.email_verification_code = None
        self.email_verification_code_expires = None
        self.email_verification_attempts = 0
        self.save(update_fields=['email_verified', 'email_verification_code', 'email_verification_code_expires', 'email_verification_attempts'])
        
        return True, "Email verified successfully."
    
    def can_request_new_code(self):
        """Check if user can request a new verification code"""
        if not self.email_verification_code_expires:
            return True
        
        # Allow new code request if current one expired or if it's been more than 2 minutes
        time_since_last_code = timezone.now() - (self.email_verification_code_expires - timedelta(minutes=15))
        return time_since_last_code > timedelta(minutes=2)

class EmailVerificationLog(models.Model):
    """Log email verification attempts for security and debugging"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_logs')
    verification_code = models.CharField(max_length=6)
    sent_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-sent_at']
    
    def __str__(self):
        return f"Verification for {self.user.email} at {self.sent_at}"