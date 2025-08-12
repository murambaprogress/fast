from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone
from decimal import Decimal
import random
import string

class UserManager(BaseUserManager):
   def create_user(self, phone_number, email, password=None, **extra_fields):
       if not phone_number:
           raise ValueError('The Phone Number field must be set')
       if not email:
           raise ValueError('The Email field must be set')
       
       email = self.normalize_email(email)
       user = self.model(phone_number=phone_number, email=email, **extra_fields)
       user.set_password(password)
       
       # Import here to avoid circular imports
       from users.views import generate_otp
       
       # Generate email verification code
       user.email_verification_code = generate_otp()
       
       # Set approval status based on user type
       user_type = extra_fields.get('user_type', 'individual')
       if user_type in ['corporate', 'student', 'club']:
           user.is_approved = False  # Requires admin approval
       else:
           user.is_approved = True  # Individual users are auto-approved
       
       user.save(using=self._db)
       return user

   def create_superuser(self, phone_number, email, password=None, **extra_fields):
       extra_fields.setdefault('is_staff', True)
       extra_fields.setdefault('is_superuser', True)
       extra_fields.setdefault('is_approved', True)
       extra_fields.setdefault('email_verified', True)
       
       if extra_fields.get('is_staff') is not True:
           raise ValueError('Superuser must have is_staff=True.')
       if extra_fields.get('is_superuser') is not True:
           raise ValueError('Superuser must have is_superuser=True.')
       
       return self.create_user(phone_number, email, password, **extra_fields)

class User(AbstractUser):
   USER_TYPE_CHOICES = [
       ('individual', 'Individual'),
       ('corporate', 'Corporate'),
       ('student', 'Student'),
       ('club', 'Club'),
   ]
   
   INSTITUTION_CHOICES = [
       ('Falcon', 'Falcon'),
       ('St George', 'St George'),
       ('Other', 'Other'),
   ]
   
   CLUB_BANK_CHOICES = [
       ('BANCABC', 'BANCABC'),
       ('CBZ', 'CBZ'),
   ]
   
   username = None  # Remove username field
   phone_number = models.CharField(max_length=20, unique=True)
   email = models.EmailField(unique=True)
   first_name = models.CharField(max_length=30)
   last_name = models.CharField(max_length=30)
   user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='individual')
   
   # Email verification
   email_verified = models.BooleanField(default=False)
   email_verification_code = models.CharField(max_length=6, blank=True, null=True)
   email_verification_attempts = models.IntegerField(default=0)
   last_verification_attempt = models.DateTimeField(blank=True, null=True)
   
   # Approval system for corporate, student, and club accounts
   is_approved = models.BooleanField(default=True)  # Individual users are auto-approved
   approval_comment = models.TextField(blank=True, null=True)
   
   # Corporate fields
   company_name = models.CharField(max_length=200, blank=True, null=True)
   company_address = models.TextField(blank=True, null=True)
   company_registration_number = models.CharField(max_length=100, blank=True, null=True)
   tin_tax_number = models.CharField(max_length=100, blank=True, null=True)
   vat_certificate = models.FileField(upload_to='documents/vat_certificates/', blank=True, null=True)
   corporate_tax_document = models.FileField(upload_to='documents/corporate_tax/', blank=True, null=True)
   certificate_of_incorporation = models.FileField(upload_to='documents/incorporation/', blank=True, null=True)
   
   # Student fields
   age = models.PositiveIntegerField(blank=True, null=True)
   institution = models.CharField(max_length=50, choices=INSTITUTION_CHOICES, blank=True, null=True)
   custom_institution = models.CharField(max_length=200, blank=True, null=True)
   student_id = models.CharField(max_length=100, blank=True, null=True)
   birth_certificate = models.FileField(upload_to='documents/birth_certificates/', blank=True, null=True)
   
   # Club fields
   club_name = models.CharField(max_length=200, blank=True, null=True)
   number_of_members = models.PositiveIntegerField(blank=True, null=True)
   club_card_bank = models.CharField(max_length=20, choices=CLUB_BANK_CHOICES, blank=True, null=True)
   account_number = models.CharField(max_length=50, blank=True, null=True)
   
   # Wallet balance (kept for backward compatibility)
   wallet_balance = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))

   # New fields for password reset
   password_reset_code = models.CharField(max_length=6, blank=True, null=True)
   password_reset_expires = models.DateTimeField(blank=True, null=True)
   
   objects = UserManager()
   
   USERNAME_FIELD = 'phone_number'
   REQUIRED_FIELDS = ['email', 'first_name', 'last_name']
   
   def __str__(self):
       return f"{self.first_name} {self.last_name} ({self.phone_number})"
   
   def is_corporate(self):
       return self.user_type == 'corporate'
   
   def is_student(self):
       return self.user_type == 'student'
   
   def is_club(self):
       return self.user_type == 'club'
   
   def can_request_new_code(self):
       from datetime import timedelta
       
       if not self.last_verification_attempt:
           return True
       
       time_since_last = timezone.now() - self.last_verification_attempt
       return time_since_last >= timedelta(minutes=2)
   
   def get_full_name(self):
       return f"{self.first_name} {self.last_name}"

   def generate_password_reset_code(self):
       self.password_reset_code = ''.join(random.choices(string.digits, k=6))
       self.password_reset_expires = timezone.now() + timezone.timedelta(minutes=10)
       self.save(update_fields=['password_reset_code', 'password_reset_expires'])

   def is_password_reset_code_valid(self, code):
       if not self.password_reset_code or not self.password_reset_expires:
           return False
       return self.password_reset_code == code and self.password_reset_expires > timezone.now()

class EmailVerificationLog(models.Model):
   user = models.ForeignKey(User, on_delete=models.CASCADE)
   verification_code = models.CharField(max_length=6)
   created_at = models.DateTimeField(auto_now_add=True)
   verified_at = models.DateTimeField(blank=True, null=True)
   ip_address = models.GenericIPAddressField(blank=True, null=True)
   user_agent = models.TextField(blank=True, null=True)
   
   def __str__(self):
       return f"Verification for {self.user.email} at {self.created_at}"
