from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from datetime import timedelta
import re

User = get_user_model()
from .models import PendingUser

class UserRegistrationSerializer(serializers.ModelSerializer):
   password = serializers.CharField(write_only=True, min_length=8)
   confirm_password = serializers.CharField(write_only=True)
   
   # Corporate fields
   company_name = serializers.CharField(required=False, allow_blank=True)
   company_address = serializers.CharField(required=False, allow_blank=True)
   company_registration_number = serializers.CharField(required=False, allow_blank=True)
   tin_tax_number = serializers.CharField(required=False, allow_blank=True)
   vat_certificate = serializers.FileField(required=False, allow_null=True)
   corporate_tax_document = serializers.FileField(required=False, allow_null=True)
   certificate_of_incorporation = serializers.FileField(required=False, allow_null=True)
   
   # Student fields
   age = serializers.IntegerField(required=False, allow_null=True)
   institution = serializers.CharField(required=False, allow_blank=True)
   custom_institution = serializers.CharField(required=False, allow_blank=True)
   student_id = serializers.CharField(required=False, allow_blank=True)
   birth_certificate = serializers.FileField(required=False, allow_null=True)
   
   # Club fields
   club_name = serializers.CharField(required=False, allow_blank=True)
   number_of_members = serializers.IntegerField(required=False, allow_null=True)
   club_card_bank = serializers.CharField(required=False, allow_blank=True)
   account_number = serializers.CharField(required=False, allow_blank=True)
   
   class Meta:
       model = PendingUser
       fields = [
           'first_name', 'last_name', 'email', 'phone_number', 'password', 'confirm_password',
           'user_type', 'company_name', 'company_address', 'company_registration_number',
           'tin_tax_number', 'vat_certificate', 'corporate_tax_document', 'certificate_of_incorporation',
           'age', 'institution', 'custom_institution', 'student_id', 'birth_certificate',
           'club_name', 'number_of_members', 'club_card_bank', 'account_number'
       ]
       extra_kwargs = {
           'password': {'write_only': True},
       }
   
   def validate_email(self, value):
       # Check if email exists in actual users or pending users
       if User.objects.filter(email__iexact=value).exists():
           raise serializers.ValidationError("A user with this email already exists.")
       if PendingUser.objects.filter(email__iexact=value).exists():
           raise serializers.ValidationError("A user with this email is already pending verification.")
       return value
   
   def validate_phone_number(self, value):
       # Check if phone number exists in actual users or pending users
       if User.objects.filter(phone_number=value).exists():
           raise serializers.ValidationError("A user with this phone number already exists.")
       if PendingUser.objects.filter(phone_number=value).exists():
           raise serializers.ValidationError("A user with this phone number is already pending verification.")
       
       # Zimbabwe phone number validation patterns
       zim_patterns = [
           r'^(\+263|263|0)(77|78|71|73|74)\d{7}$',  # Mobile networks
           r'^(\+263|263|0)(24|25|26|27|28|29)\d{6}$',  # Landlines
       ]
       
       # Check if it's a Zimbabwe number and validate accordingly
       if value.startswith(('+263', '263', '0')):
           if not any(re.match(pattern, value) for pattern in zim_patterns):
               raise serializers.ValidationError(
                   "Please enter a valid Zimbabwe phone number (e.g., +263771234567 or 0771234567)."
               )
       
       return value
   
   def validate_password(self, value):
       try:
           validate_password(value)
       except ValidationError as e:
           raise serializers.ValidationError(e.messages)
       return value
   
   def validate(self, attrs):
       if attrs['password'] != attrs['confirm_password']:
           raise serializers.ValidationError("Passwords do not match.")
       
       user_type = attrs.get('user_type', 'individual')
       
       # Corporate validation
       if user_type == 'corporate':
           required_fields = ['company_name', 'company_address', 'company_registration_number', 'tin_tax_number']
           for field in required_fields:
               if not attrs.get(field):
                   raise serializers.ValidationError(f"{field.replace('_', ' ').title()} is required for corporate registration.")
           
           required_files = ['vat_certificate', 'corporate_tax_document', 'certificate_of_incorporation']
           for field in required_files:
               if not attrs.get(field):
                   raise serializers.ValidationError(f"{field.replace('_', ' ').title()} is required for corporate registration.")
       
       # Student validation
       elif user_type == 'student':
           required_fields = ['age', 'institution', 'student_id']
           for field in required_fields:
               if not attrs.get(field):
                   raise serializers.ValidationError(f"{field.replace('_', ' ').title()} is required for student registration.")
           
           if not attrs.get('birth_certificate'):
               raise serializers.ValidationError("Birth certificate is required for student registration.")
           
           if attrs.get('institution') == 'Other' and not attrs.get('custom_institution'):
               raise serializers.ValidationError("Custom institution name is required when 'Other' is selected.")
           
           age = attrs.get('age')
           if age and (age < 3 or age > 120):
               raise serializers.ValidationError("Age must be between 3 and 120.")
       
       # Club validation
       elif user_type == 'club':
           required_fields = ['club_name', 'number_of_members', 'club_card_bank', 'account_number']
           for field in required_fields:
               if not attrs.get(field):
                   raise serializers.ValidationError(f"{field.replace('_', ' ').title()} is required for club registration.")
           
           number_of_members = attrs.get('number_of_members')
           if number_of_members and number_of_members < 1:
               raise serializers.ValidationError("Number of members must be at least 1.")
       
       return attrs
   
   def create(self, validated_data):
       validated_data.pop('confirm_password')
       password = validated_data.pop('password')
       
       # Hash the password
       validated_data['password_hash'] = make_password(password)
       
       # Generate verification code
       from users.views import generate_otp
       validated_data['email_verification_code'] = generate_otp()
       validated_data['verification_code_expires'] = timezone.now() + timedelta(minutes=10)
       
       pending_user = PendingUser.objects.create(**validated_data)
       return pending_user

class UserSerializer(serializers.ModelSerializer):
   full_name = serializers.CharField(source='get_full_name', read_only=True)
   balances = serializers.SerializerMethodField()
   
   class Meta:
       model = User
       fields = [
           'id', 'first_name', 'last_name', 'full_name', 'email', 'phone_number',
           'user_type', 'email_verified', 'is_approved', 'approval_comment',
           'company_name', 'company_address', 'company_registration_number', 'tin_tax_number',
           'age', 'institution', 'custom_institution', 'student_id',
           'club_name', 'number_of_members', 'club_card_bank', 'account_number',
           'date_joined', 'last_login', 'is_active', 'balances'
       ]
       read_only_fields = ['id', 'date_joined', 'last_login', 'email_verified']
   
   def get_balances(self, obj):
       try:
           from wallets.models import Wallet, WalletBalance
           wallet = Wallet.objects.get(user=obj)
           balances = WalletBalance.objects.filter(wallet=wallet)
           return [
               {
                   'currency': balance.currency.code,
                   'balance': str(balance.balance)
               }
               for balance in balances
           ]
       except:
           return []

class EmailVerificationSerializer(serializers.Serializer):
   email = serializers.EmailField()
   verification_code = serializers.CharField(max_length=6, min_length=6)
   
   def validate(self, attrs):
       email = attrs['email']
       verification_code = attrs['verification_code']
       
       # First check if this is a pending user
       try:
           pending_user = PendingUser.objects.get(email__iexact=email)
           if not pending_user.is_verification_code_valid(verification_code):
               pending_user.verification_attempts += 1
               pending_user.save(update_fields=['verification_attempts'])
               raise serializers.ValidationError("Invalid or expired verification code.")
           
           # Create the actual user
           user = pending_user.create_actual_user()
           attrs['user'] = user
           attrs['is_new_user'] = True
           return attrs
           
       except PendingUser.DoesNotExist:
           pass
       
       # Check existing users (legacy support)
       try:
           user = User.objects.get(email__iexact=email)
       except User.DoesNotExist:
           raise serializers.ValidationError("User with this email does not exist.")
       
       if user.email_verified:
           raise serializers.ValidationError("Email is already verified.")
       
       # Format both user's verification code and provided code as 6-digit strings
       formatted_stored_code = str(user.email_verification_code).zfill(6)
       formatted_provided_code = str(verification_code).zfill(6)
       
       if formatted_stored_code != formatted_provided_code:
           user.email_verification_attempts += 1
           user.save()
           print(f"[DEBUG] Invalid verification code. Expected: {formatted_stored_code}, Provided: {formatted_provided_code}")
           raise serializers.ValidationError("Invalid verification code.")
       
       # Mark email as verified
       user.email_verified = True
       user.email_verification_code = None
       user.save()
       
       attrs['user'] = user
       attrs['is_new_user'] = False
       return attrs

class ResendVerificationSerializer(serializers.Serializer):
   email = serializers.EmailField()
   
   def validate_email(self, value):
       # First check pending users
       try:
           pending_user = PendingUser.objects.get(email__iexact=value)
           if not pending_user.can_request_new_code():
               raise serializers.ValidationError("Please wait before requesting a new verification code.")
           self.pending_user = pending_user
           return value
       except PendingUser.DoesNotExist:
           pass
       
       # Check existing users (legacy support)
       try:
           user = User.objects.get(email__iexact=value)
       except User.DoesNotExist:
           raise serializers.ValidationError("User with this email does not exist.")
       
       if user.email_verified:
           raise serializers.ValidationError("Email is already verified.")
       
       if not user.can_request_new_code():
           raise serializers.ValidationError("Please wait before requesting a new verification code.")
       
       self.user = user
       return value
   
   def validate(self, attrs):
       if hasattr(self, 'pending_user'):
           attrs['pending_user'] = self.pending_user
       elif hasattr(self, 'user'):
           attrs['user'] = self.user
       return attrs

# New Serializers for Password Reset
class PasswordResetRequestSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=255, help_text="Email or phone number")

    def validate_identifier(self, value):
        if not User.objects.filter(Q(email__iexact=value) | Q(phone_number=value)).exists():
            raise serializers.ValidationError("User with this email or phone number does not exist.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=255)
    code = serializers.CharField(max_length=6, min_length=6)
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        
        try:
            validate_password(attrs['password'])
        except ValidationError as e:
            raise serializers.ValidationError({'password': list(e.messages)})

        try:
            user = User.objects.get(Q(email__iexact=attrs['identifier']) | Q(phone_number=attrs['identifier']))
        except User.DoesNotExist:
            raise serializers.ValidationError({"identifier": "Invalid user."})

        if not user.is_password_reset_code_valid(attrs['code']):
            raise serializers.ValidationError({"code": "Invalid or expired verification code."})
        
        attrs['user'] = user
        return attrs
