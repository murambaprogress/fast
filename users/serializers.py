from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
import re

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """Serializer for user data display and updates"""
    full_name = serializers.SerializerMethodField()
    is_corporate = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'first_name', 'last_name', 'email', 'phone_number', 
            'user_type', 'is_staff', 'is_active', 'email_verified',
            'company_name', 'company_address', 'company_registration_number', 
            'tin_tax_number', 'wallet_balance', 'date_joined', 'last_updated',
            'full_name', 'is_corporate'
        ]
        read_only_fields = ['id', 'date_joined', 'last_updated', 'full_name', 'is_corporate']
    
    def get_full_name(self, obj):
        return obj.get_full_name()
    
    def get_is_corporate(self, obj):
        return obj.is_corporate()

class UserRegistrationSerializer(serializers.ModelSerializer):
    registration_type = serializers.ChoiceField(choices=['individual', 'corporate'], default='individual')
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    
    class Meta:
        model = User
        fields = [
            'registration_type', 'first_name', 'last_name', 'email', 'phone_number', 
            'password', 'company_name', 'company_address', 'company_registration_number', 
            'tin_tax_number'
        ]
        extra_kwargs = {
            'company_name': {'required': False, 'allow_blank': True},
            'company_address': {'required': False, 'allow_blank': True},
            'company_registration_number': {'required': False, 'allow_blank': True},
            'tin_tax_number': {'required': False, 'allow_blank': True},
        }
    
    def validate_email(self, value):
        """Validate email format"""
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            raise serializers.ValidationError("Enter a valid email address.")
        return value
    
    def validate_phone_number(self, value):
        """Validate Zimbabwe phone number format"""
        zim_patterns = [
            r'^(\+263|263|0)(77|78|71|73|74)\d{7}$',  # Mobile
            r'^(\+263|263|0)(24|25|26|27|28|29)\d{6}$',  # Landlines
        ]
        
        if not any(re.match(pattern, value) for pattern in zim_patterns):
            raise serializers.ValidationError(
                "Enter a valid Zimbabwe phone number (e.g., +263771234567, 0771234567)."
            )
        return value
    
    def validate(self, data):
        """Additional validation for corporate users"""
        registration_type = data.get('registration_type')
        
        if registration_type == 'corporate':
            required_fields = ['company_name', 'company_address', 'company_registration_number', 'tin_tax_number']
            missing_fields = [field for field in required_fields if not data.get(field)]
            
            if missing_fields:
                raise serializers.ValidationError({
                    field: f"{field.replace('_', ' ').title()} is required for corporate registration."
                    for field in missing_fields
                })
        
        return data
    
    def create(self, validated_data):

        registration_type = validated_data.pop('registration_type', 'individual')
        password = validated_data.pop('password')
        validated_data['user_type'] = registration_type

        try:
            user = User.objects.create_user(password=password, **validated_data)

            # Generate and send verification code
            verification_code = user.generate_email_verification_code()
            self.send_verification_email(user, verification_code)

            return user

        except Exception as e:
            import traceback
            print("[ERROR] Registration failed:", e)
            traceback.print_exc()  # <- This will log full traceback in your Django server console
            raise serializers.ValidationError({"non_field_errors": [str(e)]})

    
    def send_verification_email(self, user, verification_code):
        """Send verification email with link and OTP to user"""
        subject = 'FastJet Loyalty - Verify Your Email'
        
        # Create verification link with OTP
        verification_link = f"{getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')}/verify-email?email={user.email}&code={verification_code}"
        
        # Simple text email (you can enhance this with HTML templates later)
        message = f"""
Hello {user.get_full_name()},

Welcome to FastJet Loyalty Program!

Your email verification code is: {verification_code}

You can also click this link to verify your email:
{verification_link}

This code will expire in 15 minutes.

If you didn't create this account, please ignore this email.

Best regards,
FastJet Loyalty Team
        """
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
            # Log the error but don't fail registration
            print(f"Failed to send verification email: {e}")

class EmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    verification_code = serializers.CharField(max_length=6, min_length=6)
    
    def validate(self, data):
        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        
        if user.email_verified:
            raise serializers.ValidationError("Email is already verified.")
        
        success, message = user.verify_email_code(data['verification_code'])
        if not success:
            raise serializers.ValidationError(message)
        
        data['user'] = user
        return data

class ResendVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        
        if user.email_verified:
            raise serializers.ValidationError("Email is already verified.")
        
        if not user.can_request_new_code():
            raise serializers.ValidationError("Please wait before requesting a new verification code.")
        
        return value
    
    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        
        verification_code = user.generate_email_verification_code()
        self.send_verification_email(user, verification_code)
        
        return user
    
    def send_verification_email(self, user, verification_code):
        """Send verification email with link and OTP to user"""
        subject = 'FastJet Loyalty - New Email Verification Code'
        
        # Create verification link with OTP
        verification_link = f"{getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')}/verify-email?email={user.email}&code={verification_code}"
        
        message = f"""
Hello {user.get_full_name()},

You requested a new verification code for your FastJet Loyalty account.

Your new email verification code is: {verification_code}

You can also click this link to verify your email:
{verification_link}

This code will expire in 15 minutes.

Best regards,
FastJet Loyalty Team
        """
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Failed to send verification email: {e}")

# Legacy serializer for backward compatibility (if you have existing code using it)
class RegisterSerializer(UserRegistrationSerializer):
    """Legacy serializer - use UserRegistrationSerializer instead"""
    pass