from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
import re
from wallets.models import WalletBalance, Currency # Assuming these models exist

User = get_user_model()

class WalletBalanceSerializer(serializers.ModelSerializer):
    currency = serializers.SlugRelatedField(slug_field='code', queryset=Currency.objects.all())

    class Meta:
        model = WalletBalance
        fields = ['currency', 'balance']

class UserSerializer(serializers.ModelSerializer):
    """Serializer for user data display and updates"""
    full_name = serializers.SerializerMethodField()
    is_corporate = serializers.SerializerMethodField()
    # Expose document URLs
    vat_certificate = serializers.FileField(read_only=True, source='vat_certificate.url')
    corporate_tax_document = serializers.FileField(read_only=True, source='corporate_tax_document.url')
    certificate_of_incorporation = serializers.FileField(read_only=True, source='certificate_of_incorporation.url')
    birth_certificate = serializers.FileField(read_only=True, source='birth_certificate.url')
    wallet_balance = serializers.SerializerMethodField() # Use SerializerMethodField for wallet balances

    class Meta:
        model = User
        fields = [
            'id', 'first_name', 'last_name', 'email', 'phone_number',
            'user_type', 'is_staff', 'is_active', 'email_verified',
            'is_approved', 'approval_comment', # Added is_approved and approval_comment
            'company_name', 'company_address', 'company_registration_number',
            'tin_tax_number', 'vat_certificate', 'corporate_tax_document',
            'certificate_of_incorporation',
            'age', 'institution', 'custom_institution', 'student_id', 'birth_certificate',
            'wallet_balance', 'date_joined', 'last_updated',
            'full_name', 'is_corporate',
        ]
        read_only_fields = [
            'id', 'date_joined', 'last_updated', 'full_name',
            'is_corporate', 'is_approved', 'approval_comment' # Made read-only for users
        ]

    def get_full_name(self, obj):
        return obj.get_full_name()

    def get_is_corporate(self, obj):
        return obj.is_corporate()

    def get_wallet_balance(self, obj):
        if hasattr(obj, 'wallet'):
            balances = obj.wallet.balances.all()
            return WalletBalanceSerializer(balances, many=True).data
        return []

class UserRegistrationSerializer(serializers.ModelSerializer):
    # registration_type will be used to determine the user_type for the User model
    registration_type = serializers.ChoiceField(choices=['individual', 'corporate', 'student'], default='individual')
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, required=True) # Added confirm_password

    class Meta:
        model = User
        fields = [
            'registration_type', 'first_name', 'last_name', 'email', 'phone_number',
            'password', 'confirm_password', # Include confirm_password
            # Corporate
            'company_name', 'company_address', 'company_registration_number',
            'tin_tax_number', 'vat_certificate', 'corporate_tax_document', 'certificate_of_incorporation',
            # Student
            'age', 'institution', 'custom_institution', 'student_id', 'birth_certificate'
        ]

        extra_kwargs = {
            # CharFields that support allow_blank
            'company_name': {'required': False, 'allow_blank': True},
            'company_address': {'required': False, 'allow_blank': True},
            'company_registration_number': {'required': False, 'allow_blank': True},
            'tin_tax_number': {'required': False, 'allow_blank': True},
            'institution': {'required': False, 'allow_blank': True},
            'custom_institution': {'required': False, 'allow_blank': True},
            'student_id': {'required': False, 'allow_blank': True},

            # Integer or file fields (allow_null only, no allow_blank)
            'age': {'required': False, 'allow_null': True},
            'vat_certificate': {'required': False, 'allow_null': True},
            'corporate_tax_document': {'required': False, 'allow_null': True},
            'certificate_of_incorporation': {'required': False, 'allow_null': True},
            'birth_certificate': {'required': False, 'allow_null': True},
        }


    def validate_email(self, value):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            raise serializers.ValidationError("Enter a valid email address.")
        return value

    def validate_phone_number(self, value):
        zim_patterns = [
            r'^(\+263|263|0)(77|78|71|73|74)\d{7}$',
            r'^(\+263|263|0)(24|25|26|27|28|29)\d{6}$',
        ]
        if not any(re.match(pattern, value) for pattern in zim_patterns):
            raise serializers.ValidationError(
                "Enter a valid Zimbabwe phone number (e.g., +263771234567, 0771234567)."
            )
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']: # Check password match
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})

        user_type = data.get('registration_type')

        # Clear fields not relevant to the chosen user_type
        if user_type == 'individual':
            # Ensure corporate and student fields are null/empty for individual
            for field in ['company_name', 'company_address', 'company_registration_number', 'tin_tax_number',
                          'vat_certificate', 'corporate_tax_document', 'certificate_of_incorporation',
                          'age', 'institution', 'custom_institution', 'student_id', 'birth_certificate']:
                data[field] = None # Set to None for FileFields and nullable fields
        elif user_type == 'corporate':
            # Ensure student fields are null/empty for corporate
            for field in ['age', 'institution', 'custom_institution', 'student_id', 'birth_certificate']:
                data[field] = None
            # Validate corporate required fields
            required_fields = [
                'company_name', 'company_address',
                'company_registration_number', 'tin_tax_number',
                'vat_certificate', 'corporate_tax_document', 'certificate_of_incorporation'
            ]
            missing = [f for f in required_fields if not data.get(f)]
            if missing:
                raise serializers.ValidationError({
                    f: f"{f.replace('_', ' ').title()} is required for corporate registration."
                    for f in missing
                })
        elif user_type == 'student':
            # Ensure corporate fields are null/empty for student
            for field in ['company_name', 'company_address', 'company_registration_number', 'tin_tax_number',
                          'vat_certificate', 'corporate_tax_document', 'certificate_of_incorporation']:
                data[field] = None
            # Validate student required fields
            student_fields = ['age', 'institution', 'student_id', 'birth_certificate']
            missing = [f for f in student_fields if not data.get(f)]
            if missing:
                raise serializers.ValidationError({
                    f: f"{f.replace('_', ' ').title()} is required for student registration."
                    for f in missing
                })
            if data.get('institution') == 'Other' and not data.get('custom_institution'):
                raise serializers.ValidationError({
                    'custom_institution': "Specify institution if 'Other' is selected."
                })

        return data

    def create(self, validated_data):
        registration_type = validated_data.pop('registration_type', 'individual')
        password = validated_data.pop('password')
        validated_data.pop('confirm_password') # Pop confirm_password before passing to create_user
        validated_data['user_type'] = registration_type

        try:
            user = User.objects.create_user(password=password, **validated_data)

            # Only send verification email if not admin phone (admin email is for login OTP)
            # For regular users (individual, corporate, student), email verification is still part of the flow
            # but the code is sent via SMS as per previous instruction.
            verification_code = user.generate_email_verification_code()
            # The actual sending of SMS/Email is handled in views.py based on user_type/phone_number
            # This serializer just ensures the code is generated and associated with the user.

            return user

        except Exception as e:
            import traceback
            print("[ERROR] Registration failed:", e)
            traceback.print_exc()
            raise serializers.ValidationError({"non_field_errors": [str(e)]})

    def send_verification_email(self, user, verification_code):
        # This method is called by the User model's generate_email_verification_code,
        # but the actual sending mechanism (SMS vs Email) is controlled in views.py
        # based on user type. This method can be simplified or removed if not directly used for sending.
        # For now, keeping it as a placeholder if other parts of the system rely on its existence.
        subject = 'FastJet Loyalty - Verify Your Email'
        verification_link = f"{getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')}/verify-email?email={user.email}&code={verification_code}"

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
            # This send_mail is for the email verification, not the admin login OTP.
            # It will only be triggered if the user's email is not the admin email.
            # The actual sending for non-admin users is now primarily SMS-based from views.py
            # This part might be redundant if all non-admin verification is SMS.
            # However, the email_verified field is still on the User model, so keeping this for now.
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
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
        subject = 'FastJet Loyalty - New Email Verification Code'
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

# Legacy support
class RegisterSerializer(UserRegistrationSerializer):
    pass
