from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.contrib.auth import authenticate, get_user_model
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from decimal import Decimal
from twilio.rest import Client
from rest_framework.authtoken.models import Token # Import Token model
# Ensure TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_SMS_FROM are in settings.py
twilio_client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
import random
import string
from wallets.serializers import WalletSerializer # Assuming this serializer exists
from wallets.models import Wallet, WalletBalance # Assuming these models exist
from currency.models import Currency # Assuming this model exists

from .serializers import (
    UserRegistrationSerializer,
    UserSerializer,
    EmailVerificationSerializer,
    ResendVerificationSerializer
)
from .models import User, EmailVerificationLog

User = get_user_model()

# Admin credentials (ensure these are set in your settings.py for production)
# IMPORTANT: This should be the full E.164 formatted phone number, e.g., "+263771234567"
ADMIN_PHONE = getattr(settings, 'ADMIN_PHONE', "+263999999999") # Updated to E.164 format
ADMIN_PASSWORD = getattr(settings, 'ADMIN_PASSWORD', "fastjetv1")
ADMIN_EMAIL = getattr(settings, 'ADMIN_EMAIL', "murambaprogress@gmail.com")

# Store admin OTP temporarily (in production, use Redis or database)
admin_otp_storage = {}

# --- Helper functions for sending OTPs ---
def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def send_admin_otp_email(otp_code):
    """Send OTP to admin email"""
    subject = 'FastJet Admin Login - OTP Verification'
    message = f"""
    Admin Login Verification

    Your OTP code for admin dashboard access is: {otp_code}

    This code will expire in 10 minutes.

    If you didn't attempt to login, please ignore this email.

    FastJet Loyalty System
    """

    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [ADMIN_EMAIL],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send admin OTP email: {e}")
        return False

def send_user_otp_sms(phone_number, otp_code):
    """Send OTP via SMS to a regular user's phone number"""
    try:
        message_body = f"FastJet OTP: {otp_code}. Expires in 10 min."
        # Twilio requires phone numbers in E.164 format (e.g., +263771234567)
        # Ensure the phone_number passed here already includes the '+' prefix
        message = twilio_client.messages.create(
            body=message_body,
            from_=settings.TWILIO_SMS_FROM, # This must be your Twilio number
            to=phone_number # Assumes phone_number is already in E.164 format
        )
        if message.sid:
            return True
        return False
    except Exception as e:
        print(f"Twilio Exception: {e}")
        return False

# --- Registration ---
class RegisterView(APIView):
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save() # user.is_approved is set in UserManager.create_user

            # Create a wallet for the new user
            Wallet.objects.create(user=user)

            try:
                # Only send SMS for normal users on registration
                if user.phone_number == ADMIN_PHONE:
                    print(f"Admin phone number {ADMIN_PHONE} attempted registration. No SMS sent for verification.")
                else:
                    # For regular users (individual, corporate, student), send SMS verification
                    send_user_otp_sms(user.phone_number, user.email_verification_code)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            EmailVerificationLog.objects.create(
                user=user,
                verification_code=user.email_verification_code,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            return Response({
                "message": "User registered successfully. Verification code sent.",
                "user_created": True,
                "user_type": user.user_type, # Use user.user_type from model
                "phone_number": user.phone_number,
                "requires_verification": True,
                "is_approved": user.is_approved # Include approval status in response
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# --- Email Verification (for users who received SMS code) ---
class VerifyEmailView(APIView):
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']

            # Log successful verification
            verification_log = EmailVerificationLog.objects.filter(
                user=user,
                verification_code=request.data.get('verification_code')
            ).first()

            if verification_log:
                verification_log.verified_at = timezone.now()
                verification_log.save()

            return Response({
                "message": "Email verified successfully. You can now log in.",
                "email_verified": True
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# --- Resend SMS Verification Code (for normal users) ---
class ResendVerificationView(APIView):
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            try:
                # Only send SMS for normal users on resend
                if user.phone_number == ADMIN_PHONE:
                    print(f"Admin phone number {ADMIN_PHONE} requested resend. No SMS sent for verification.")
                else:
                    send_user_otp_sms(user.phone_number, user.email_verification_code)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            EmailVerificationLog.objects.create(
                user=user,
                verification_code=user.email_verification_code,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            return Response({
                "message": "New verification code sent.",
                "phone_number": user.phone_number
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# --- Login ---
class LoginView(APIView):
    def post(self, request):
        phone_number = request.data.get("phone_number")
        password = request.data.get("password")

        # Check for admin credentials
        if phone_number == ADMIN_PHONE and password == ADMIN_PASSWORD:
            # Ensure a proper admin user exists for token generation
            admin_user, created = User.objects.get_or_create(
                phone_number=ADMIN_PHONE,
                defaults={
                    'email': ADMIN_EMAIL,
                    'first_name': 'FastJet',
                    'last_name': 'Admin',
                    'is_staff': True,
                    'is_superuser': True,
                    'is_active': True,
                    'email_verified': True, # Admin email is considered verified
                    'is_approved': True, # Admin is always approved
                    'user_type': 'individual' # Admin is a special individual user
                }
            )
            if created:
                admin_user.set_password(ADMIN_PASSWORD) # Set password only if created
                admin_user.save()
            elif not admin_user.check_password(ADMIN_PASSWORD):
                # If user exists but password doesn't match, update it (e.g., if password was changed manually)
                admin_user.set_password(ADMIN_PASSWORD)
                admin_user.save()

            # Generate and send OTP for admin via EMAIL
            otp_code = generate_otp()
            expiry_time = timezone.now() + timezone.timedelta(minutes=10)

            # Store OTP temporarily, associated with the admin_user's ID
            admin_otp_storage[admin_user.id] = { # Use user ID for storage
                'otp': otp_code,
                'expiry': expiry_time,
                'attempts': 0
            }

            # Send OTP email
            if send_admin_otp_email(otp_code):
                return Response({
                    "message": "Admin credentials verified. OTP sent to admin email.",
                    "requires_admin_otp": True,
                    "admin_email": ADMIN_EMAIL,
                    "phone_number": phone_number,
                    "admin_user_id": admin_user.id # Pass admin user ID for OTP verification
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Failed to send OTP. Please try again."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Regular user authentication
        user = authenticate(request, phone_number=phone_number, password=password)
        if user:
            # Check if email is verified (assuming normal users verify via SMS code for email)
            if not user.email_verified:
                return Response({
                    "error": "Email not verified. Please verify your email before logging in.",
                    "requires_verification": True,
                    "email": user.email
                }, status=status.HTTP_403_FORBIDDEN)

            # Check if corporate/student account is approved
            if user.user_type in ['corporate', 'student'] and not user.is_approved:
                status_message = "Your account is currently under review by the admin. Please check back later."
                if user.approval_comment:
                    status_message = f"Your account has been declined: {user.approval_comment}. Please contact support for more details."
                return Response({
                    "error": status_message,
                    "account_status": "pending_approval" if not user.approval_comment else "declined",
                    "approval_comment": user.approval_comment,
                    "user_type": user.user_type,
                    "email": user.email,
                    "is_approved": user.is_approved # Explicitly send this
                }, status=status.HTTP_403_FORBIDDEN)

            # Generate or retrieve token for regular user
            token, created = Token.objects.get_or_create(user=user)

            return Response({
                "message": "Login successful",
                "token": token.key, # Return the token
                "user": {
                    "id": user.id,
                    "phone_number": user.phone_number,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                    "is_staff": user.is_staff,
                    "user_type": user.user_type,
                    "email_verified": user.email_verified,
                    "is_approved": user.is_approved, # Include approval status
                    "company_name": user.company_name if user.is_corporate() else None,
                }
            }, status=status.HTTP_200_OK)
        return Response({"error": "Invalid phone number or password"}, status=status.HTTP_401_UNAUTHORIZED)


# --- Admin OTP Verification ---
class AdminOTPVerificationView(APIView):
    def post(self, request):
        phone_number = request.data.get("phone_number")
        otp_code = request.data.get("otp_code")
        admin_user_id = request.data.get("admin_user_id") # Get admin user ID

        if not phone_number or not otp_code or not admin_user_id:
            return Response({
                "error": "Phone number, OTP code, and admin user ID are required."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if this is admin phone number (must match the full E.164 format)
        if phone_number != ADMIN_PHONE:
            return Response({
                "error": "Invalid admin credentials."
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            admin_user = User.objects.get(id=admin_user_id, phone_number=ADMIN_PHONE, is_staff=True)
        except User.DoesNotExist:
            return Response({
                "error": "Admin user not found or invalid."
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Check if OTP exists and is valid for this admin_user_id
        stored_otp_data = admin_otp_storage.get(admin_user.id) # Use user ID for lookup
        if not stored_otp_data:
            return Response({
                "error": "No OTP found. Please login again."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if OTP has expired
        if timezone.now() > stored_otp_data['expiry']:
            # Clean up expired OTP
            del admin_otp_storage[admin_user.id]
            return Response({
                "error": "OTP has expired. Please login again."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check attempt limit
        if stored_otp_data['attempts'] >= 3:
            # Clean up after too many attempts
            del admin_otp_storage[admin_user.id]
            return Response({
                "error": "Too many failed attempts. Please login again."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify OTP
        if stored_otp_data['otp'] != otp_code:
            # Increment attempts
            admin_otp_storage[admin_user.id]['attempts'] += 1
            remaining_attempts = 3 - admin_otp_storage[admin_user.id]['attempts']
            return Response({
                "error": f"Invalid OTP. {remaining_attempts} attempts remaining."
            }, status=status.HTTP_400_BAD_REQUEST)

        # OTP is valid - clean up and grant access
        del admin_otp_storage[admin_user.id]

        # Generate or retrieve token for admin user
        token, created = Token.objects.get_or_create(user=admin_user)

        return Response({
            "message": "Admin OTP verified successfully.",
            "admin_access": True,
            "redirect_to": "/admin-dashboard",
            "token": token.key, # Return the token
            "admin_data": {
                "phone_number": ADMIN_PHONE,
                "email": ADMIN_EMAIL,
                "role": "admin",
                "access_level": "full"
            }
        }, status=status.HTTP_200_OK)


# --- Resend Admin OTP ---
class ResendAdminOTPView(APIView):
    def post(self, request):
        phone_number = request.data.get("phone_number")
        admin_user_id = request.data.get("admin_user_id") # Get admin user ID

        if phone_number != ADMIN_PHONE or not admin_user_id:
            return Response({
                "error": "Invalid admin credentials or missing user ID."
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            admin_user = User.objects.get(id=admin_user_id, phone_number=ADMIN_PHONE, is_staff=True)
        except User.DoesNotExist:
            return Response({
                "error": "Admin user not found or invalid."
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Check if there's an existing OTP that's not expired
        stored_otp_data = admin_otp_storage.get(admin_user.id)
        if stored_otp_data and timezone.now() < stored_otp_data['expiry']:
            # Check if enough time has passed (prevent spam)
            time_since_last = timezone.now() - (stored_otp_data['expiry'] - timezone.timedelta(minutes=10))
            if time_since_last < timezone.timedelta(minutes=1):
                return Response({
                    "error": "Please wait before requesting a new OTP."
                }, status=status.HTTP_400_BAD_REQUEST)

        # Generate new OTP
        otp_code = generate_otp()
        expiry_time = timezone.now() + timezone.timedelta(minutes=10)

        # Store new OTP
        admin_otp_storage[admin_user.id] = {
            'otp': otp_code,
            'expiry': expiry_time,
            'attempts': 0
        }

        # Send OTP email
        if send_admin_otp_email(otp_code):
            return Response({
                "message": "New OTP sent to admin email.",
                "admin_email": ADMIN_EMAIL,
                "admin_user_id": admin_user.id # Return user ID
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "error": "Failed to send OTP. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- Admin User Approval/Decline Endpoint ---
@api_view(['PATCH'])
@permission_classes([IsAuthenticated, IsAdminUser]) # Only authenticated admin users can access
def user_approval(request, pk):
    try:
        user = get_object_or_404(User, pk=pk)
    except User.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    # Ensure only corporate or student accounts can be approved/declined via this endpoint
    if user.user_type not in ['corporate', 'student']:
        return Response({"error": "Only corporate and student accounts require approval."}, status=status.HTTP_400_BAD_REQUEST)

    is_approved = request.data.get('is_approved')
    comment = request.data.get('comment', None)

    if is_approved is None:
        return Response({"error": "is_approved field is required."}, status=status.HTTP_400_BAD_REQUEST)

    user.is_approved = is_approved
    user.approval_comment = comment # Store the comment regardless of approval status

    # If approved, clear any previous decline comments
    if is_approved:
        user.approval_comment = None
    # If declined, ensure a comment is provided
    elif not is_approved and not comment:
        return Response({"error": "A comment is required when declining an account."}, status=status.HTTP_400_BAD_REQUEST)

    user.save(update_fields=['is_approved', 'approval_comment'])

    serializer = UserSerializer(user, context={'request': request})
    return Response(serializer.data, status=status.HTTP_200_OK)


# --- List Users ---
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser]) # Protect this endpoint
def get_users(request):
    users = User.objects.all()
    serializer = UserSerializer(users, many=True, context={'request': request})
    return Response(serializer.data)


# --- Retrieve/Update/Delete a User ---
@api_view(['PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsAdminUser]) # Protect this endpoint
def user_detail(request, pk):
    user = get_object_or_404(User, pk=pk)

    if request.method == 'PUT':
        serializer = UserSerializer(user, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    elif request.method == 'DELETE':
        user.delete()
        return Response({'message': 'User deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


# --- PATCH user fields ---
@api_view(['PATCH'])
@permission_classes([IsAuthenticated, IsAdminUser]) # Protect this endpoint
def update_user_wallet(request, pk):
    print(f"[DEBUG] PATCH wallet request received for user ID: {pk}")

    try:
        user = get_object_or_404(User, pk=pk)
        print(f"[DEBUG] Found user: {user.phone_number}")

        wallet = get_object_or_404(Wallet, user=user)
        print(f"[DEBUG] Found wallet for user ID {user.id}")

        # Optionally update fields on wallet if included in PATCH payload
        serializer = WalletSerializer(wallet, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            print("[DEBUG] Wallet updated successfully")
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            print(f"[ERROR] Serializer errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        print(f"[ERROR] Exception occurred: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- Wallet Top-up by Currency ---
@api_view(['PATCH'])
#@permission_classes([IsAuthenticated, IsAdminUser]) # Protect this endpoint
def top_up_wallet(request, user_id, currency_code):
    try:
        amount = Decimal(str(request.data.get('amount', '0')))
        if amount <= 0:
            return Response({'error': 'Amount must be greater than zero.'}, status=400)

        user = get_object_or_404(User, pk=user_id)

        # Check if user's email is verified before allowing wallet operations
        if not user.email_verified:
            return Response({
                'error': 'Email verification required before wallet operations.',
                'requires_verification': True
            }, status=status.HTTP_403_FORBIDDEN)

        currency = get_object_or_404(Currency, code=currency_code.upper())

        wallet, _ = Wallet.objects.get_or_create(user=user)
        wallet_balance, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency)

        wallet_balance.balance = Decimal(wallet_balance.balance) + amount
        wallet_balance.save()

        # Return updated user with balances
        serializer = UserSerializer(user, context={'request': request})
        return Response(serializer.data, status=200)

    except Exception as e:
        return Response({'error': str(e)}, status=500)


# --- Check Email Verification Status ---
@api_view(['GET'])
def check_verification_status(request, email):
    try:
        user = get_object_or_404(User, email=email)
        return Response({
            "email": user.email,
            "email_verified": user.email_verified,
            "can_request_new_code": user.can_request_new_code(),
            "verification_attempts": user.email_verification_attempts
        }, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_logged_in_user(request):
    user = request.user
    user_data = UserSerializer(user, context={'request': request}).data

    try:
        wallet = Wallet.objects.get(user=user)
        balances = WalletBalance.objects.filter(wallet=wallet)
        balance_data = [
            {
                'currency': bal.currency.code,
                'balance': str(bal.balance)
            } for bal in balances
        ]
    except Wallet.DoesNotExist:
        balance_data = []

    # Get loyalty points if loyalty model exists and is linked
    points = getattr(getattr(user, 'loyaltyaccount', None), 'points', 0)

    return Response({
        'user': user_data,
        'balances': balance_data,
        'loyalty_points': points
    }, status=200)
