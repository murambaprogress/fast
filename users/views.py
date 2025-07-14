from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view
from django.contrib.auth import authenticate, get_user_model
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from decimal import Decimal
import random
import string
from wallets.serializers import WalletSerializer
from .serializers import (
    UserRegistrationSerializer, 
    UserSerializer, 
    EmailVerificationSerializer, 
    ResendVerificationSerializer
)
from .models import User, EmailVerificationLog
from wallets.models import Wallet, WalletBalance
from currency.models import Currency

User = get_user_model()

# Admin credentials
ADMIN_PHONE = "9999999999"
ADMIN_PASSWORD = "fastjetv1"
ADMIN_EMAIL = "murambaprogress@gmail.com"

# Store admin OTP temporarily (in production, use Redis or database)
admin_otp_storage = {}

# --- Registration ---
class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Create wallet for the user
            Wallet.objects.create(user=user)
            
            # Log the verification attempt
            EmailVerificationLog.objects.create(
                user=user,
                verification_code=user.email_verification_code,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response({
                "message": "User registered successfully. Please check your email for verification code.",
                "user_created": True,
                "user_type": request.data.get('registration_type', 'individual'),
                "email": user.email,
                "requires_verification": True
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


# --- Email Verification ---
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


# --- Resend Verification Code ---
class ResendVerificationView(APIView):
    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Log the new verification attempt
            EmailVerificationLog.objects.create(
                user=user,
                verification_code=user.email_verification_code,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response({
                "message": "New verification code sent to your email.",
                "email": user.email
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


# --- Generate Admin OTP ---
def generate_admin_otp():
    """Generate a 6-digit OTP for admin login"""
    return ''.join(random.choices(string.digits, k=6))


# --- Send Admin OTP Email ---
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


# --- Login ---
class LoginView(APIView):
    def post(self, request):
        phone_number = request.data.get("phone_number")
        password = request.data.get("password")

        # Check for admin credentials
        if phone_number == ADMIN_PHONE and password == ADMIN_PASSWORD:
            # Generate and send OTP for admin
            otp_code = generate_admin_otp()
            expiry_time = timezone.now() + timezone.timedelta(minutes=10)
            
            # Store OTP temporarily
            admin_otp_storage[ADMIN_PHONE] = {
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
                    "phone_number": phone_number
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Failed to send OTP. Please try again."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Regular user authentication
        user = authenticate(request, phone_number=phone_number, password=password)
        if user:
            # Check if email is verified
            if not user.email_verified:
                return Response({
                    "error": "Email not verified. Please verify your email before logging in.",
                    "requires_verification": True,
                    "email": user.email
                }, status=status.HTTP_403_FORBIDDEN)
            
            return Response({
                "message": "Login successful",
                "user": {
                    "id": user.id,
                    "phone_number": user.phone_number,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                    "is_staff": user.is_staff,
                    "user_type": user.user_type,
                    "email_verified": user.email_verified,
                    "company_name": user.company_name if user.is_corporate() else None,
                }
            }, status=status.HTTP_200_OK)
        return Response({"error": "Invalid phone number or password"}, status=status.HTTP_401_UNAUTHORIZED)


# --- Admin OTP Verification ---
class AdminOTPVerificationView(APIView):
    def post(self, request):
        phone_number = request.data.get("phone_number")
        otp_code = request.data.get("otp_code")
        
        if not phone_number or not otp_code:
            return Response({
                "error": "Phone number and OTP code are required."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if this is admin phone number
        if phone_number != ADMIN_PHONE:
            return Response({
                "error": "Invalid admin credentials."
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check if OTP exists and is valid
        stored_otp_data = admin_otp_storage.get(ADMIN_PHONE)
        if not stored_otp_data:
            return Response({
                "error": "No OTP found. Please login again."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if OTP has expired
        if timezone.now() > stored_otp_data['expiry']:
            # Clean up expired OTP
            del admin_otp_storage[ADMIN_PHONE]
            return Response({
                "error": "OTP has expired. Please login again."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check attempt limit
        if stored_otp_data['attempts'] >= 3:
            # Clean up after too many attempts
            del admin_otp_storage[ADMIN_PHONE]
            return Response({
                "error": "Too many failed attempts. Please login again."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify OTP
        if stored_otp_data['otp'] != otp_code:
            # Increment attempts
            admin_otp_storage[ADMIN_PHONE]['attempts'] += 1
            remaining_attempts = 3 - admin_otp_storage[ADMIN_PHONE]['attempts']
            return Response({
                "error": f"Invalid OTP. {remaining_attempts} attempts remaining."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # OTP is valid - clean up and grant access
        del admin_otp_storage[ADMIN_PHONE]
        
        return Response({
            "message": "Admin OTP verified successfully.",
            "admin_access": True,
            "redirect_to": "/admin-dashboard",
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
        
        if phone_number != ADMIN_PHONE:
            return Response({
                "error": "Invalid admin credentials."
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check if there's an existing OTP that's not expired
        stored_otp_data = admin_otp_storage.get(ADMIN_PHONE)
        if stored_otp_data and timezone.now() < stored_otp_data['expiry']:
            # Check if enough time has passed (prevent spam)
            time_since_last = timezone.now() - (stored_otp_data['expiry'] - timezone.timedelta(minutes=10))
            if time_since_last < timezone.timedelta(minutes=1):
                return Response({
                    "error": "Please wait before requesting a new OTP."
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate new OTP
        otp_code = generate_admin_otp()
        expiry_time = timezone.now() + timezone.timedelta(minutes=10)
        
        # Store new OTP
        admin_otp_storage[ADMIN_PHONE] = {
            'otp': otp_code,
            'expiry': expiry_time,
            'attempts': 0
        }
        
        # Send OTP email
        if send_admin_otp_email(otp_code):
            return Response({
                "message": "New OTP sent to admin email.",
                "admin_email": ADMIN_EMAIL
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "error": "Failed to send OTP. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- List Users ---
@api_view(['GET'])
def get_users(request):
    users = User.objects.all()
    serializer = UserSerializer(users, many=True, context={'request': request})
    return Response(serializer.data)


# --- Retrieve/Update/Delete a User ---
@api_view(['PUT', 'DELETE'])
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
    

from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes

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
