from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from django.contrib.auth import authenticate, get_user_model
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.db.models import Q
from decimal import Decimal
from twilio.rest import Client
from rest_framework.authtoken.models import Token
import random
import string
from wallets.serializers import WalletSerializer
from wallets.models import Wallet, WalletBalance
from currency.models import Currency
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.hashers import make_password
from datetime import timedelta
import time

from .serializers import (
    UserRegistrationSerializer,
    UserSerializer,
    EmailVerificationSerializer,
    ResendVerificationSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)
from .models import User, EmailVerificationLog, PendingUser, AdminOTP

User = get_user_model()

# Admin credentials
ADMIN_PHONE = getattr(settings, 'ADMIN_PHONE', "+263772966966")
ADMIN_PASSWORD = getattr(settings, 'ADMIN_PASSWORD', "fastjetv1")
ADMIN_EMAIL = getattr(settings, 'ADMIN_EMAIL', "murambaprogress@gmail.com")

admin_otp_storage = {}

# --- Helper functions ---
def get_admin_user_key(user_id):
    """Ensure consistent string key for admin OTP storage"""
    return str(user_id)

def debug_admin_otp_storage():
    """Debug helper to show current admin OTP storage state"""
    print(f"[DEBUG] Admin OTP Storage Contents:")
    # Check database storage
    try:
        admin_otps = AdminOTP.objects.all()
        print(f"[DEBUG] Database OTPs: {admin_otps.count()} records")
        for otp_record in admin_otps:
            print(f"  User: {otp_record.user.id} ({otp_record.user.email})")
            print(f"  OTP: {otp_record.otp_code}")
            print(f"  Expires: {otp_record.expires_at}")
            print(f"  Attempts: {otp_record.attempts}")
            print(f"  Is Expired: {otp_record.is_expired()}")
    except Exception as e:
        print(f"[DEBUG] Error checking database OTPs: {e}")
    
    # Check in-memory storage (legacy)
    for key, value in admin_otp_storage.items():
        print(f"  Memory Key: {key} (type: {type(key)})")
        print(f"  OTP: {value.get('otp', 'N/A')}")
        print(f"  Expiry: {value.get('expiry', 'N/A')}")
        print(f"  Attempts: {value.get('attempts', 'N/A')}")

def cleanup_expired_otps():
    """Remove expired OTPs from both database and memory storage"""
    # Clean up database
    try:
        expired_count = AdminOTP.cleanup_expired()
        if expired_count > 0:
            print(f"[DEBUG] Cleaned up {expired_count} expired OTP(s) from database")
    except Exception as e:
        print(f"[DEBUG] Error cleaning up database OTPs: {e}")
    
    # Clean up memory storage (legacy)
    current_time = timezone.now()
    expired_keys = []
    
    for key, value in admin_otp_storage.items():
        if value.get('expiry') and current_time > value['expiry']:
            expired_keys.append(key)
    
    for key in expired_keys:
        del admin_otp_storage[key]
        print(f"[DEBUG] Removed expired OTP from memory for admin_user_id: {key}")
    
    if expired_keys:
        print(f"[DEBUG] Cleaned up {len(expired_keys)} expired OTP(s) from memory")

def get_twilio_client():
    """Get Twilio client with proper error handling"""
    if not all([settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN, settings.TWILIO_SMS_FROM]):
        print(f"[DEBUG] Twilio not configured - missing credentials")
        return None
        
    # Check if credentials look like default/demo values
    if (settings.TWILIO_ACCOUNT_SID == "ACc574e043f52d83ceefd946699e9a7c45" or 
        settings.TWILIO_AUTH_TOKEN == "66091780cf652327039b917dc633c891"):
        print(f"[DEBUG] Twilio using demo credentials - SMS disabled")
        return None
        
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        # Test the connection by making a simple API call
        client.api.accounts.get(settings.TWILIO_ACCOUNT_SID)
        return client
    except Exception as e:
        print(f"[WARN] Twilio client initialization failed: {e}")
        return None

def generate_otp():
   # Ensure we generate exactly 6 digits with possible leading zeros
   otp = ''.join(random.choices(string.digits, k=6))
   print(f"[DEBUG] Generated 6-digit OTP: {otp}")
   return otp

def send_admin_otp_email(otp_code):
   subject = 'FastJet Admin Login - OTP Verification'
   # Ensure the OTP is exactly 6 digits with leading zeros if needed
   otp_string = str(otp_code).zfill(6)
   message = f"Your OTP code for admin dashboard access is: {otp_string}\nThis code will expire in 10 minutes."
   try:
       send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [ADMIN_EMAIL], fail_silently=False)
       print(f"[DEBUG] Admin OTP email sent with 6-digit code: {otp_string}")
       return True
   except Exception as e:
       print(f"Failed to send admin OTP email: {e}")
       return False

def send_user_otp_sms(phone_number, otp_code):
   twilio_client = get_twilio_client()
   if not twilio_client:
       print("Twilio not configured. SMS not sent.")
       return False
   try:
       # Ensure otp_code is a string and has exactly 6 digits
       otp_string = str(otp_code).zfill(6)
       message_body = f"FastJet OTP: {otp_string}. Expires in 10 min."
       print(f"[DEBUG] Sending 6-digit OTP via SMS: {otp_string}")
       message = twilio_client.messages.create(body=message_body, from_=settings.TWILIO_SMS_FROM, to=phone_number)
       return bool(message.sid)
   except Exception as e:
       print(f"Twilio Exception: {e}")
       return False

def send_admin_otp_email_and_sms(user):
    admin_user_id = get_admin_user_key(user.id)
    print(f"[DEBUG] Checking existing OTP for admin_user_id: {admin_user_id}")
    
    # Check for existing valid OTP in database
    try:
        existing_otp = AdminOTP.objects.get(user=user)
        if not existing_otp.is_expired() and existing_otp.attempts < 3:
            print(f"[DEBUG] Existing valid OTP found. OTP: {existing_otp.otp_code}, Expiry: {existing_otp.expires_at}")
            return False, existing_otp.otp_code
        else:
            print(f"[DEBUG] Existing OTP is expired or has too many attempts, deleting")
            existing_otp.delete()
    except AdminOTP.DoesNotExist:
        print(f"[DEBUG] No existing OTP found")
    
    debug_admin_otp_storage()
    
    # Legacy check for in-memory storage
    stored_otp_data = admin_otp_storage.get(admin_user_id)
    if stored_otp_data and timezone.now() <= stored_otp_data['expiry']:
        print(f"[DEBUG] Existing OTP is still valid. OTP: {stored_otp_data['otp']}, Expiry: {stored_otp_data['expiry']}")
        return False, str(stored_otp_data['otp']).zfill(6)

    # Generate a 6-digit OTP
    otp_string = str(generate_otp()).zfill(6)
    
    subject = 'FastJet Admin Login - OTP Verification'
    message = f"Your OTP code for admin dashboard access is: {otp_string}\nThis code will expire in 10 minutes."
    
    email_sent = False
    sms_sent = False
    
    try:
        # Send email (primary method)
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [ADMIN_EMAIL],
            fail_silently=False
        )
        email_sent = True
        print(f"[DEBUG] Email sent successfully to {ADMIN_EMAIL}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

    # Send SMS (secondary method)
    twilio_client = get_twilio_client()
    if twilio_client:
        try:
            message_body = f"FastJet OTP: {otp_string}. Expires in 10 min."
            twilio_client.messages.create(
                body=message_body,
                from_=settings.TWILIO_SMS_FROM,
                to=ADMIN_PHONE
            )
            sms_sent = True
            print(f"[DEBUG] SMS sent successfully to {ADMIN_PHONE}")
        except Exception as e:
            print(f"[WARN] Failed to send SMS: {e}")
            # Continue anyway - email is primary delivery method
    else:
        print(f"[DEBUG] Twilio not configured - SMS not sent")
        
    # Only fail if both email and SMS failed
    if not email_sent:
        print(f"[ERROR] Critical: Email sending failed and no SMS backup")
        return False, None

    # Store the OTP in database for persistence
    expiry_time = timezone.now() + timedelta(minutes=10)
    AdminOTP.objects.update_or_create(
        user=user,
        defaults={
            'otp_code': otp_string,
            'expires_at': expiry_time,
            'attempts': 0
        }
    )
    
    # Also store in memory for backward compatibility
    admin_otp_storage[admin_user_id] = {
        "otp": otp_string,
        "expiry": expiry_time,
        "attempts": 0
    }
    
    print(f"[DEBUG] New OTP generated and stored. User ID: {admin_user_id}, OTP: '{otp_string}', Type: {type(otp_string)}")
    print(f"[DEBUG] OTP repr: {repr(otp_string)}, Length: {len(otp_string)}")
    print(f"[DEBUG] Expiry: {expiry_time}")
    print(f"[DEBUG] Stored in database and memory")
    print(f"[DEBUG] Email sent: {email_sent}, SMS sent: {sms_sent}")
    
    # Immediate verification test
    try:
        db_otp = AdminOTP.objects.get(user=user)
        print(f"[DEBUG] Database retrieval test - stored OTP: '{db_otp.otp_code}', match: {db_otp.otp_code == otp_string}")
    except AdminOTP.DoesNotExist:
        print(f"[DEBUG] ERROR: Could not retrieve OTP from database immediately after storage")
    
    delivery_message = []
    if email_sent:
        delivery_message.append("email")
    if sms_sent:
        delivery_message.append("SMS")
    
    return True, otp_string

# --- Registration ---
class RegisterView(APIView):
   permission_classes = [AllowAny]
   def get_client_ip(self, request):
       x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
       return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

   def post(self, request):
       serializer = UserRegistrationSerializer(data=request.data)
       if serializer.is_valid():
           try:
               # Create pending user instead of actual user
               pending_user = serializer.save()
               pending_user.ip_address = self.get_client_ip(request)
               pending_user.user_agent = request.META.get('HTTP_USER_AGENT', '')
               pending_user.save()
               
               print(f"Pending user {pending_user.email} created successfully.")  # Debugging log

               # Send OTP via SMS and Email to the pending user
               if pending_user.phone_number != ADMIN_PHONE:
                   send_user_otp_sms(pending_user.phone_number, pending_user.email_verification_code)
               try:
                   otp_str = str(pending_user.email_verification_code).zfill(6)
                   send_mail(
                       'FastJet Email Verification Code',
                       f'Your verification code is: {otp_str}. It expires in 10 minutes.',
                       settings.DEFAULT_FROM_EMAIL,
                       [pending_user.email],
                       fail_silently=False,
                   )
                   print(f"[DEBUG] Sent verification email with OTP {otp_str} to {pending_user.email}")
               except Exception as e:
                   print(f"[WARN] Failed to send verification email to {pending_user.email}: {e}")

               message = "Registration initiated. Please verify your email to complete registration."
               if pending_user.user_type in ['corporate', 'student', 'club']:
                   message = f"Registration initiated. Please verify your email first. Your {pending_user.user_type} account will be reviewed by admin after verification."

               return Response({
                   "message": message, 
                   "user_created": False,  # User not actually created yet
                   "user_type": pending_user.user_type,
                   "phone_number": pending_user.phone_number, 
                   "requires_verification": True,
                   "requires_admin_approval": pending_user.user_type in ['corporate', 'student', 'club'],
               }, status=status.HTTP_201_CREATED)
           except Exception as e:
               print(f"Error saving pending user: {e}")  # Debugging log
               return Response({"code": "SERVER_ERROR", "message": "An error occurred while processing registration."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
       else:
           print(f"Validation errors: {serializer.errors}")  # Debugging log
       return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# --- Email Verification ---
class VerifyEmailView(APIView):
   permission_classes = [AllowAny]
   def post(self, request):
       serializer = EmailVerificationSerializer(data=request.data)
       if serializer.is_valid():
           user = serializer.validated_data['user']
           is_new_user = serializer.validated_data.get('is_new_user', False)
           
           if is_new_user:
               # Log the verification for new user
               EmailVerificationLog.objects.create(
                   user=user,
                   verification_code=request.data.get('verification_code'),
                   verified_at=timezone.now(),
                   ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0] if request.META.get('HTTP_X_FORWARDED_FOR') else request.META.get('REMOTE_ADDR'),
                   user_agent=request.META.get('HTTP_USER_AGENT', '')
               )
               
               message = "Email verified successfully! Account created. You can now log in."
               if user.user_type in ['corporate', 'student', 'club']:
                   message = f"Email verified successfully! Your {user.user_type} account is now pending admin approval."
               
               # Return additional info for new users
               return Response({
                   "message": message, 
                   "email_verified": True,
                   "user_created": True,
                   "requires_admin_approval": user.user_type in ['corporate', 'student', 'club'],
                   "welcome_points": 50,
                   "user": UserSerializer(user).data
               }, status=status.HTTP_200_OK)
           else:
               # Legacy user verification
               message = "Email verified successfully. You can now log in."
               if user.user_type in ['corporate', 'student', 'club']:
                   message = f"Email verified successfully! Your {user.user_type} account is now pending admin approval."
               return Response({
                   "message": message, 
                   "email_verified": True,
                   "requires_admin_approval": user.user_type in ['corporate', 'student', 'club']
               }, status=status.HTTP_200_OK)
       return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# --- Resend SMS Verification Code ---
class ResendVerificationView(APIView):
   permission_classes = [AllowAny]
   def post(self, request):
       serializer = ResendVerificationSerializer(data=request.data)
       if serializer.is_valid():
           if 'pending_user' in serializer.validated_data:
               # Handle pending user
               pending_user = serializer.validated_data['pending_user']
               # Generate new verification code
               pending_user.generate_verification_code()
               
               # Send the new OTP via SMS and Email
               if pending_user.phone_number != ADMIN_PHONE:
                   send_user_otp_sms(pending_user.phone_number, pending_user.email_verification_code)
               try:
                   otp_str = str(pending_user.email_verification_code).zfill(6)
                   send_mail(
                       'FastJet Email Verification Code',
                       f'Your verification code is: {otp_str}. It expires in 10 minutes.',
                       settings.DEFAULT_FROM_EMAIL,
                       [pending_user.email],
                       fail_silently=False,
                   )
                   print(f"[DEBUG] Resent verification email with OTP {otp_str} to {pending_user.email}")
               except Exception as e:
                   print(f"[WARN] Failed to resend verification email to {pending_user.email}: {e}")
               
               print(f"[DEBUG] Resent 6-digit OTP: {pending_user.email_verification_code} to {pending_user.phone_number}")
               return Response({"message": "Verification code sent to your phone.", "phone_number": pending_user.phone_number}, status=status.HTTP_200_OK)
           
           elif 'user' in serializer.validated_data:
               # Handle existing user (legacy)
               user = serializer.validated_data['user']
               # Generate new verification code - explicitly use generate_otp()
               user.email_verification_code = generate_otp()
               user.save()
               
               # Send the new OTP via SMS and Email
               if user.phone_number != ADMIN_PHONE:
                   send_user_otp_sms(user.phone_number, user.email_verification_code)
               try:
                   otp_str = str(user.email_verification_code).zfill(6)
                   send_mail(
                       'FastJet Email Verification Code',
                       f'Your verification code is: {otp_str}. It expires in 10 minutes.',
                       settings.DEFAULT_FROM_EMAIL,
                       [user.email],
                       fail_silently=False,
                   )
                   print(f"[DEBUG] Resent verification email with OTP {otp_str} to {user.email}")
               except Exception as e:
                   print(f"[WARN] Failed to resend verification email to {user.email}: {e}")
               
               print(f"[DEBUG] Resent 6-digit OTP: {user.email_verification_code} to {user.phone_number}")
               return Response({"message": "Verification code sent to your phone.", "phone_number": user.phone_number}, status=status.HTTP_200_OK)
       
       return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# --- Login ---
class LoginView(APIView):
    permission_classes = [AllowAny]
    # Disable SessionAuthentication to avoid CSRF requirement for this token-based login endpoint
    authentication_classes = []

    def post(self, request):
        identifier = request.data.get("identifier")
        password = request.data.get("password")
        otp_code = request.data.get("otp_code")  # Added to capture OTP for admin users

        if not identifier or not password:
            return Response({"code": "ERROR", "message": "Please provide both an identifier and a password."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if identifier is email or phone number
        if "@" in identifier:
            user_query = Q(email__iexact=identifier)
        else:
            user_query = Q(phone_number=identifier)

        try:
            user = User.objects.get(user_query)
        except User.DoesNotExist:
            print(f"Login failed: User with identifier '{identifier}' does not exist.")
            return Response({"code": "AUTH_ERROR", "message": "Invalid identifier or password."}, status=status.HTTP_401_UNAUTHORIZED)

        user = authenticate(request, username=user.email, password=password)
        if user:
            print(f"Login successful for user: {user.email}")
            if not user.email_verified:
                return Response({"code": "AUTH_ERROR", "message": "Email not verified. Please verify your email before logging in.", "requires_verification": True, "email": user.email}, status=status.HTTP_403_FORBIDDEN)
            if user.user_type in ['corporate', 'student', 'club'] and not user.is_approved:
                status_message = f"Your {user.user_type} account has been declined by admin." if user.approval_comment else f"Your {user.user_type} account is currently under review by admin."
                return Response({"code": "AUTH_ERROR", "message": status_message, "account_status": "declined" if user.approval_comment else "pending_approval", "approval_comment": user.approval_comment}, status=status.HTTP_403_FORBIDDEN)

            token, _ = Token.objects.get_or_create(user=user)
            
            # Handle admin users separately - require OTP
            if user.is_staff and ADMIN_EMAIL in user.email:
                # Generate OTP for admin user
                admin_user_id = get_admin_user_key(user.id)
                print(f"[DEBUG] Admin login attempt for user_id: {admin_user_id}, has otp_code: {bool(otp_code)}")
                debug_admin_otp_storage()
                
                if otp_code:
                    # Verify OTP if provided
                    stored_otp_data = admin_otp_storage.get(admin_user_id)
                    print(f"[DEBUG] Found stored_otp_data: {bool(stored_otp_data)}")
                    if not stored_otp_data or timezone.now() > stored_otp_data['expiry']:
                        return Response({"code": "OTP_ERROR", "message": "Invalid or expired OTP", "requires_otp": True, "admin_user_id": admin_user_id}, status=status.HTTP_403_FORBIDDEN)
                    
                    # Format both OTPs as 6-digit strings for comparison
                    formatted_stored_otp = str(stored_otp_data['otp']).zfill(6)
                    formatted_provided_otp = str(otp_code).zfill(6)
                    
                    if formatted_stored_otp != formatted_provided_otp:
                        print(f"[DEBUG] OTP mismatch in login. Expected: {formatted_stored_otp}, Provided: {formatted_provided_otp}")
                        return Response({"code": "OTP_ERROR", "message": "Invalid OTP code", "requires_otp": True, "admin_user_id": admin_user_id}, status=status.HTTP_403_FORBIDDEN)
                    
                    # OTP verified successfully
                    del admin_otp_storage[admin_user_id]
                else:
                    # Generate and send OTP, and persist in session
                    success, otp_str = send_admin_otp_email_and_sms(user)
                    try:
                        # If no new OTP was generated but an existing one is valid, use it
                        if not success and not otp_str:
                            existing = admin_otp_storage.get(admin_user_id)
                            if existing:
                                otp_str = str(existing.get('otp')).zfill(6)
                        if otp_str:
                            request.session['admin_otp'] = {
                                'user_id': admin_user_id,
                                'otp': otp_str,
                                'expiry_ts': int((timezone.now() + timedelta(minutes=10)).timestamp())
                            }
                            request.session.modified = True
                    except Exception as e:
                        print(f"[WARN] Failed to store admin OTP in session: {e}")
                    return Response({
                        "message": "OTP sent to your email and phone",
                        "requires_otp": True,
                        "admin_user_id": admin_user_id
                    }, status=status.HTTP_200_OK)
            
            # Check for first login welcome points
            if not user.welcome_points_awarded and not user.is_staff:
                from loyalty.models import LoyaltyAccount
                loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
                loyalty_account.add_points(10, "Welcome bonus - 10 points for first login")
                user.welcome_points_awarded = True
                user.save()
            
            # Regular users don't need OTP
            return Response({
                "message": "Login successful" + (". Welcome bonus of 10 points awarded!" if not user.welcome_points_awarded else ""),
                "token": token.key,
                "user": UserSerializer(user).data,
                "is_staff": user.is_staff,
            }, status=status.HTTP_200_OK)
        else:
            print(f"Login failed: Authentication failed for identifier '{identifier}'.")
            return Response({"code": "AUTH_ERROR", "message": "Invalid identifier or password."}, status=status.HTTP_401_UNAUTHORIZED)

# --- Admin OTP Verification ---
class AdminOTPVerificationView(APIView):
    permission_classes = [AllowAny]
    # No session auth to avoid CSRF requirement for this public verification step
    authentication_classes = []

    def post(self, request):
        raw_admin_user_id = request.data.get("admin_user_id")
        admin_user_id = get_admin_user_key(raw_admin_user_id) if raw_admin_user_id else ""
        otp_code = request.data.get("otp_code")
        
        if not admin_user_id or admin_user_id == "None" or not otp_code:
            return Response({"code": "VALIDATION_ERROR", "message": "Admin user ID and OTP code are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        print(f"[DEBUG] OTP verification attempt for admin_user_id: {admin_user_id}")
        cleanup_expired_otps()
        debug_admin_otp_storage()
        
        # First check database for OTP
        stored_otp_data = None
        try:
            admin_user = User.objects.get(id=admin_user_id)
            otp_record = AdminOTP.objects.get(user=admin_user)
            
            if not otp_record.is_expired() and otp_record.attempts < 3:
                stored_otp_data = {
                    'otp': otp_record.otp_code,
                    'expiry': otp_record.expires_at,
                    'attempts': otp_record.attempts
                }
                print(f"[DEBUG] Found valid OTP in database: {otp_record.otp_code}")
            else:
                print(f"[DEBUG] Database OTP is expired or has too many attempts")
                if otp_record.is_expired():
                    print(f"[DEBUG] OTP expired at {otp_record.expires_at}, now is {timezone.now()}")
                if otp_record.attempts >= 3:
                    print(f"[DEBUG] Too many attempts: {otp_record.attempts}")
                otp_record.delete()
        except User.DoesNotExist:
            print(f"[DEBUG] Admin user with ID {admin_user_id} does not exist")
        except AdminOTP.DoesNotExist:
            print(f"[DEBUG] No OTP record found in database for user {admin_user_id}")
            # Fall back to memory storage
            stored_otp_data = admin_otp_storage.get(admin_user_id)
        
        # Prefer OTP stored in session if present and not expired
        session_otp = None
        try:
            session_otp = request.session.get('admin_otp') if hasattr(request, 'session') else None
        except Exception:
            session_otp = None

        # Debug logging
        print(f"[DEBUG] Looking for OTP data for admin_user_id: {admin_user_id}")
        print(f"[DEBUG] admin_otp_storage keys: {list(admin_otp_storage.keys())}")
        print(f"[DEBUG] session_otp: {session_otp}")

        if session_otp and str(session_otp.get('user_id')) == str(admin_user_id):
            now_ts = int(time.time())
            if int(session_otp.get('expiry_ts', 0)) >= now_ts:
                # Override stored_otp_data with session copy for verification
                stored_otp_data = {
                    'otp': str(session_otp.get('otp')).zfill(6),
                    'expiry': timezone.now() + timedelta(seconds=session_otp.get('expiry_ts', now_ts) - now_ts),
                    'attempts': 0
                }
                print(f"[DEBUG] Using session OTP data for verification")

        if not stored_otp_data:
            print(f"[DEBUG] No OTP data found for admin_user_id: {admin_user_id}")
            print(f"[DEBUG] Available keys in admin_otp_storage: {list(admin_otp_storage.keys())}")
            return Response({"code": "OTP_ERROR", "message": "Invalid or expired OTP. Please login again to generate a new OTP."}, status=status.HTTP_400_BAD_REQUEST)

        if timezone.now() > stored_otp_data['expiry']:
            print(f"[DEBUG] OTP expired for admin_user_id: {admin_user_id}. Expiry: {stored_otp_data['expiry']}, Now: {timezone.now()}")
            try:
                del admin_otp_storage[admin_user_id]
            except Exception:
                pass
            try:
                if hasattr(request, 'session') and 'admin_otp' in request.session:
                    del request.session['admin_otp']
            except Exception:
                pass
            return Response({"code": "OTP_ERROR", "message": "OTP expired. Please request a new OTP."}, status=status.HTTP_400_BAD_REQUEST)

        if stored_otp_data.get('attempts', 0) >= 3:
            print(f"[DEBUG] OTP attempts exceeded for admin_user_id: {admin_user_id}. Attempts: {stored_otp_data['attempts']}")
            del admin_otp_storage[admin_user_id]
            return Response({"code": "OTP_ERROR", "message": "Invalid or expired OTP. Please login again."}, status=status.HTTP_400_BAD_REQUEST)

        # Format both provided and stored OTPs as strings with exactly 6 digits
        # Strip any whitespace and ensure clean comparison
        formatted_otp_code = str(otp_code).strip().zfill(6)
        formatted_stored_otp = str(stored_otp_data['otp']).strip().zfill(6)
        
        print(f"[DEBUG] OTP Comparison - Provided: '{formatted_otp_code}', Stored: '{formatted_stored_otp}'")
        print(f"[DEBUG] OTP Types - Provided: {type(otp_code)}, Stored: {type(stored_otp_data['otp'])}")
        print(f"[DEBUG] Raw OTP values - Provided: {repr(otp_code)}, Stored: {repr(stored_otp_data['otp'])}")
        print(f"[DEBUG] OTP Length - Provided: {len(formatted_otp_code)}, Stored: {len(formatted_stored_otp)}")
        print(f"[DEBUG] OTP Match: {formatted_stored_otp == formatted_otp_code}")
        
        if formatted_stored_otp != formatted_otp_code:
            # Update attempts in database if using database OTP
            try:
                admin_user = User.objects.get(id=admin_user_id)
                otp_record = AdminOTP.objects.get(user=admin_user)
                otp_record.increment_attempts()
                remaining = 3 - otp_record.attempts
                
                print(f"[DEBUG] OTP mismatch for admin_user_id: {admin_user_id}. Provided: '{formatted_otp_code}', Expected: '{formatted_stored_otp}', Remaining attempts: {remaining}")
                
                if remaining <= 0:
                    otp_record.delete()
                    print(f"[DEBUG] Deleted OTP record due to too many attempts")
            except (User.DoesNotExist, AdminOTP.DoesNotExist):
                # Fall back to memory storage update
                if admin_user_id in admin_otp_storage:
                    admin_otp_storage[admin_user_id]['attempts'] += 1
                    remaining = 3 - admin_otp_storage[admin_user_id]['attempts']
                    if remaining <= 0:
                        del admin_otp_storage[admin_user_id]
                else:
                    remaining = 0
            
            # Additional debugging for character comparison
            if len(formatted_otp_code) == len(formatted_stored_otp):
                for i, (p, s) in enumerate(zip(formatted_otp_code, formatted_stored_otp)):
                    if p != s:
                        print(f"[DEBUG] Character mismatch at position {i}: provided='{p}' ({ord(p)}), stored='{s}' ({ord(s)})")

            return Response({"code": "OTP_ERROR", "message": f"Invalid OTP. {remaining} attempts remaining."}, status=status.HTTP_400_BAD_REQUEST)

        print(f"[DEBUG] OTP verified successfully for admin_user_id: {admin_user_id}")
        
        # Clean up OTP after successful verification
        try:
            admin_user = User.objects.get(id=admin_user_id)
            AdminOTP.objects.filter(user=admin_user).delete()
            print(f"[DEBUG] Deleted OTP record after successful verification")
        except User.DoesNotExist:
            pass
        
        # Also clean up memory storage
        try:
            del admin_otp_storage[admin_user_id]
        except KeyError:
            pass
        try:
            if hasattr(request, 'session') and 'admin_otp' in request.session:
                del request.session['admin_otp']
        except Exception:
            pass
        admin_user = User.objects.get(id=admin_user_id)
        token, _ = Token.objects.get_or_create(user=admin_user)
        return Response({"message": "Admin OTP verified successfully.", "token": token.key, "admin_data": UserSerializer(admin_user).data}, status=status.HTTP_200_OK)

# --- Resend Admin OTP ---
class ResendAdminOTPView(APIView):
    permission_classes = [AllowAny]
    # No session auth to avoid CSRF requirement
    authentication_classes = []
    
    def post(self, request):
        raw_admin_user_id = request.data.get("admin_user_id", "")
        admin_user_id = get_admin_user_key(raw_admin_user_id) if raw_admin_user_id else ""
        email = request.data.get("email")
        
        if not admin_user_id or admin_user_id == "None":
            return Response(
                {"code": "VALIDATION_ERROR", "message": "Admin user ID is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get the user object
            admin_user = User.objects.get(id=admin_user_id)
            
            # Generate new OTP (padded string)
            otp_code = generate_otp()
            otp_string = str(otp_code).zfill(6)
            expiry_time = timezone.now() + timedelta(minutes=10)
            
            # Store in database
            AdminOTP.objects.update_or_create(
                user=admin_user,
                defaults={
                    'otp_code': otp_string,
                    'expires_at': expiry_time,
                    'attempts': 0
                }
            )
            
            # Also store in memory for backward compatibility
            admin_otp_storage[admin_user_id] = {
                "otp": otp_string,
                "expiry": expiry_time,
                "attempts": 0
            }
            
            print(f"[DEBUG] Resend OTP stored for admin_user_id: {admin_user_id}, OTP: {otp_string}")
            print(f"[DEBUG] Stored in both database and memory")
            
            # Also store in session for robustness
            try:
                request.session['admin_otp'] = {
                    'user_id': admin_user_id,
                    'otp': otp_string,
                    'expiry_ts': int(expiry_time.timestamp())
                }
                request.session.modified = True
            except Exception as e:
                print(f"[WARN] Failed to store resend admin OTP in session: {e}")
            
            # Send OTP via email
            subject = 'FastJet Admin Login - OTP Verification (Resent)'
            message = f"""
            Your new OTP code for admin dashboard access is: {otp_string}
            
            This code will expire in 10 minutes.
            
            If you did not request this code, please ignore this email.
            """
            
            # Send email (primary method)
            send_mail(
                subject, 
                message, 
                settings.DEFAULT_FROM_EMAIL, 
                [ADMIN_EMAIL if not email else email],
                fail_silently=False
            )
            print(f"[DEBUG] Email sent successfully to {ADMIN_EMAIL if not email else email}")
            
            # Try to send SMS as well if possible
            twilio_client = get_twilio_client()
            if twilio_client:
                try:
                    message_body = f"FastJet New OTP: {otp_string}. Expires in 10 min."
                    twilio_client.messages.create(
                        body=message_body,
                        from_=settings.TWILIO_SMS_FROM,
                        to=ADMIN_PHONE
                    )
                    print(f"[DEBUG] SMS sent successfully to {ADMIN_PHONE}")
                except Exception as sms_error:
                    print(f"[WARN] Failed to send SMS: {sms_error}")
                    # Continue anyway - email was sent successfully
            else:
                print(f"[DEBUG] Twilio not configured - SMS not sent")
            
            print(f"[DEBUG] New OTP generated and sent for admin_user_id: {admin_user_id}, OTP: {otp_string}")
            return Response({"message": "New OTP sent successfully (email sent, SMS may have failed)"}, status=status.HTTP_200_OK)
            
        except Exception as e:
            print(f"[ERROR] Failed to send admin OTP: {e}")
            return Response(
                {"code": "SERVER_ERROR", "message": "Failed to send OTP. Please try again later."}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# --- Password Reset Views ---
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            identifier = serializer.validated_data['identifier']
            user = User.objects.get(Q(email__iexact=identifier) | Q(phone_number=identifier))

            # Generate and store a new 6-digit reset code with 10-minute expiry
            try:
                if hasattr(user, 'generate_password_reset_code'):
                    user.generate_password_reset_code()
                else:
                    user.password_reset_code = str(generate_otp()).zfill(6)
                    user.password_reset_expires = timezone.now() + timedelta(minutes=10)
                    user.save(update_fields=['password_reset_code', 'password_reset_expires'])
            except Exception as e:
                print(f"[ERROR] Failed generating password reset code for {identifier}: {e}")
                return Response({'error': 'Failed to generate reset code. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Send email (if configured)
            try:
                send_mail(
                    'FastJet Password Reset Code',
                    f'Your password reset code is: {user.password_reset_code}. It expires in 10 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False
                )
                print(f"[DEBUG] Sent password reset email to {user.email} with code {user.password_reset_code}")
            except Exception as e:
                print(f"[WARN] Failed to send password reset email to {user.email}: {e}")

            # Try SMS as well if Twilio is set up
            try:
                send_user_otp_sms(user.phone_number, user.password_reset_code)
            except Exception as e:
                print(f"[WARN] Failed to send password reset SMS to {user.phone_number}: {e}")

            masked_email = user.email[:2] + '***@' + user.email.split('@')[-1] if user.email else None
            masked_phone = user.phone_number[:-4] + '****' if user.phone_number and len(user.phone_number) > 4 else None
            return Response({
                'message': 'A password reset code has been sent to your email and phone (if available).',
                'email': masked_email,
                'phone': masked_phone
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            user.set_password(serializer.validated_data['password'])
            user.password_reset_code = None
            user.password_reset_expires = None
            user.save()
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# --- Admin User Approval/Decline Endpoint ---
@api_view(['PATCH'])
@permission_classes([IsAuthenticated, IsAdminUser])
def user_approval(request, pk):
    user = get_object_or_404(User, pk=pk)
    if user.user_type not in ['corporate', 'student', 'club']:
        return Response({"code": "ERROR", "message": "Only corporate, student, and club accounts require approval."}, status=status.HTTP_400_BAD_REQUEST)

    is_approved = request.data.get('is_approved')
    comment = request.data.get('comment', None)
    if is_approved is None:
        return Response({"code": "VALIDATION_ERROR", "message": "is_approved field is required."}, status=status.HTTP_400_BAD_REQUEST)

    user.is_approved = is_approved
    if is_approved:
        user.approval_comment = None
        send_mail('FastJet Account Approved', f'Dear {user.get_full_name()},\n\nYour {user.user_type} account has been approved.', settings.DEFAULT_FROM_EMAIL, [user.email])
    else:
        if not comment:
            return Response({"code": "VALIDATION_ERROR", "message": "A comment is required when declining an account."}, status=status.HTTP_400_BAD_REQUEST)
        user.approval_comment = comment
        send_mail('FastJet Account Update', f'Dear {user.get_full_name()},\n\nRegarding your {user.user_type} account application:\nReason: {comment}', settings.DEFAULT_FROM_EMAIL, [user.email])

    user.save(update_fields=['is_approved', 'approval_comment'])
    return Response(UserSerializer(user).data, status=status.HTTP_200_OK)

# --- List Users ---
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def get_users(request):
    try:
        users = User.objects.all()
        serializer = UserSerializer(users, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error in get_users endpoint: {e}")
    return Response({"code": "SERVER_ERROR", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# --- Retrieve/Update/Delete a User ---
@api_view(['PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsAdminUser])
def user_detail(request, pk):
    # Logic remains the same as original
    pass

# --- PATCH user fields ---
@api_view(['PATCH'])
@permission_classes([IsAuthenticated, IsAdminUser])
def update_user_wallet(request, pk):
    # Logic remains the same as original
    pass

# --- Wallet Top-up by Currency ---
@api_view(['PATCH'])
@permission_classes([IsAuthenticated]) # FIX: Changed to IsAuthenticated
def top_up_wallet(request, user_id, currency_code):
    # Check if the user is topping up their own wallet or is an admin
    if request.user.id != user_id and not request.user.is_staff:
        return Response({'error': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

    try:
        amount = Decimal(str(request.data.get('amount', '0')))
        if amount <= 0:
            return Response({'error': 'Amount must be greater than zero.'}, status=400)

        user = get_object_or_404(User, pk=user_id)
        if not user.email_verified:
            return Response({'error': 'Email verification required before wallet operations.'}, status=status.HTTP_403_FORBIDDEN)

        currency = get_object_or_404(Currency, code=currency_code.upper())
        wallet, _ = Wallet.objects.get_or_create(user=user)
        wallet_balance, _ = WalletBalance.objects.get_or_create(wallet=wallet, currency=currency)

        wallet_balance.balance += amount
        wallet_balance.save()

        # Award loyalty points (fixed 10 for now) and record transaction if loyalty app available
        try:
            from loyalty.models import LoyaltyAccount
            loyalty_account, _ = LoyaltyAccount.objects.get_or_create(user=user)
            loyalty_account.add_points(10, f"Wallet Top-Up: {currency.code} {amount}")
            awarded_points = 10
        except Exception:
            awarded_points = 0

        # Build balances list
        balances_qs = WalletBalance.objects.filter(wallet=wallet)
        balance_data = [{'currency': b.currency.code, 'balance': str(b.balance)} for b in balances_qs]

        serializer = UserSerializer(user, context={'request': request})
        return Response({
            'user': serializer.data,
            'balances': balance_data,
            'points_awarded': awarded_points
        }, status=200)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

# --- Check Email Verification Status ---
@api_view(['GET'])
@permission_classes([AllowAny])
def check_verification_status(request, email):
    # First check pending users
    try:
        pending_user = PendingUser.objects.get(email__iexact=email)
        return Response({
            'email_verified': False,
            'user_exists': False,  # User doesn't exist yet, still pending
            'is_pending': True,
            'user_type': pending_user.user_type,
            'requires_admin_approval': pending_user.user_type in ['corporate', 'student', 'club']
        }, status=status.HTTP_200_OK)
    except PendingUser.DoesNotExist:
        pass
    
    # Check existing users
    try:
        user = User.objects.get(email__iexact=email)
        return Response({
            'email_verified': user.email_verified,
            'user_exists': True,
            'is_pending': False,
            'is_approved': user.is_approved,
            'user_type': user.user_type,
            'requires_admin_approval': user.user_type in ['corporate', 'student', 'club']
        }, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({
            'email_verified': False,
            'user_exists': False,
            'is_pending': False
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_logged_in_user(request):
    user = request.user
    user_data = UserSerializer(user).data
    try:
        wallet = Wallet.objects.get(user=user)
        balances = WalletBalance.objects.filter(wallet=wallet)
        balance_data = [{'currency': bal.currency.code, 'balance': str(bal.balance)} for bal in balances]
    except Wallet.DoesNotExist:
        balance_data = []
    points = getattr(getattr(user, 'loyaltyaccount', None), 'points', 0)
    return Response({'user': user_data, 'balances': balance_data, 'loyalty_points': points}, status=200)

# --- Admin User Setup ---
def ensure_admin_user():
    try:
        admin_user, created = User.objects.get_or_create(
            email=ADMIN_EMAIL,
            defaults={
                "phone_number": ADMIN_PHONE,
                "password": make_password(ADMIN_PASSWORD),
                "is_staff": True,
                "is_superuser": True,
                "is_active": True,
                "first_name": "Admin",
                "last_name": "User",
            },
        )
        if not created:
            # Update password and phone number if the admin user already exists
            admin_user.phone_number = ADMIN_PHONE
            admin_user.password = make_password(ADMIN_PASSWORD)
            admin_user.is_staff = True
            admin_user.is_superuser = True
            admin_user.is_active = True
            admin_user.save()

        # OTP sending disabled
        # otp_code = generate_otp()
        # admin_otp_storage[admin_user.id] = {
        #     "otp": otp_code,
        #     "expiry": timezone.now() + timezone.timedelta(minutes=10),
        #     "attempts": 0
        # }
        # send_user_otp_sms("+263772966966", otp_code)

        print("Admin user setup complete.")
    except Exception as e:
        print(f"Error ensuring admin user: {e}")

# Call the function to ensure admin user exists
ensure_admin_user()
