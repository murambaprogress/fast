from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.db.models import Q

User = get_user_model()

class EmailOrPhoneBackend(ModelBackend):
    """
    Custom authentication backend.
    Allows users to log in using their email address or phone number.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        # The `username` argument can be an email or a phone number.
        if username is None:
            username = kwargs.get('email') or kwargs.get('phone_number')
        if not username or not password:
            return None

        try:
            user = User.objects.get(Q(email__iexact=username) | Q(phone_number=username))
        except User.DoesNotExist:
            # Mitigate timing attacks by hashing a dummy password
            User().set_password(password)
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

class PhoneNumberBackend(ModelBackend):
    """
    Custom authentication backend to authenticate via phone number only.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Accept phone_number either via username or kwargs
        phone_number = kwargs.get('phone_number') or username
        if not phone_number or not password:
            return None

        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            # Mitigate timing attacks by hashing a dummy password
            User().set_password(password)
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
