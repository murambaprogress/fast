from pathlib import Path
import os
from twilio.rest import Client

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-7@7s40ts7&b4zoyp8p$(7&2u675!#fgpwhia=+qs-pj^$9n&zw'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'True') == 'True'

ALLOWED_HOSTS = [h for h in os.getenv('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',') if h]

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'users',
    'destinations',
    "routes",
    'currency',
    'wallets',
    'booking',
    'loyalty',
    'creditbooking',
    'corsheaders',
    'rest_framework',
    'rest_framework.authtoken',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CORS_ALLOW_ALL_ORIGINS = True  # or better: CORS_ALLOWED_ORIGINS = ['http://localhost:5173']

ROOT_URLCONF = 'fastjet_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'fastjet_backend.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'fastjet_loyalty_system',
        'USER': 'root',
        'PASSWORD': '',  # Default for XAMPP
        'HOST': '127.0.0.1',
        'PORT': '3306',
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

AUTH_USER_MODEL = 'users.User'

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/
STATIC_URL = '/static/'

# Directory where collected static files will be placed (python manage.py collectstatic)
STATIC_ROOT = os.path.join(BASE_DIR, 'collected_static')

# Frontend (Vite) build output path (we'll set Vite to emit here) and serve via Django
FRONTEND_DIST = os.path.join(BASE_DIR.parent.parent, 'fastjet-sky-rewards-hub', 'dist')

# Add the built assets directory to STATICFILES_DIRS so Django can find hashed bundles
STATICFILES_DIRS = [
    # Include the dist assets if it exists (guards allow backend to run before first build)
    *( [FRONTEND_DIST] if os.path.isdir(FRONTEND_DIST) else [] ),
]

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTHENTICATION_BACKENDS = ['users.backends.PhoneNumberBackend']

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'murambaprogress@gmail.com'
EMAIL_HOST_PASSWORD = 'ghnd xylw gfcg sdwd'  # You'll need to generate an app password in your Google account
DEFAULT_FROM_EMAIL = 'FastJet Loyalty <murambaprogress@gmail.com>'

TWILIO_ACCOUNT_SID = "ACc574e043f52d83ceefd946699e9a7c45"
TWILIO_AUTH_TOKEN = "a053f5389d9cac8429183bb3047e83a2"
TWILIO_SMS_FROM = "+12709185346"

# Frontend URL for verification links
FRONTEND_URL = 'http://localhost:8080/'  # Replace with your actual frontend URL

# Admin credentials
ADMIN_PHONE = "+2639999999999" # Use your actual admin phone number
ADMIN_PASSWORD = "fastjetv1" # Use a strong password in production
ADMIN_EMAIL = "murambaprogress@gmail.com" # Use your actual admin email

# Django REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

# Add this line to your settings.py
AUTHENTICATION_BACKENDS = [
    'users.backends.EmailOrPhoneBackend',
    'django.contrib.auth.backends.ModelBackend', # Keep the default backend
]
