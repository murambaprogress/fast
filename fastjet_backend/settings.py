from pathlib import Path
import os
from dotenv import load_dotenv

# --------------------------------
# Paths
# --------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
load_dotenv(BASE_DIR / '.env')

# --------------------------------
# Security / Debug
# --------------------------------
SECRET_KEY = 'django-insecure-7@7s40ts7&b4zoyp8p$(7&2u675!#fgpwhia=+qs-pj^$9n&zw'
DEBUG = os.getenv('DEBUG', 'True') == 'True'

ALLOWED_HOSTS = [h for h in os.getenv('ALLOWED_HOSTS', '127.0.0.1,localhost,fastjet.pythonanywhere.com').split(',') if h]
CSRF_TRUSTED_ORIGINS = [
    'https://fastjet.pythonanywhere.com',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
]

# Optional HTTPS hardening (safe defaults for PA)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = os.getenv('SECURE_SSL_REDIRECT', 'False') == 'True'
SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
CSRF_COOKIE_SECURE = os.getenv('CSRF_COOKIE_SECURE', 'False') == 'True'

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
        # Add frontend dist so index.html is served by TemplateView / fallback
        'DIRS': [],  # will append dynamically after FRONTEND_DIST definition
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

# --------------------------------
# Database (PythonAnywhere Cloud MySQL)
# --------------------------------
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'fastjet$fastjet',
        'USER': 'fastjet',
        'PASSWORD': 'jetjetv1',
        'HOST': 'fastjet.mysql.pythonanywhere-services.com',
        'PORT': '3306',
        'OPTIONS': {
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        },
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

# --------------------------------
# Static & Media (PythonAnywhere)
# --------------------------------
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'  # map in PA: URL=/static/ → /home/fastjet/fastjet_backend/staticfiles

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'         # map in PA: URL=/media/  → /home/fastjet/fastjet_backend/media

# Source static directories with priority: project static/ first, then frontend_build/
PROJECT_STATIC = BASE_DIR / 'static'
# FRONTEND_DIST points to the built frontend within the backend directory
# This makes deployment to PythonAnywhere simpler - just push the backend folder
FRONTEND_DIST = BASE_DIR / 'frontend_build'

STATICFILES_DIRS = [
    p for p in [
        PROJECT_STATIC,
        FRONTEND_DIST if FRONTEND_DIST.exists() else None,
    ] if p and p.exists()
]

# If you want Django templates to also find SPA index.html from dist, keep this:
if FRONTEND_DIST.exists():
    TEMPLATES[0]['DIRS'].append(str(FRONTEND_DIST))

# Ensure media and static directories exist
os.makedirs(MEDIA_ROOT, exist_ok=True)
os.makedirs(STATIC_ROOT, exist_ok=True)

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'murambaprogress@gmail.com'
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', 'khzy taxx znkb jneb')  # You'll need to generate an app password in your Google account
DEFAULT_FROM_EMAIL = 'FastJet Loyalty <murambaprogress@gmail.com>'

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "ACc574e043f52d83ceefd946699e9a7c45")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "66091780cf652327039b917dc633c891")
TWILIO_SMS_FROM = os.getenv("TWILIO_SMS_FROM", "+12709185346")

# Frontend URL for verification links
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:8080/')

# Admin credentials
ADMIN_PHONE = os.getenv('ADMIN_PHONE', '+2639999999999')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'fastjetv1')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'murambaprogress@gmail.com')

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
    'django.contrib.auth.backends.ModelBackend',  # Keep the default backend
]

# Append FRONTEND_DIST to template dirs late (after its definition) if present
if FRONTEND_DIST.exists():
    TEMPLATES[0]['DIRS'].append(str(FRONTEND_DIST))

# --------------------------------
# InnBucks Wallet Integration Settings
# --------------------------------
INNBUCKS_BASE_URL = os.getenv('INNBUCKS_BASE_URL', 'https://staging.innbucks.co.zw')
INNBUCKS_API_KEY = os.getenv('INNBUCKS_API_KEY', 'a92f156a-7d31-40b8-8b27-a43ec8cd7fff')
INNBUCKS_USERNAME = os.getenv('INNBUCKS_USERNAME', 'FastjetTestClientydvll8TO')
INNBUCKS_PASSWORD = os.getenv('INNBUCKS_PASSWORD', 'Jf5UGIGNTKTuBjUwtI1f')
INNBUCKS_ACCOUNT = os.getenv('INNBUCKS_ACCOUNT', '2008877953850')
INNBUCKS_ENVIRONMENT = os.getenv('INNBUCKS_ENVIRONMENT', 'staging')

# --------------------------------
# Application Base URL for generating notification URLs
# --------------------------------
BASE_URL = os.getenv('BASE_URL', 'https://fastjet.pythonanywhere.com')

# --------------------------------
# EcoCash Wallet Integration Settings
# --------------------------------
# API credentials - Stored in .env file for security
ECOCASH_API_USERNAME = os.getenv('ECOCASH_API_USERNAME')
ECOCASH_API_PASSWORD = os.getenv('ECOCASH_API_PASSWORD')

# Merchant details - Stored in .env file for security
ECOCASH_MERCHANT_CODE = os.getenv('ECOCASH_MERCHANT_CODE')
ECOCASH_MERCHANT_PIN = os.getenv('ECOCASH_MERCHANT_PIN')
ECOCASH_MERCHANT_NUMBER = os.getenv('ECOCASH_MERCHANT_NUMBER')
ECOCASH_MERCHANT_NAME = os.getenv('ECOCASH_MERCHANT_NAME')
ECOCASH_SUPER_MERCHANT_NAME = os.getenv('ECOCASH_SUPER_MERCHANT_NAME')
ECOCASH_TERMINAL_ID = os.getenv('ECOCASH_TERMINAL_ID')
ECOCASH_LOCATION = os.getenv('ECOCASH_LOCATION')

# Webhook/notification URL
ECOCASH_NOTIFY_URL = os.getenv('ECOCASH_NOTIFY_URL')

# Loyalty settings
ECOCASH_POINTS_AWARD_RATE = float(os.getenv('ECOCASH_POINTS_AWARD_RATE', '0.02'))  # 2% of transaction amount

# Test MSISDN for EcoCash sandbox/testing
ECOCASH_TEST_MSISDN = os.getenv('ECOCASH_TEST_MSISDN')
