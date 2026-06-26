"""
Django settings for queinvestigator_project.

The QueueStorm Investigator service is stateless and entirely rule-based.
We keep only the Django apps required to bootstrap the URL conf and the
ORM is configured to use an in-memory SQLite database so `manage.py`
commands work without writing to disk.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


# --- Security ----------------------------------------------------------------
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-secret-change-me")
DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"
if os.environ.get("DJANGO_ALLOW_ALL_HOSTS", "0") == "1":
    ALLOWED_HOSTS = ["*"]
else:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]


# --- Apps / middleware -------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "queinvestigator_app",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "queinvestigator_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": []},
    },
]

WSGI_APPLICATION = "queinvestigator_project.wsgi.application"


# --- Database ----------------------------------------------------------------
# The investigator does not persist anything. An in-memory SQLite engine
# satisfies Django's bootstrapping without writing to disk during requests.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}


# --- i18n --------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# --- Static ------------------------------------------------------------------
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
