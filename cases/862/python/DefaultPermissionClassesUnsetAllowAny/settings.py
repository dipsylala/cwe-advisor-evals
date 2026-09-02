# Excerpt from the project settings module. There is no DEFAULT_PERMISSION_CLASSES
# key anywhere in this file, so DRF falls back to its built-in default of
# rest_framework.permissions.AllowAny for every view that does not set
# permission_classes itself - including ApiKeyViewSet.

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "apikeys",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
}
