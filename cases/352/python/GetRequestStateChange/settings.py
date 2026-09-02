"""Project settings excerpt showing CSRF middleware is correctly enabled."""

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# CsrfViewMiddleware only rejects unsafe methods (POST/PUT/PATCH/DELETE)
# that are missing or carry an invalid CSRF token. GET requests are
# treated as safe and pass through untouched, so a state-changing view
# reachable via GET (see account/urls.py: delete_account) is never
# checked for a token no matter how this middleware list is configured.

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SAMESITE = "Strict"
