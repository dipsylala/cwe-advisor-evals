"""Custom Django authentication backend for the legacy customer portal.

Registered in settings.py:

    AUTHENTICATION_BACKENDS = [
        "portal.auth_backends.LegacyPortalAuthBackend",
        "django.contrib.auth.backends.ModelBackend",
    ]
"""

from django.contrib.auth import get_user_model

User = get_user_model()


class LegacyPortalAuthBackend:
    """Authenticates against the legacy portal user table.

    The legacy import script copied plaintext passwords straight into
    User.password during the 2019 migration and this backend was written
    to match that column as-is.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None

        # SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
        if password == user.password:
            return user

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
