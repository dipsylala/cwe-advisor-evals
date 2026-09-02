from rest_framework import viewsets

from .models import ApiKey
from .serializers import ApiKeySerializer


# SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
class ApiKeyViewSet(viewsets.ModelViewSet):
    """Manage internal API keys used by service-to-service integrations.

    Supports list, retrieve, create, and destroy via the default router.
    """

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
