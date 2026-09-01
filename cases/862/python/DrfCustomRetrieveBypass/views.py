from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from .models import Invoice
from .permissions import IsInvoiceOwner


class InvoiceViewSet(ModelViewSet):
    serializer_class = None
    permission_classes = [IsAuthenticated, IsInvoiceOwner]

    def get_queryset(self):
        if self.request.user.is_staff:
            return Invoice.objects.all()
        return Invoice.objects.filter(owner_id=self.request.user.id)

    def retrieve(self, request, pk=None):
        # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        invoice = get_object_or_404(Invoice, pk=pk)
        return Response({
            "id": invoice.id,
            "owner_id": invoice.owner_id,
            "total_cents": invoice.total_cents
        })
