from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from .models import Ticket
from .permissions import IsTicketOwner


class TicketViewSet(ModelViewSet):
    """Support tickets. Product policy is that a ticket - which carries a
    customer's raw message body - is visible only to the customer who
    filed it, plus whichever single agent it has been explicitly assigned
    to (assignment happens through a separate endpoint, not modeled here).
    IsTicketOwner is meant to be the one and only access rule for this
    resource.

    is_staff was widened into get_queryset() while copying the pattern
    from AdminAuditLogViewSet, where every staff member is genuinely
    meant to see every row. Nobody reconciled that with IsTicketOwner's
    contract here: has_object_permission() only runs from self.get_object()
    (retrieve/update/destroy), so it never constrains what this list
    action returns, and every staff account - support, sales, whatever
    role - now lists every customer's ticket body regardless of
    assignment.
    """

    serializer_class = None
    permission_classes = [IsAuthenticated, IsTicketOwner]

    def get_queryset(self):
        if self.request.user.is_staff:
            # SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
            return Ticket.objects.all()
        return Ticket.objects.filter(owner=self.request.user)
