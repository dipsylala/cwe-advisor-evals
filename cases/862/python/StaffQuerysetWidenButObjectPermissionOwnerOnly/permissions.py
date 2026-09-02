from rest_framework.permissions import BasePermission


class IsTicketOwner(BasePermission):
    """Object-level check used by TicketViewSet.

    Compares the ticket's owner to the requesting user. This is meant to
    be the only access rule for a ticket - see TicketViewSet's own
    docstring for why the get_queryset() staff widening does not
    actually defer to this check for the list action.
    """

    def has_object_permission(self, request, view, obj):
        return obj.owner_id == request.user.id
