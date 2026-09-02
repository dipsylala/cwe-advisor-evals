from rest_framework.permissions import BasePermission


class IsExpenseReportOwner(BasePermission):
    """Object-level permission restricting retrieve/update/destroy to the report's owner."""

    def has_object_permission(self, request, view, obj):
        return obj.owner_id == request.user.id
