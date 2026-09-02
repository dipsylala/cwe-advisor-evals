from rest_framework import serializers

from .models import ExpenseReport


class ExpenseReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpenseReport
        fields = ["id", "owner", "description", "amount_cents", "status", "created_at"]
        read_only_fields = ["id", "status", "created_at"]
