from django.conf import settings
from django.db import models


class ExpenseReport(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="expense_reports",
    )
    description = models.CharField(max_length=255)
    amount_cents = models.PositiveIntegerField()
    status = models.CharField(max_length=20, default="submitted")
    created_at = models.DateTimeField(auto_now_add=True)
