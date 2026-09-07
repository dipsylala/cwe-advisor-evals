"""Compile-only collaborator the fixture imports but does not ship (evals/stubs)."""
from django.db import models


class Order(models.Model):
    customer_email = models.CharField(max_length=200)
    placed_at = models.DateTimeField()
    total_cents = models.IntegerField()
    status = models.CharField(max_length=32)
