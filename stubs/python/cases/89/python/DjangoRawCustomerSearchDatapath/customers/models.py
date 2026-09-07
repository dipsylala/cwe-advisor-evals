"""Compile-only collaborator the fixture imports but does not ship (evals/stubs)."""
from django.db import models


class Customer(models.Model):
    tenant_id = models.IntegerField()
    name = models.CharField(max_length=200)
    email = models.CharField(max_length=200)
