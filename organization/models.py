from django.db import models
from uuid import uuid4

# Create your models here.
class Organization(models.Model):
    org_name = models.CharField(max_length=255)
    org_identifier = models.UUIDField(default=uuid4, unique=True, editable=False)  # e.g. a unique code or slug to identify the organization
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.org_name
