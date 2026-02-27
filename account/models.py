from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Account(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organization = models.ForeignKey('organization.Organization', on_delete=models.CASCADE, related_name='account_organization')
    is_admin = models.BooleanField(default=False)  # Indicates if the user is an admin of the organization
    # Additional fields can be added here

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username


class AccountInvite(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='account_invites')
    invite_uuid = models.UUIDField(unique=True)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Invite for {self.email} to join {self.account.organization.org_name}"
