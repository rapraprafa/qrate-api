from django.db import models
from organization.models import Organization

# Create your models here.
class QRCode(models.Model):
    org = models.ForeignKey('organization.Organization', on_delete=models.CASCADE, related_name='qr_codes')
    uuid = models.CharField(max_length=255, default=None, unique=True)
    profile_created = models.BooleanField(default=False)
    qr_downloaded = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        self.org: Organization
        return "({}) {} {}".format(self.id, str(self.org.org_name), self.uuid)


# class ProfileDetails(models.Model):
#     # This model can be expanded in the future to include more details about the user profile created after scanning the QR code
#     qr_code = models.OneToOneField(QRCode, on_delete=models.CASCADE, related_name='profile_details')
#     name = models.CharField(max_length=255, blank=True, null=True)
#     email = models.EmailField(blank=True, null=True)
#     phone_number = models.CharField(max_length=20, blank=True, null=True)
