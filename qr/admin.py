from django.contrib import admin
from qr.models import QRCode

class QRCodeAdmin(admin.ModelAdmin):
    # readonly_fields = ["id", "org_identifier"]

    list_display = [
        "org",
        "uuid",
        "profile_created",
        "qr_downloaded",
        "created_at",
        "updated_at",
    ]

    # list_filter = [("org_name", AutoCompleteFilter), "org_identifier"]

    search_fields = ["org__org_name", "uuid"]

# Register your models here.
admin.site.register(QRCode, QRCodeAdmin)
