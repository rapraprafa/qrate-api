from django.contrib import admin
from organization.models import Organization
# from adminfilters.autocomplete import AutoCompleteFilter


class OrganizationAdmin(admin.ModelAdmin):
    readonly_fields = ["id", "org_identifier"]
    list_display = [
        "org_name",
        "org_identifier",
        "created_at",
        "updated_at",
    ]

    # list_filter = [("org_name", AutoCompleteFilter), "org_identifier"]

    search_fields = ["org_name", "org_identifier"]

# Register your models here.
admin.site.register(Organization, OrganizationAdmin)
