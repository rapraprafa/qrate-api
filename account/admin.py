from django.contrib import admin
from account.models import Account
# from adminfilters.autocomplete import AutoCompleteFilter


class AccountAdmin(admin.ModelAdmin):
    readonly_fields = ["id", "organization"]
    list_display = [
        "user",
        "organization",
        "is_admin",
        "created_at",
        "updated_at",
    ]

    # list_filter = [("org_name", AutoCompleteFilter), "org_identifier"]

    search_fields = ["user__username", "organization__org_name"]

# Register your models here.
admin.site.register(Account, AccountAdmin)
