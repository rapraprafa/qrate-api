import sys
import os
import django

sys.path.append(os.getcwd())
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "qrate_api.settings")
django.setup()

def create(applications):
    for application_name in applications:
        application, created = Application.objects.get_or_create(
            name=application_name,
            defaults={
                "client_type": Application.CLIENT_CONFIDENTIAL,
                "authorization_grant_type": Application.GRANT_PASSWORD,
                "user": None,
            },
        )

        if created:
            print(f"Created OAuth application: {application.name}")
        else:
            print(f"OAuth application already exists: {application.name}")

if __name__ == "__main__":
    from oauth2_provider.models import Application

    applications = [
        "qrate-staff",
        "qrate-customer",
    ]

    create(applications=applications)





