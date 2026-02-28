from account.models import Account

class SecurityUtils:
    @staticmethod
    def is_staff_an_org_member(user_instance, org_id):
        if not user_instance or not user_instance.is_authenticated:
            return False

        # Check if the user has an associated account
        account: Account = Account.objects.filter(user=user_instance).first()

        if not account:
            return False

        # Check if the user is a member of the organization
        if not account.organization:
            return False

        # Check if the user is part of the specified organization
        if str(account.organization.id) != str(org_id):
            return False

        return True

    def is_staff_an_org_admin(user_instance, org_id):
        if not SecurityUtils.is_staff_an_org_member(user_instance, org_id):
            return False

        account: Account = Account.objects.filter(user=user_instance).first()
        if not account:
            return False

        return account.is_admin

