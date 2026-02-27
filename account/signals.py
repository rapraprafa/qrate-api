from django.contrib.auth.models import User
from django.db.models.signals import post_delete
from django.dispatch import receiver

from .models import Account


@receiver(post_delete, sender=Account)
def delete_user_with_account(sender, instance, **kwargs):
    User.objects.filter(pk=instance.user_id).delete()
