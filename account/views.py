from django.shortcuts import render
import hashlib
import json

from django.core.cache import cache
from django.conf import settings
from django.middleware.csrf import get_token
from rest_framework.viewsets import ViewSet
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth import authenticate, logout
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils.crypto import constant_time_compare
from rest_framework.permissions import IsAuthenticated
from qr.models import QRCode
from account.models import Account, AccountInvite
from datetime import timedelta
from uuid import uuid4
from oauth2_provider.models import AccessToken, Application, RefreshToken
from utils.security_utils import SecurityUtils
from oauthlib.common import generate_token
from utils.response_utils import ResponseUtils
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

# Create your views here.

# TODO - Implement permission classes for this viewset, e.g. only allow requests from a specific host (qrate-staff-portal)
CACHE_KEY_LIST_STAFF_ACCOUNTS_VERSION = "account:list_staff_accounts:version"
STAFF_LIST_CACHE_TTL_SECONDS = 60


def _get_staff_list_cache_version():
    return cache.get_or_set(CACHE_KEY_LIST_STAFF_ACCOUNTS_VERSION, 1, timeout=None)


def _bump_staff_list_cache_version():
    try:
        cache.incr(CACHE_KEY_LIST_STAFF_ACCOUNTS_VERSION)
    except ValueError:
        current = cache.get(CACHE_KEY_LIST_STAFF_ACCOUNTS_VERSION, 1)
        cache.set(CACHE_KEY_LIST_STAFF_ACCOUNTS_VERSION, int(current) + 1, timeout=None)

class AccountViewSet(ViewSet):
    @staticmethod
    def _get_cookie_config():
        return {
            "access_name": getattr(settings, "AUTH_COOKIE_ACCESS_NAME", "qrate-staff-access-token"),
            "refresh_name": getattr(settings, "AUTH_COOKIE_REFRESH_NAME", "qrate-staff-refresh-token"),
            "csrf_name": getattr(settings, "CSRF_COOKIE_NAME", "qrate-staff-csrf-token"),
            "access_max_age": getattr(settings, "AUTH_COOKIE_ACCESS_MAX_AGE_SECONDS", 900),
            "refresh_max_age": getattr(settings, "AUTH_COOKIE_REFRESH_MAX_AGE_SECONDS", 60 * 60 * 24 * 7),
            "csrf_max_age": getattr(settings, "CSRF_COOKIE_AGE", 31449600),
            "samesite": getattr(settings, "AUTH_COOKIE_SAMESITE", None),
            "secure": getattr(settings, "AUTH_COOKIE_SECURE", True),
            "csrf_domain": getattr(settings, "CSRF_COOKIE_DOMAIN", None),
            "csrf_path": getattr(settings, "CSRF_COOKIE_PATH", "/"),
            "csrf_httponly": getattr(settings, "CSRF_COOKIE_HTTPONLY", False),
        }

    @classmethod
    def _set_token_cookies(cls, response, access_token, refresh_token, request):
        cookie_cfg = cls._get_cookie_config()
        response.set_cookie(
            cookie_cfg["access_name"],
            access_token,
            max_age=cookie_cfg["access_max_age"],
            httponly=True,
            secure=cookie_cfg["secure"],
            samesite=cookie_cfg["samesite"],
            path="/",
        )
        response.set_cookie(
            cookie_cfg["refresh_name"],
            refresh_token,
            max_age=cookie_cfg["refresh_max_age"],
            httponly=True,
            secure=cookie_cfg["secure"],
            samesite=cookie_cfg["samesite"],
            path="/",
        )
        csrf_token = get_token(request)
        response.set_cookie(
            key=cookie_cfg["csrf_name"],
            value=csrf_token,
            max_age=cookie_cfg["csrf_max_age"],
            secure=cookie_cfg["secure"],
            domain=cookie_cfg["csrf_domain"],
            path=cookie_cfg["csrf_path"],
            samesite=cookie_cfg["samesite"],
            httponly=cookie_cfg["csrf_httponly"],
        )

    @classmethod
    def _clear_token_cookies(cls, response):
        cookie_cfg = cls._get_cookie_config()
        response.delete_cookie(
            cookie_cfg["access_name"],
            path="/",
            samesite=cookie_cfg["samesite"],
        )
        response.delete_cookie(
            cookie_cfg["refresh_name"],
            path="/",
            samesite=cookie_cfg["samesite"],
        )

    @classmethod
    def _issue_token_pair(cls, user_instance, oauth_application, scope="read write"):
        access_token_expiry = timezone.now() + timedelta(seconds=cls._get_cookie_config()["access_max_age"])

        access_token = generate_token()
        access_token_instance = AccessToken.objects.create(
            user=user_instance,
            application=oauth_application,
            token=access_token,
            expires=access_token_expiry,
            scope=scope,
        )
        refresh_token = generate_token()
        RefreshToken.objects.create(
            user=user_instance,
            token=refresh_token,
            application=oauth_application,
            access_token=access_token_instance,
        )
        return access_token, refresh_token

    @staticmethod
    def _get_application_from_request(request):
        application_name = (request.headers.get("X-Application-Name") or "").strip()
        if not application_name:
            return None, ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Missing X-Application-Name header.")

        oauth_application = Application.objects.filter(name=application_name).first()
        if oauth_application is None:
            return None, ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Invalid OAuth application.")

        return oauth_application, None

    @classmethod
    def _serialize_staff_details(cls, user_instance):
        account = Account.objects.filter(user=user_instance).first()
        if account is None:
            return None
        return {
            "id": user_instance.id,
            "username": user_instance.username,
            "email": user_instance.email,
            "first_name": user_instance.first_name,
            "last_name": user_instance.last_name,
            "organization": {
                "id": account.organization.id,
                "org_name": account.organization.org_name,
            },
            "is_admin": account.is_admin,
        }

    @action(methods=["POST"], detail=False)
    # TODO: This can only be accessed by organization admins, but for now we will leave it open until we implement the permission classes
    def add_staff(self, request):
        payload = request.data
        email = payload.get("email")
        first_name = payload.get("first_name")
        last_name = payload.get("last_name")
        org_id = payload.get("org_id")

        # TODO: Security check to ensure request.user is part of the organization and is an admin

        if not all([email, first_name, last_name, org_id]):
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Missing required fields.")

        email = email.strip()
        first_name = first_name.strip()
        last_name = last_name.strip()

        if User.objects.filter(email__iexact=email).exists():
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Email already exists.")


        account_invite_uuid = uuid4() # new model for staff invites, with FK to account instance
        user_instance = User.objects.create_user(username=email, email=email, first_name=first_name, last_name=last_name)
        account_instance = Account.objects.create(user=user_instance, organization_id=org_id)

        # Add an entry in the AccountInvite model with the generated UUID and link it to the account instance, this will be used to verify the staff invite and allow them to set up their password
        AccountInvite.objects.create(account=account_instance, invite_uuid=account_invite_uuid)
        _bump_staff_list_cache_version()

        # TODO: function to send email invitation to the new staff member to be implemented later, email should contain a link that has the invite UUID to set up their account and create a password

        return Response(
            {
                "message": "Staff member added successfully.",
                "staff_details": {
                    "id": user_instance.id,
                    "username": user_instance.username,
                    "email": user_instance.email,
                    "first_name": user_instance.first_name,
                    "last_name": user_instance.last_name,
                    "organization": {
                        "id": account_instance.organization.id,
                        "org_name": account_instance.organization.org_name,
                    },
                    "is_admin": account_instance.is_admin,
                },
            }
        )

    @action(methods=["PATCH"], detail=False)
    # This is the endpoint that will be called on create-password-page (link sent by admin to staff email), the endpoint will verify the staff invite uuid and allow the staff to set up their password
    def staff_create_password(self, request, permission_classes=[], authentication_classes=[]):
        payload = request.data
        invite_uuid = payload.get("invite_uuid")
        new_password = payload.get("new_password")

        if not all([invite_uuid, new_password]):
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Missing required fields.")

        account_invite_instance = AccountInvite.objects.filter(invite_uuid=invite_uuid).first()
        if not account_invite_instance:
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Invalid invite UUID.")

        if account_invite_instance.is_used:
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Invite UUID has already been used.")

        user_instance = account_invite_instance.account.user
        user_instance.set_password(new_password)
        user_instance.save()

        return Response(
            {
                "message": "Password has been saved successfully!"
            }
        )

    @action(methods=["POST"], detail=False, permission_classes=[], authentication_classes=[])
    def staff_login(self, request):
        payload = request.data
        email = (payload.get("email") or "").strip()
        password = (payload.get("password") or "").strip()

        if not email or not password:
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Missing required fields.")

        # user = request.user # based on access token (oauth2, to be implemented later)
        # Note: need to implement security checks if user is a part of the organization

        user_instance = None

        try:
            findUser = User._default_manager.get(email__iexact=email)
        except User.DoesNotExist:
            findUser = None

        if findUser is not None:
            user_instance = authenticate(username=findUser.username, password=password)
        if not user_instance:
            # TODO: handle_failed_login(username) # to be implemented later, e.g. logging, rate limiting, locking account if tried too many times etc.
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Invalid email or password.")

        oauth_application, error_response = self._get_application_from_request(request)
        if error_response is not None:
            return error_response

        staff_details = self._serialize_staff_details(user_instance)
        if staff_details is None:
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "No account associated with this user.")

        # Delete existing tokens for the user and application to enforce single session per user per application, can be modified later if we want to allow multiple sessions
        existing_tokens = AccessToken.objects.filter(user=user_instance, application=oauth_application)
        for token in existing_tokens:
            RefreshToken.objects.filter(access_token=token).delete()
            token.delete()

        access_token, refresh_token = self._issue_token_pair(
            user_instance=user_instance,
            oauth_application=oauth_application,
            scope="read write",
        )

        response = {
            "staff_details": staff_details,
            "expires_in": self._get_cookie_config()["access_max_age"],
            "token_type": "Bearer",
        }

        login_response = Response(response)
        self._set_token_cookies(login_response, access_token, refresh_token, request)
        return login_response

        # check if there are enough qr tokens left for the organization before allowing to create a new QR code
        # qr tokens can only be bought by organization admins, will be stored in the organization model (to be implemented later)

        new_qr_code = QRCode.objects.create(org_id=org_id, uuid=org_with_uuid)

        return Response({"message": f"Generated QR code with UUID: {new_qr_code.uuid}"})

    @action(methods=["POST"], detail=False)
    def staff_logout(self, request):
        token = None
        refresh_cookie_token = request.COOKIES.get(self._get_cookie_config()["refresh_name"])

        if request.auth is not None:
            token = request.auth.token if hasattr(request.auth, "token") else str(request.auth)

        if token is None:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ", 1)[1].strip()

        if token is None:
            token = (request.data.get("access_token") or "").strip() or None

        if token:
            access_token = AccessToken.objects.filter(token=token).first()
            if access_token is not None:
                RefreshToken.objects.filter(access_token=access_token).delete()
                access_token.delete()

                user_instance = access_token.user

                oauth_application, error_response = self._get_application_from_request(request)
                if error_response is not None:
                    return error_response

                # Delete existing tokens for the user and application to enforce single session per user per application, can be modified later if we want to allow multiple sessions
                existing_tokens = AccessToken.objects.filter(user=user_instance, application=oauth_application)
                for token in existing_tokens:
                    RefreshToken.objects.filter(access_token=token).delete()
                    token.delete()

        if refresh_cookie_token:
            refresh_token_qs = RefreshToken.objects.filter(token=refresh_cookie_token, revoked__isnull=True)
            for refresh_token_instance in refresh_token_qs:
                refresh_token_instance.revoke()
                previous_access_token = refresh_token_instance.access_token
                if previous_access_token is not None:
                    previous_access_token.delete()

        logout(request)

        logout_response = ResponseUtils.send_success_response("Logged out successfully.")
        self._clear_token_cookies(logout_response)
        return logout_response

    @action(methods=["POST"], detail=False, permission_classes=[], authentication_classes=[])
    def revoke_expired_tokens(self, request):
        payload = request.data
        access_token = (payload.get("access_token") or "").strip()
        if not access_token:
            access_token = (request.COOKIES.get(self._get_cookie_config()["access_name"]) or "").strip()
        if not access_token:
            return ResponseUtils.send_error_response(HTTP_401_UNAUTHORIZED, "Invalid access token.")

        application_name = (request.headers.get("X-Application-Name") or "").strip()
        if not application_name:
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Missing X-Application-Name header.")

        oauth_application = Application.objects.filter(name=application_name).first()
        if oauth_application is None:
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Invalid OAuth application.")

        access_tokens = AccessToken.objects.filter(application=oauth_application, token=access_token)
        if not access_tokens.exists():
            return ResponseUtils.send_error_response(HTTP_401_UNAUTHORIZED, "Invalid access token.")

        RefreshToken.objects.filter(access_token__in=access_tokens).delete()

        access_tokens.delete()

        response = ResponseUtils.send_success_response("Expired tokens revoked successfully.")
        self._clear_token_cookies(response)
        return response

    @action(methods=["POST"], detail=False, permission_classes=[], authentication_classes=[])
    def refresh_token(self, request):
        oauth_application, error_response = self._get_application_from_request(request)
        if error_response is not None:
            return error_response

        refresh_cookie_name = self._get_cookie_config()["refresh_name"]
        refresh_token_cookie = (request.COOKIES.get(refresh_cookie_name) or "").strip()
        refresh_token_body = (request.data.get("refresh_token") or "").strip()

        refresh_token_value = refresh_token_cookie or refresh_token_body
        if not refresh_token_value:
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Missing refresh_token.")

        if refresh_token_cookie and refresh_token_body:
            if not constant_time_compare(refresh_token_cookie, refresh_token_body):
                return ResponseUtils.send_error_response(HTTP_401_UNAUTHORIZED, "Refresh token mismatch.")

        refresh_token_instance = RefreshToken.objects.filter(
            token=refresh_token_value,
            application=oauth_application,
            revoked__isnull=True,
        ).first()
        if refresh_token_instance is None:
            return ResponseUtils.send_error_response(HTTP_401_UNAUTHORIZED, "Invalid refresh token.")

        previous_scope = "read write"
        previous_access_token = refresh_token_instance.access_token
        if previous_access_token is not None and previous_access_token.scope:
            previous_scope = previous_access_token.scope

        user_instance = refresh_token_instance.user
        refresh_token_instance.revoke()
        if previous_access_token is not None:
            previous_access_token.delete()

        access_token_expiry = timezone.now() + timedelta(seconds=self._get_cookie_config()["access_max_age"])
        new_access_token = generate_token()
        access_token_instance = AccessToken.objects.create(
            user=user_instance,
            application=oauth_application,
            token=new_access_token,
            expires=access_token_expiry,
            scope=previous_scope,
            source_refresh_token=refresh_token_instance,
        )

        new_refresh_token = generate_token()
        RefreshToken.objects.create(
            user=user_instance,
            token=new_refresh_token,
            application=oauth_application,
            access_token=access_token_instance,
        )

        refresh_response = Response(
            {
                "expires_in": self._get_cookie_config()["access_max_age"],
                "token_type": "Bearer",
            }
        )
        self._set_token_cookies(refresh_response, new_access_token, new_refresh_token, request)
        return refresh_response

    @action(methods=["GET"], detail=False)
    def list_staff_accounts(self, request):
        payload = request.GET

        def parse_int(value, default):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        org_id = payload.get("org_id")
        if not SecurityUtils.is_staff_an_org_admin(request.user, org_id):
            return ResponseUtils.send_error_response(HTTP_403_FORBIDDEN, "You do not have permission to view staff accounts.")

        if not org_id and request.user and request.user.is_authenticated:
            request_account = Account.objects.filter(user=request.user).first()
            if not request_account.is_admin:
                return ResponseUtils.send_error_response(HTTP_403_FORBIDDEN, "You do not have permission to view staff accounts.")
            if request_account is not None:
                org_id = request_account.organization_id

        if not org_id:
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "Missing org_id.")

        draw = max(parse_int(payload.get("draw"), 1), 1)
        start = max(parse_int(payload.get("start"), 0), 0)
        length = parse_int(payload.get("length"), 12)
        if length <= 0:
            length = 12
        length = min(length, 100)

        search_term = (payload.get("search") or "").strip()
        order_by = (payload.get("order_by") or "email").strip()
        order_dir = (payload.get("order_dir") or "asc").strip().lower()

        allowed_order_fields = {
            "id": "user__id",
            "email": "user__email",
            "first_name": "user__first_name",
            "last_name": "user__last_name",
            "is_admin": "is_admin",
            "created_at": "created_at",
            "updated_at": "updated_at",
        }
        if order_by not in allowed_order_fields:
            order_by = "email"
        if order_dir not in {"asc", "desc"}:
            order_dir = "asc"

        cache_payload = {
            "org_id": str(org_id),
            "start": start,
            "length": length,
            "search": search_term,
            "order_by": order_by,
            "order_dir": order_dir,
            "version": _get_staff_list_cache_version(),
        }
        cache_suffix = hashlib.md5(
            json.dumps(cache_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        cache_key = f"account:list_staff_accounts:{cache_suffix}"
        cached_response = cache.get(cache_key)
        if cached_response is not None:
            cached_response["draw"] = draw
            return Response(cached_response)

        base_qs = Account.objects.select_related("user").filter(organization_id=org_id)
        records_total = base_qs.count()

        filtered_qs = base_qs
        if search_term:
            search_filter = (
                Q(user__email__icontains=search_term)
                | Q(user__first_name__icontains=search_term)
                | Q(user__last_name__icontains=search_term)
                | Q(user__username__icontains=search_term)
            )

            normalized_search = search_term.lower()
            if normalized_search in {"admin", "true", "yes", "1"}:
                search_filter |= Q(is_admin=True)
            elif normalized_search in {"staff", "false", "no", "0"}:
                search_filter |= Q(is_admin=False)

            filtered_qs = filtered_qs.filter(search_filter)

        records_filtered = filtered_qs.count()

        resolved_order_field = allowed_order_fields[order_by]
        ordering = f"-{resolved_order_field}" if order_dir == "desc" else resolved_order_field
        paginated_qs = filtered_qs.order_by(ordering, "user__id")[start : start + length]

        records = [
            {
                "id": account.user.id,
                "email": account.user.email,
                "first_name": account.user.first_name,
                "last_name": account.user.last_name,
                "is_admin": account.is_admin,
            }
            for account in paginated_qs
        ]

        response_payload = {
            "draw": draw,
            "recordsTotal": records_total,
            "recordsFiltered": records_filtered,
            "records": records,
        }
        cache.set(cache_key, response_payload.copy(), timeout=STAFF_LIST_CACHE_TTL_SECONDS)
        return Response(response_payload)

    @action(methods=["GET"], detail=False, permission_classes=[IsAuthenticated])
    def staff_details(self, request):
        staff_details = self._serialize_staff_details(request.user)
        if staff_details is None:
            return ResponseUtils.send_error_response(HTTP_400_BAD_REQUEST, "No account associated with this user.")

        return Response({"staff_details": staff_details})
