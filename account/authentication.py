from django.conf import settings
from oauth2_provider.oauth2_backends import get_oauthlib_core
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import exceptions
from rest_framework.authentication import CSRFCheck


class CookieOrHeaderOAuth2Authentication(OAuth2Authentication):
    """
    Accept bearer token from Authorization header (existing behavior)
    and from the HttpOnly access-token cookie for browser requests.
    """

    def authenticate(self, request):
        auth_result = super().authenticate(request)
        if auth_result is not None:
            return auth_result

        cookie_name = getattr(settings, "AUTH_COOKIE_ACCESS_NAME", "access_token")

        raw_token = request.COOKIES.get(cookie_name)
        print(request.path, raw_token)
        if not raw_token:
            raise exceptions.NotAuthenticated("Authentication credentials were not provided.")

        # Reuse DOT verification by temporarily injecting Authorization header from cookie.
        original_auth = request.META.get("HTTP_AUTHORIZATION")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {raw_token}"
        oauthlib_core = get_oauthlib_core()
        valid, oauth_request = oauthlib_core.verify_request(request, scopes=[])
        if original_auth is None:
            request.META.pop("HTTP_AUTHORIZATION", None)
        else:
            request.META["HTTP_AUTHORIZATION"] = original_auth

        if not valid:
            request.oauth2_error = getattr(oauth_request, "oauth2_error", {})
            raise exceptions.AuthenticationFailed("Invalid access token.")

        self._enforce_csrf(request)
        return oauth_request.user, oauth_request.access_token

    def _enforce_csrf(self, request):
        django_request = request._request
        csrf_check = CSRFCheck(lambda _request: None)
        csrf_check.process_request(django_request)
        reason = csrf_check.process_view(django_request, None, (), {})
        if reason:
            raise exceptions.PermissionDenied(f"CSRF Failed: {reason}")
