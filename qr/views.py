import hashlib
import json

from django.core.cache import cache
from rest_framework.viewsets import ViewSet
from rest_framework.decorators import action
from rest_framework.response import Response
from qr.models import QRCode
from organization.models import Organization


CACHE_KEY_LIST_VERSION = "qr:list_qr_codes:version"
CACHE_TTL_SECONDS = 60


def _get_list_cache_version():
    return cache.get_or_set(CACHE_KEY_LIST_VERSION, 1, timeout=None)


def _bump_list_cache_version():
    try:
        cache.incr(CACHE_KEY_LIST_VERSION)
    except ValueError:
        current = cache.get(CACHE_KEY_LIST_VERSION, 1)
        cache.set(CACHE_KEY_LIST_VERSION, int(current) + 1, timeout=None)


# Create your views here.
class QRCodeViewSet(ViewSet):
    # Endpoint to list all QR codes in the database, with pagination support
    @action(methods=["GET"], detail=False)
    def list_qr_codes(self, request):
        payload = request.GET

        org_id = payload.get("org_id")
        # user = request.user # based on access token (oauth2, to be implemented later)
        # Note: need to implement security checks if user is a part of the organization

        def parse_int(value, default):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        start = max(parse_int(payload.get("start"), 0), 0)
        length = parse_int(payload.get("length"), 12)
        if length <= 0:
            length = 12
        length = min(length, 100)

        search_term = (payload.get("search") or "").strip()
        order_by = (payload.get("order_by") or "created_at").strip()
        order_dir = (payload.get("order_dir") or "desc").strip().lower()

        allowed_order_fields = {
            "id",
            "uuid",
            "created_at",
            "updated_at",
            "profile_created",
            "qr_downloaded",
        }
        if order_by not in allowed_order_fields:
            order_by = "created_at"
        if order_dir not in {"asc", "desc"}:
            order_dir = "desc"

        cache_payload = {
            "start": start,
            "length": length,
            "search": search_term,
            "order_by": order_by,
            "order_dir": order_dir,
            "version": _get_list_cache_version(),
        }
        cache_suffix = hashlib.md5(
            json.dumps(cache_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        cache_key = f"qr:list_qr_codes:{cache_suffix}"
        cached_response = cache.get(cache_key)
        if cached_response is not None:
            return Response(cached_response)

        # Note: Only get QR codes for the org_id passed in the payload
        base_qs = QRCode.objects.filter(org_id=org_id)  # hardcoded org_id for now, to be replaced with actual org_id from payload/user context
        records_total = base_qs.count()

        filtered_qs = base_qs
        if search_term:
            filtered_qs = filtered_qs.filter(uuid__icontains=search_term)
        records_filtered = filtered_qs.count()

        ordering = f"-{order_by}" if order_dir == "desc" else order_by
        paginated_qs = filtered_qs.order_by(ordering, "-id")[start : start + length]

        records = [
            {
                "id": qr_code.id,
                "uuid": qr_code.uuid,
                "profile_created": qr_code.profile_created,
                "qr_downloaded": qr_code.qr_downloaded,
                "created_at": qr_code.created_at,
                "updated_at": qr_code.updated_at,
            }
            for qr_code in paginated_qs
        ]

        response_payload = {
            "recordsTotal": records_total,
            "recordsFiltered": records_filtered,
            "records": records,
        }
        cache.set(cache_key, response_payload, timeout=CACHE_TTL_SECONDS)
        return Response(response_payload)

    @action(methods=["POST"], detail=False)
    def add_qr_code(self, request):
        payload = request.data
        uuid = payload.get("uuid")

        org_id = payload.get("org_id")
        # user = request.user # based on access token (oauth2, to be implemented later)
        # Note: need to implement security checks if user is a part of the organization

        organization = Organization.objects.filter(id=org_id).first()
        if not organization:
            return Response({"error": "Organization not found"}, status=404)

        org_with_uuid = str(organization.org_identifier) + '-' + str(uuid)

        # check if there are enough qr tokens left for the organization before allowing to create a new QR code
        # qr tokens can only be bought by organization admins, will be stored in the organization model (to be implemented later)

        new_qr_code = QRCode.objects.create(org_id=org_id, uuid=org_with_uuid)
        _bump_list_cache_version()

        return Response({"message": f"Generated QR code with UUID: {new_qr_code.uuid}"})

    @action(methods=["PATCH"], detail=False)
    def update_qr_code(self, request):
        payload = request.data
        uuid = payload.get("uuid")

        org_id = payload.get("org_id")
        # user = request.user # based on access token (oauth2, to be implemented later)
        # Note: need to implement security checks if user is a part of the organization

        qr_code = QRCode.objects.filter(org_id=org_id, uuid=uuid).first()
        if not qr_code:
            return Response({"error": "QR code not found"}, status=404)
        profile_created = payload.get("profile_created")
        qr_downloaded = payload.get("qr_downloaded")
        if profile_created is not None:
            qr_code.profile_created = bool(profile_created)
        if qr_downloaded is not None:
            qr_code.qr_downloaded = bool(qr_downloaded)
        qr_code.save(update_fields=["profile_created", "qr_downloaded"])
        _bump_list_cache_version()

        return Response({"message": f"Updated QR code with UUID: {uuid}"})

    @action(methods=["DELETE"], detail=False)
    def delete_qr_code(self, request):
        payload = request.data
        uuid = payload.get("uuid")

        org_id = payload.get("org_id")
        # user = request.user # based on access token (oauth2, to be implemented later)
        # Note: need to implement security checks if user is a part of the organization

        qr_code = QRCode.objects.filter(org_id=org_id, uuid=uuid).first()
        if not qr_code:
            return Response({"error": "QR code not found"}, status=404)

        qr_code.delete()
        _bump_list_cache_version()

        return Response({"message": f"Deleted QR code with UUID: {uuid}"})

    # Endpoint to get profile details for a QR code (this is for the PetProfilePage to call on load)
    @action(methods=["GET"], detail=False)
    def get_profile_details(self, request):
        payload = request.GET
        uuid = payload.get("uuid")

        org_id = payload.get("org_id")
        # user = request.user # based on access token (oauth2, to be implemented later)
        # Note: need to implement security checks if user is a part of the organization

        qr_code = QRCode.objects.filter(org_id=org_id, uuid=uuid).first()
        if not qr_code:
            return Response({"error": "QR code not found"}, status=404)

        profile_details = {
            "profile_created": qr_code.profile_created,
            "created_at": qr_code.created_at,
            "updated_at": qr_code.updated_at,
        }

        if not qr_code.profile_created:
            return Response(profile_details)

        # If profile is created, we can return more details (to be implemented later when ProfileDetails model is created and linked to QRCode)
        # profile_details["name"] = "John Doe"
        # profile_details["email"] = ""
        return Response(profile_details)




