from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from organization.models import Organization
from qr.models import QRCode


class QRCodeViewSetTests(TestCase):
    def setUp(self):
        cache.clear()
        self.org = Organization.objects.create(org_name="Test Org")
        for idx in range(1, 16):
            QRCode.objects.create(org=self.org, uuid=f"qr-{idx:03d}")

    def test_list_qr_codes_default_pagination_contract(self):
        response = self.client.get("/api/qr/list_qr_codes/", {"start": 0, "length": 12})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["recordsTotal"], 15)
        self.assertEqual(data["recordsFiltered"], 15)
        self.assertEqual(len(data["records"]), 12)
        self.assertIn("uuid", data["records"][0])

    def test_list_qr_codes_search_filters_records(self):
        response = self.client.get("/api/qr/list_qr_codes/", {"search": "qr-00", "start": 0, "length": 20})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["recordsTotal"], 15)
        self.assertEqual(data["recordsFiltered"], 9)
        self.assertEqual(len(data["records"]), 9)

    def test_list_qr_codes_honors_ordering(self):
        response = self.client.get(
            "/api/qr/list_qr_codes/",
            {"start": 0, "length": 3, "order_by": "uuid", "order_dir": "asc"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        ordered = [item["uuid"] for item in data["records"]]
        self.assertEqual(ordered, ["qr-001", "qr-002", "qr-003"])

    def test_list_qr_codes_uses_cache_for_repeated_requests(self):
        params = {"start": 0, "length": 12, "search": "", "order_by": "created_at", "order_dir": "desc"}
        first_response = self.client.get("/api/qr/list_qr_codes/", params)

        self.assertEqual(first_response.status_code, 200)
        with CaptureQueriesContext(connection) as context:
            second_response = self.client.get("/api/qr/list_qr_codes/", params)
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(len(context), 0)

    def test_add_qr_code_invalidates_list_cache(self):
        params = {"start": 0, "length": 12}
        before_response = self.client.get("/api/qr/list_qr_codes/", params)
        self.assertEqual(before_response.status_code, 200)
        before_total = before_response.json()["recordsTotal"]

        create_response = self.client.post("/api/qr/add_qr_code/", {"uuid": "qr-cache-test"})
        self.assertEqual(create_response.status_code, 200)

        after_response = self.client.get("/api/qr/list_qr_codes/", params)
        self.assertEqual(after_response.status_code, 200)
        self.assertEqual(after_response.json()["recordsTotal"], before_total + 1)
