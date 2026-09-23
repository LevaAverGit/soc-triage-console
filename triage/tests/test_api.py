"""Read-only DRF API: authenticated access, filtering, alerts, metrics."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from triage.models import Alert, Incident

User = get_user_model()


class ApiTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("analyst", password="pw")
        inc = Incident.objects.create(
            incident_id="INC-1", title="t", severity="high", score=80,
            status="new", created_at=timezone.now(),
        )
        Alert.objects.create(incident=inc, rule_id="R1", rule_name="x",
                             severity="high", mitre_technique_id="T1110")
        Incident.objects.create(
            incident_id="INC-2", title="t2", severity="low", score=10,
            status="closed", created_at=timezone.now(),
        )

    def test_api_requires_authentication(self):
        assert self.client.get("/api/incidents/").status_code in (401, 403)
        assert self.client.get("/api/metrics/").status_code in (401, 403)

    def test_list_is_paginated_and_lists_incidents(self):
        self.client.force_login(self.user)
        data = self.client.get("/api/incidents/").json()
        assert "results" in data  # PageNumberPagination
        assert {"INC-1", "INC-2"} <= {i["incident_id"] for i in data["results"]}

    def test_detail_includes_alerts(self):
        self.client.force_login(self.user)
        data = self.client.get("/api/incidents/INC-1/").json()
        assert data["incident_id"] == "INC-1"
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["mitre_technique_id"] == "T1110"

    def test_filter_by_severity(self):
        self.client.force_login(self.user)
        data = self.client.get("/api/incidents/?severity=high").json()
        assert [i["incident_id"] for i in data["results"]] == ["INC-1"]

    def test_metrics_endpoint(self):
        self.client.force_login(self.user)
        data = self.client.get("/api/metrics/").json()
        assert data["total"] == 2
        assert data["by_severity"]["high"] == 1
        assert data["by_status"]["closed"] == 1
