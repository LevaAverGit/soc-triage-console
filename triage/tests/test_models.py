"""Model-level guarantees the rest of the app leans on: queue ordering and the
append-only audit trail's default order.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from triage.models import AuditEntry, Incident

User = get_user_model()


class OrderingTests(TestCase):
    def test_queue_orders_by_score_then_severity(self):
        now = timezone.now()
        Incident.objects.create(incident_id="LOW", title="t", severity="low",
                                score=10, created_at=now)
        Incident.objects.create(incident_id="TOP", title="t", severity="critical",
                                score=90, created_at=now)
        Incident.objects.create(incident_id="MID", title="t", severity="high",
                                score=50, created_at=now)
        self.assertEqual(
            [i.incident_id for i in Incident.objects.all()],
            ["TOP", "MID", "LOW"],
        )

    def test_audit_is_newest_first(self):
        inc = Incident.objects.create(incident_id="INC", title="t", severity="low",
                                      score=1, created_at=timezone.now())
        AuditEntry.objects.create(incident=inc, from_status="new", to_status="triaged")
        AuditEntry.objects.create(incident=inc, from_status="triaged", to_status="closed")
        self.assertEqual(
            [e.to_status for e in inc.audit.all()],
            ["closed", "triaged"],
        )
