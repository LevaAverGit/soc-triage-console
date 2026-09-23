"""View-level tests: everything is login-gated, and the status-change endpoint
enforces the transition rule server-side -- a hand-crafted POST from an L1 cannot
close an escalated incident even though the button is never rendered for them.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from triage.models import AuditEntry, Incident, TriageNote

User = get_user_model()


class ViewTestBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        l1 = Group.objects.create(name="L1")
        l2 = Group.objects.create(name="L2")
        cls.analyst = User.objects.create_user("analyst", password="pw")
        cls.analyst.groups.add(l1)
        cls.lead = User.objects.create_user("lead", password="pw")
        cls.lead.groups.add(l2)

    def _incident(self, status=Incident.Status.NEW, **over):
        fields = dict(
            incident_id="INC-0001", title="t", severity="high", score=50,
            status=status, created_at=timezone.now(),
        )
        fields.update(over)
        return Incident.objects.create(**fields)


class AccessControlTests(ViewTestBase):
    def test_queue_requires_login(self):
        resp = self.client.get(reverse("incident-list"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("login"), resp["Location"])

    def test_detail_requires_login(self):
        self._incident()
        resp = self.client.get(reverse("incident-detail", args=["INC-0001"]))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("login"), resp["Location"])

    def test_logged_in_analyst_sees_queue(self):
        self._incident()
        self.client.force_login(self.analyst)
        resp = self.client.get(reverse("incident-list"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "INC-0001")


class QueueFilterTests(ViewTestBase):
    def test_filter_by_severity_and_status(self):
        self._incident(incident_id="A", severity="critical", status="new")
        self._incident(incident_id="B", severity="low", status="closed")
        self.client.force_login(self.analyst)

        resp = self.client.get(reverse("incident-list"), {"severity": "critical"})
        self.assertContains(resp, "A")
        self.assertNotContains(resp, ">B<")

        resp = self.client.get(reverse("incident-list"), {"status": "closed"})
        self.assertContains(resp, "B")
        self.assertNotContains(resp, ">A<")


class StatusChangeTests(ViewTestBase):
    def _post_status(self, user, incident_id, to_status):
        self.client.force_login(user)
        return self.client.post(
            reverse("incident-status", args=[incident_id]), {"to_status": to_status}
        )

    def test_analyst_can_triage(self):
        self._incident(status="new")
        self._post_status(self.analyst, "INC-0001", "triaged")
        self.assertEqual(Incident.objects.get(incident_id="INC-0001").status, "triaged")
        self.assertEqual(AuditEntry.objects.count(), 1)
        entry = AuditEntry.objects.get()
        self.assertEqual((entry.from_status, entry.to_status), ("new", "triaged"))
        self.assertEqual(entry.actor, self.analyst)

    def test_l1_cannot_close_escalated_even_by_direct_post(self):
        self._incident(status="escalated")
        resp = self._post_status(self.analyst, "INC-0001", "closed")
        self.assertEqual(resp.status_code, 302)  # refused, redirected back
        self.assertEqual(
            Incident.objects.get(incident_id="INC-0001").status, "escalated"
        )
        self.assertEqual(AuditEntry.objects.count(), 0)  # nothing recorded

    def test_l2_can_close_escalated(self):
        self._incident(status="escalated")
        self._post_status(self.lead, "INC-0001", "closed")
        self.assertEqual(Incident.objects.get(incident_id="INC-0001").status, "closed")
        self.assertEqual(AuditEntry.objects.count(), 1)

    def test_illegal_jump_is_refused(self):
        self._incident(status="new")
        self._post_status(self.lead, "INC-0001", "closed")  # new -> closed not allowed
        self.assertEqual(Incident.objects.get(incident_id="INC-0001").status, "new")
        self.assertEqual(AuditEntry.objects.count(), 0)

    def test_get_does_not_change_status(self):
        self._incident(status="new")
        self.client.force_login(self.analyst)
        self.client.get(reverse("incident-status", args=["INC-0001"]))
        self.assertEqual(Incident.objects.get(incident_id="INC-0001").status, "new")


class AssignTests(ViewTestBase):
    def test_take_and_release(self):
        self._incident()
        self.client.force_login(self.analyst)
        url = reverse("incident-assign", args=["INC-0001"])

        self.client.post(url, {"action": "take"})
        self.assertEqual(
            Incident.objects.get(incident_id="INC-0001").assignee, self.analyst
        )

        self.client.post(url, {"action": "release"})
        self.assertIsNone(Incident.objects.get(incident_id="INC-0001").assignee)

    def test_assign_requires_login(self):
        self._incident()
        resp = self.client.post(reverse("incident-assign", args=["INC-0001"]),
                                {"action": "take"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("login"), resp["Location"])


class NoteTests(ViewTestBase):
    def test_add_note(self):
        self._incident()
        self.client.force_login(self.analyst)
        self.client.post(reverse("incident-note", args=["INC-0001"]), {"body": "looks real"})
        note = TriageNote.objects.get()
        self.assertEqual(note.body, "looks real")
        self.assertEqual(note.author, self.analyst)

    def test_empty_note_is_rejected(self):
        self._incident()
        self.client.force_login(self.analyst)
        self.client.post(reverse("incident-note", args=["INC-0001"]), {"body": "   "})
        self.assertEqual(TriageNote.objects.count(), 0)
