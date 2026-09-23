"""Evidence file upload: login-gated, stored, size-limited."""

import tempfile

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from triage.models import Attachment, Incident

User = get_user_model()


@override_settings(MEDIA_ROOT=tempfile.mkdtemp())
class AttachmentTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("analyst", password="pw")
        Incident.objects.create(
            incident_id="INC-1", title="t", severity="high", score=80,
            status="new", created_at=timezone.now(),
        )

    def _url(self):
        return reverse("incident-attach", args=["INC-1"])

    def test_upload_requires_login(self):
        resp = self.client.post(self._url(), {})
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("login"), resp["Location"])

    def test_upload_attaches_file(self):
        self.client.force_login(self.user)
        f = SimpleUploadedFile("evidence.txt", b"pcap-bytes", content_type="text/plain")
        self.client.post(self._url(), {"file": f})
        att = Attachment.objects.get()
        self.assertEqual(att.original_name, "evidence.txt")
        self.assertEqual(att.uploaded_by, self.user)
        self.assertEqual(att.incident.incident_id, "INC-1")

    def test_oversized_file_is_rejected(self):
        self.client.force_login(self.user)
        big = SimpleUploadedFile("big.bin", b"x" * (10 * 1024 * 1024 + 1))
        self.client.post(self._url(), {"file": big})
        self.assertEqual(Attachment.objects.count(), 0)

    def test_empty_upload_is_rejected(self):
        self.client.force_login(self.user)
        self.client.post(self._url(), {})
        self.assertEqual(Attachment.objects.count(), 0)
