"""Management-command tests: the demo bootstrap, and every branch of the SIEM
sync command -- the REST (``--url``) fetch and each error path -- so the
advertised integration is actually covered, not just the ingest core.
"""

import json
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

import httpx
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from triage.models import Incident
from triage.transitions import is_l2

User = get_user_model()


def _one_incident(incident_id="INC-1"):
    return {
        "incident_id": incident_id, "title": "t", "severity": "high",
        "score": 40, "summary": "s", "source_ips": [],
        "created_at": "2026-09-20T10:00:00Z", "alerts": [],
    }


class BootstrapDemoTests(TestCase):
    def test_creates_roles_and_users(self):
        call_command("bootstrap_demo", "--no-data", stdout=StringIO())
        self.assertTrue(Group.objects.filter(name="L1").exists())
        self.assertTrue(Group.objects.filter(name="L2").exists())

        analyst = User.objects.get(username="analyst")
        lead = User.objects.get(username="lead")
        self.assertFalse(is_l2(analyst))
        self.assertTrue(is_l2(lead))
        self.assertTrue(analyst.check_password("analyst-demo"))
        self.assertTrue(lead.is_staff)  # L2 can reach the admin

    def test_is_idempotent(self):
        call_command("bootstrap_demo", "--no-data", stdout=StringIO())
        call_command("bootstrap_demo", "--no-data", stdout=StringIO())
        self.assertEqual(User.objects.filter(username="analyst").count(), 1)
        self.assertEqual(Group.objects.filter(name="L1").count(), 1)

    def test_loads_sample_incidents_from_bundled_export(self):
        # The repo ships exports/incidents.json; bootstrap should load it.
        call_command("bootstrap_demo", stdout=StringIO())
        self.assertGreater(Incident.objects.count(), 0)

    def test_l2_group_gets_admin_permissions(self):
        call_command("bootstrap_demo", "--no-data", stdout=StringIO())
        l2 = Group.objects.get(name="L2")
        codenames = set(l2.permissions.values_list("codename", flat=True))
        # Enough to open the admin and read the (read-only) audit trail.
        self.assertIn("view_incident", codenames)
        self.assertIn("view_auditentry", codenames)


class SyncCommandTests(TestCase):
    def test_url_source_fetches_and_ingests(self):
        payload = [_one_incident("INC-URL-1"), _one_incident("INC-URL-2")]
        fake = httpx.Response(
            200, json=payload,
            request=httpx.Request("GET", "http://siem.local/incidents/export.json"),
        )
        with mock.patch(
            "triage.management.commands.sync_from_siem.httpx.get", return_value=fake
        ) as getter:
            call_command("sync_from_siem", url="http://siem.local", stdout=StringIO())
        getter.assert_called_once()
        # The command appends the export path to the base URL.
        self.assertEqual(
            getter.call_args.args[0], "http://siem.local/incidents/export.json"
        )
        self.assertEqual(Incident.objects.count(), 2)

    def test_url_http_error_becomes_command_error(self):
        with mock.patch(
            "triage.management.commands.sync_from_siem.httpx.get",
            side_effect=httpx.ConnectError("refused"),
        ):
            with self.assertRaisesRegex(CommandError, "Could not fetch"):
                call_command("sync_from_siem", url="http://siem.local", stdout=StringIO())

    def test_missing_file_becomes_command_error(self):
        with self.assertRaisesRegex(CommandError, "Could not read export file"):
            call_command("sync_from_siem", file="/no/such/export.json", stdout=StringIO())

    def test_invalid_json_becomes_command_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{ this is not json")
            path = f.name
        try:
            with self.assertRaisesRegex(CommandError, "Could not read export file"):
                call_command("sync_from_siem", file=path, stdout=StringIO())
        finally:
            Path(path).unlink()

    def test_non_list_payload_becomes_command_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"incident_id": "INC-1"}, f)  # an object, not a list
            path = f.name
        try:
            with self.assertRaisesRegex(CommandError, "must be a JSON list"):
                call_command("sync_from_siem", file=path, stdout=StringIO())
        finally:
            Path(path).unlink()

    def test_file_and_url_are_mutually_exclusive(self):
        with self.assertRaises(CommandError):
            call_command("sync_from_siem", stdout=StringIO())  # neither given
