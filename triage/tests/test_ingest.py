"""Ingest / upsert behaviour: the boundary where upstream SIEM data becomes
triage rows. The rule that matters is that a re-sync updates mirrored fields but
never overwrites the analyst's local status.
"""

from django.test import TestCase

from triage.ingest import ingest_incidents
from triage.models import Alert, Incident


def _record(**over):
    rec = {
        "incident_id": "INC-0001",
        "title": "Brute force against SSH",
        "severity": "high",
        "score": 72,
        "summary": "Repeated failed logins.",
        "source_ips": ["10.0.0.5"],
        "created_at": "2026-09-20T10:00:00Z",
        "alerts": [
            {"rule_id": "R1", "rule_name": "SSH brute force",
             "severity": "high", "mitre_technique_id": "T1110"},
        ],
    }
    rec.update(over)
    return rec


class IngestTests(TestCase):
    def test_create_new_incident_with_alerts(self):
        result = ingest_incidents([_record()])
        self.assertEqual(result.created, 1)
        self.assertEqual(result.updated, 0)
        inc = Incident.objects.get(incident_id="INC-0001")
        self.assertEqual(inc.severity, "high")
        self.assertEqual(inc.score, 72)
        self.assertEqual(inc.source_ips, ["10.0.0.5"])
        self.assertEqual(inc.status, Incident.Status.NEW)
        self.assertEqual(inc.alerts.count(), 1)

    def test_resync_updates_fields_but_preserves_status(self):
        ingest_incidents([_record()])
        inc = Incident.objects.get(incident_id="INC-0001")
        inc.status = Incident.Status.ESCALATED
        inc.save(update_fields=["status"])

        result = ingest_incidents([_record(score=95, title="Brute force (updated)")])
        self.assertEqual(result.created, 0)
        self.assertEqual(result.updated, 1)
        inc.refresh_from_db()
        self.assertEqual(inc.score, 95)                      # mirrored field updated
        self.assertEqual(inc.title, "Brute force (updated)")
        self.assertEqual(inc.status, Incident.Status.ESCALATED)  # analyst state kept

    def test_alert_mirror_is_replaced_wholesale(self):
        ingest_incidents([_record()])
        ingest_incidents([_record(alerts=[
            {"rule_id": "R2", "rule_name": "New rule", "severity": "medium",
             "mitre_technique_id": ""},
        ])])
        inc = Incident.objects.get(incident_id="INC-0001")
        self.assertEqual([a.rule_id for a in inc.alerts.all()], ["R2"])
        self.assertEqual(Alert.objects.count(), 1)  # old alert gone, not orphaned

    def test_invalid_severity_falls_back_to_low(self):
        ingest_incidents([_record(severity="catastrophic")])
        self.assertEqual(
            Incident.objects.get(incident_id="INC-0001").severity,
            Incident.Severity.LOW,
        )

    def test_records_without_incident_id_are_skipped(self):
        result = ingest_incidents([_record(incident_id=""), {"severity": "low"}])
        self.assertEqual(result.created, 0)
        self.assertEqual(Incident.objects.count(), 0)

    def test_missing_optional_fields_do_not_crash(self):
        result = ingest_incidents([{"incident_id": "INC-9", "severity": "low"}])
        self.assertEqual(result.created, 1)
        inc = Incident.objects.get(incident_id="INC-9")
        self.assertEqual(inc.summary, "")
        self.assertEqual(inc.source_ips, [])
        self.assertEqual(inc.score, 0)

    def test_explicit_null_fields_are_coerced_not_crash(self):
        # A present-but-null value must not violate a non-null column.
        result = ingest_incidents([_record(title=None, summary=None, source_ips=None)])
        self.assertEqual(result.created, 1)
        inc = Incident.objects.get(incident_id="INC-0001")
        self.assertEqual(inc.title, "")
        self.assertEqual(inc.summary, "")
        self.assertEqual(inc.source_ips, [])

    def test_score_is_coerced(self):
        ingest_incidents([
            _record(incident_id="A", score="72.5"),   # string float
            _record(incident_id="B", score="n/a"),     # non-numeric
            _record(incident_id="C", score=-5),         # negative
        ])
        self.assertEqual(Incident.objects.get(incident_id="A").score, 72)
        self.assertEqual(Incident.objects.get(incident_id="B").score, 0)
        self.assertEqual(Incident.objects.get(incident_id="C").score, 0)

    def test_impossible_created_at_falls_back_instead_of_crashing(self):
        # A well-formed but out-of-range date makes parse_datetime raise.
        result = ingest_incidents([_record(created_at="2026-13-01T10:00:00Z")])
        self.assertEqual(result.created, 1)
        self.assertIsNotNone(Incident.objects.get(incident_id="INC-0001").created_at)

    def test_one_bad_record_does_not_abort_the_batch(self):
        # A non-JSON-serializable source_ips (a set) blows up at save time; the
        # record is rolled back and skipped, and the good records still land.
        records = [
            _record(incident_id="GOOD-1"),
            _record(incident_id="BAD", source_ips={"10.0.0.9"}),
            _record(incident_id="GOOD-2"),
        ]
        result = ingest_incidents(records)
        self.assertEqual(result.created, 2)
        self.assertEqual(result.skipped, 1)
        self.assertFalse(Incident.objects.filter(incident_id="BAD").exists())
        self.assertTrue(Incident.objects.filter(incident_id="GOOD-2").exists())

    def test_records_without_incident_id_count_as_skipped(self):
        result = ingest_incidents([{"severity": "low"}, _record(incident_id="")])
        self.assertEqual(result.skipped, 2)
        self.assertEqual(result.created, 0)
