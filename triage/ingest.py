"""Turn mini-SIEM incident data into triage rows.

Kept separate from the management command so it can be unit-tested directly with
a list of dicts, without a database fixture file or a live SIEM. The command is a
thin wrapper that reads the same list from a URL or a file and hands it here.

Upsert semantics: an incident is matched by its ``incident_id``, so re-running a
sync updates the existing row (and replaces its alert mirror) instead of
duplicating it. A locally-changed ``status`` is preserved on re-sync -- triage
state belongs to this app, not to the upstream feed.

Upstream data is untrusted: fields are coerced to sane values, and each record
is processed in its own savepoint so a single malformed incident is rolled back
and counted in ``skipped`` rather than aborting the whole sync.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import Alert, Incident


@dataclass
class SyncResult:
    created: int = 0
    updated: int = 0
    skipped: int = 0


_VALID_SEVERITY = set(Incident.Severity.values)


def _coerce_score(value) -> int:
    """Best-effort non-negative small int; unparsable or negative -> 0.

    Upstream may deliver a risk score as an int, a float, or a string; the model
    field is a non-negative small int, so clamp anything odd instead of crashing.
    """
    try:
        n = int(float(value))
    except (TypeError, ValueError):
        return 0
    return max(0, n)


def _parse_created(value):
    """Parse an ISO timestamp, tolerating empty, garbage, and out-of-range input.

    ``parse_datetime`` returns None for unparseable input but *raises* ValueError
    for a well-formed-but-impossible value like ``2026-13-01T..``; treat both as
    "no usable timestamp".
    """
    try:
        return parse_datetime(value or "")
    except (TypeError, ValueError):
        return None


def ingest_incidents(records: list[dict]) -> SyncResult:
    """Create or update incidents (with their alerts) from ``records``."""
    result = SyncResult()
    for rec in records:
        incident_id = rec.get("incident_id")
        if not incident_id:
            result.skipped += 1
            continue
        try:
            with transaction.atomic():
                outcome = _ingest_one(rec, incident_id)
        except (ValueError, TypeError, IntegrityError):
            # One bad record must not drop the rest of the batch.
            result.skipped += 1
            continue
        if outcome == "created":
            result.created += 1
        else:
            result.updated += 1
    return result


def _ingest_one(rec: dict, incident_id: str) -> str:
    """Upsert a single incident and its alerts; return "created" or "updated"."""
    severity = str(rec.get("severity", "")).lower()
    if severity not in _VALID_SEVERITY:
        severity = Incident.Severity.LOW

    defaults = {
        "title": rec.get("title") or "",
        "severity": severity,
        "score": _coerce_score(rec.get("score")),
        "summary": rec.get("summary") or "",
        "source_ips": rec.get("source_ips") or [],
    }
    # created_at is required; if upstream omits it, fall back to sync time on
    # create, but never clobber a real timestamp with the fallback on re-sync.
    parsed_created = _parse_created(rec.get("created_at"))

    incident, created = Incident.objects.get_or_create(
        incident_id=incident_id,
        defaults={**defaults, "created_at": parsed_created or timezone.now()},
    )
    if created:
        outcome = "created"
    else:
        # Update mirrored fields but never overwrite the analyst's status.
        for field, value in defaults.items():
            setattr(incident, field, value)
        if parsed_created is not None:
            incident.created_at = parsed_created
        incident.save()
        outcome = "updated"

    # Replace the alert mirror wholesale: it is read-only upstream data.
    incident.alerts.all().delete()
    Alert.objects.bulk_create([
        Alert(
            incident=incident,
            rule_id=a.get("rule_id", ""),
            rule_name=a.get("rule_name", ""),
            severity=str(a.get("severity", "")).lower(),
            mitre_technique_id=a.get("mitre_technique_id", "") or "",
        )
        for a in rec.get("alerts", []) or []
    ])
    return outcome
