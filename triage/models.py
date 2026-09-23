"""Domain models for the SOC triage console.

An analyst works incidents that were detected upstream (in the mini-SIEM), so
`Incident` and `Alert` mirror that upstream data and carry an external id, while
`TriageNote` and `AuditEntry` are this app's own: the human work of triage and an
append-only trail of who changed what.
"""

from django.conf import settings
from django.db import models


class Incident(models.Model):
    """One incident under triage, keyed to its upstream id from the mini-SIEM."""

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"

    class Status(models.TextChoices):
        NEW = "new", "New"
        TRIAGED = "triaged", "Triaged"
        ESCALATED = "escalated", "Escalated"
        CLOSED = "closed", "Closed"

    # The upstream identifier (e.g. "INC-0003"); unique so a re-sync updates the
    # existing row rather than duplicating it.
    incident_id = models.CharField(max_length=64, unique=True)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    score = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    summary = models.TextField(blank=True)
    source_ips = models.JSONField(default=list, blank=True)
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_incidents",
    )
    created_at = models.DateTimeField(help_text="When the SIEM created the incident")
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-score", "severity"]

    def __str__(self) -> str:
        return f"{self.incident_id} [{self.severity}]"


class Alert(models.Model):
    """An alert that rolled up into an incident; read-only mirror of SIEM data."""

    incident = models.ForeignKey(Incident, related_name="alerts", on_delete=models.CASCADE)
    rule_id = models.CharField(max_length=64)
    rule_name = models.CharField(max_length=255)
    severity = models.CharField(max_length=16)
    mitre_technique_id = models.CharField(max_length=32, blank=True)

    def __str__(self) -> str:
        return self.rule_id


class TriageNote(models.Model):
    """An analyst's note on an incident."""

    incident = models.ForeignKey(Incident, related_name="notes", on_delete=models.CASCADE)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]


class AuditEntry(models.Model):
    """Append-only record of a status change.

    Nothing edits or deletes these: the triage history is evidence, so a status
    change writes one row here and never touches an existing one.
    """

    incident = models.ForeignKey(Incident, related_name="audit", on_delete=models.CASCADE)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    from_status = models.CharField(max_length=16)
    to_status = models.CharField(max_length=16)
    at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-at"]
        verbose_name_plural = "audit entries"

    def __str__(self) -> str:
        return f"{self.incident.incident_id}: {self.from_status} -> {self.to_status}"


def _attachment_upload_to(instance: "Attachment", filename: str) -> str:
    return f"attachments/{instance.incident.incident_id}/{filename}"


class Attachment(models.Model):
    """An evidence file an analyst attaches to an incident (pcap, screenshot, log)."""

    incident = models.ForeignKey(
        Incident, related_name="attachments", on_delete=models.CASCADE
    )
    file = models.FileField(upload_to=_attachment_upload_to)
    original_name = models.CharField(max_length=255)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-uploaded_at"]

    def __str__(self) -> str:
        return self.original_name
