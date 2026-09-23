"""DRF serializers for the read-only API.

Read-only by intent: the API exposes incident data and metrics to external
systems (a dashboard, a SOAR, a reporting job); triage actions stay in the
login-gated web UI where the role rules are enforced.
"""

from rest_framework import serializers

from .models import Alert, Incident


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ["rule_id", "rule_name", "severity", "mitre_technique_id"]


class IncidentSerializer(serializers.ModelSerializer):
    alerts = AlertSerializer(many=True, read_only=True)
    assignee = serializers.CharField(
        source="assignee.username", default=None, read_only=True
    )

    class Meta:
        model = Incident
        fields = [
            "incident_id", "title", "severity", "score", "status", "summary",
            "source_ips", "assignee", "created_at", "alerts",
        ]
