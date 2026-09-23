"""Read-only REST API (Django REST Framework).

    GET /api/incidents/            list incidents (filter ?severity= ?status=)
    GET /api/incidents/<id>/       one incident with its alerts
    GET /api/metrics/              counts by severity and status

Authenticated read access only -- external systems consume incident data and
metrics here, while the privileged triage actions live in the web UI.
"""

from django.db.models import Count
from rest_framework import permissions, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Incident
from .serializers import IncidentSerializer


class IncidentViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = IncidentSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "incident_id"

    def get_queryset(self):
        qs = Incident.objects.prefetch_related("alerts").select_related("assignee")
        severity = self.request.query_params.get("severity")
        status = self.request.query_params.get("status")
        if severity in Incident.Severity.values:
            qs = qs.filter(severity=severity)
        if status in Incident.Status.values:
            qs = qs.filter(status=status)
        return qs


class MetricsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        qs = Incident.objects.all()
        return Response({
            "total": qs.count(),
            "by_severity": {
                row["severity"]: row["n"]
                for row in qs.values("severity").annotate(n=Count("id"))
            },
            "by_status": {
                row["status"]: row["n"]
                for row in qs.values("status").annotate(n=Count("id"))
            },
        })
