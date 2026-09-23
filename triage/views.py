"""Views for the triage console: an incident queue, a detail page, and the two
actions an analyst takes on an incident (add a note, change its status).

Everything is login-gated. The status change is the only privileged action, and
it is checked twice: the template only offers the transitions this user may make,
and the POST handler re-checks server-side, so a hand-crafted request cannot
bypass the rule.
"""

from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.generic import DetailView, ListView

from .models import Attachment, AuditEntry, Incident, TriageNote
from .transitions import allowed_targets, can_transition

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024  # 10 MB


class IncidentListView(LoginRequiredMixin, ListView):
    """The queue: incidents filtered by severity/status, paginated."""

    model = Incident
    template_name = "triage/incident_list.html"
    context_object_name = "incidents"
    paginate_by = 20

    def get_queryset(self):
        qs = super().get_queryset()
        severity = self.request.GET.get("severity")
        status = self.request.GET.get("status")
        if severity in Incident.Severity.values:
            qs = qs.filter(severity=severity)
        if status in Incident.Status.values:
            qs = qs.filter(status=status)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["severities"] = Incident.Severity.choices
        ctx["statuses"] = Incident.Status.choices
        ctx["active_severity"] = self.request.GET.get("severity", "")
        ctx["active_status"] = self.request.GET.get("status", "")
        return ctx


class IncidentDetailView(LoginRequiredMixin, DetailView):
    model = Incident
    template_name = "triage/incident_detail.html"
    context_object_name = "incident"
    slug_field = "incident_id"
    slug_url_kwarg = "incident_id"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["targets"] = allowed_targets(self.request.user, self.object.status)
        ctx["notes"] = self.object.notes.select_related("author")
        ctx["audit"] = self.object.audit.select_related("actor")
        ctx["attachments"] = self.object.attachments.select_related("uploaded_by")
        return ctx


@login_required
def change_status(request, incident_id):
    """Move an incident to a new status, if this analyst is allowed to.

    The transition is validated against ``transitions.py`` server-side, and a
    successful change writes one append-only ``AuditEntry``. A disallowed request
    is refused with a message, not silently ignored.
    """
    incident = get_object_or_404(Incident, incident_id=incident_id)
    if request.method != "POST":
        return redirect("incident-detail", incident_id=incident_id)

    to_status = request.POST.get("to_status", "")
    if not can_transition(request.user, incident.status, to_status):
        messages.error(
            request,
            f"You may not move {incident.incident_id} from "
            f"{incident.status} to {to_status or '(none)'}.",
        )
        return redirect("incident-detail", incident_id=incident_id)

    from_status = incident.status
    incident.status = to_status
    incident.save(update_fields=["status", "synced_at"])
    AuditEntry.objects.create(
        incident=incident,
        actor=request.user,
        from_status=from_status,
        to_status=to_status,
    )
    messages.success(request, f"{incident.incident_id}: {from_status} -> {to_status}.")
    return redirect("incident-detail", incident_id=incident_id)


@login_required
def assign(request, incident_id):
    """Take an incident (assign it to yourself) or release it.

    POST ``action=take`` sets the assignee to the current analyst; ``release``
    clears it. Kept deliberately simple: ownership is a claim an analyst makes,
    not a scheduling system.
    """
    incident = get_object_or_404(Incident, incident_id=incident_id)
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "take":
            incident.assignee = request.user
            incident.save(update_fields=["assignee", "synced_at"])
            messages.success(request, f"{incident.incident_id} assigned to you.")
        elif action == "release":
            incident.assignee = None
            incident.save(update_fields=["assignee", "synced_at"])
            messages.success(request, f"{incident.incident_id} released.")
    return redirect("incident-detail", incident_id=incident_id)


@login_required
def upload_attachment(request, incident_id):
    """Attach an evidence file (pcap, screenshot, log) to an incident."""
    incident = get_object_or_404(Incident, incident_id=incident_id)
    if request.method == "POST":
        upload = request.FILES.get("file")
        if upload is None:
            messages.error(request, "No file selected.")
        elif upload.size > MAX_ATTACHMENT_BYTES:
            messages.error(request, "File too large (max 10 MB).")
        else:
            Attachment.objects.create(
                incident=incident,
                file=upload,
                original_name=upload.name[:255],
                uploaded_by=request.user,
            )
            messages.success(request, f"Attached {upload.name}.")
    return redirect("incident-detail", incident_id=incident_id)


@login_required
def add_note(request, incident_id):
    incident = get_object_or_404(Incident, incident_id=incident_id)
    if request.method == "POST":
        body = (request.POST.get("body") or "").strip()
        if body:
            TriageNote.objects.create(incident=incident, author=request.user, body=body)
            messages.success(request, "Note added.")
        else:
            messages.error(request, "A note cannot be empty.")
    return redirect("incident-detail", incident_id=incident_id)
