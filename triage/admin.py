"""Django admin registration.

The admin is a genuine part of the tool here, not an afterthought: a SOC lead
uses it to review incidents and read the audit trail. Audit entries are shown
read-only, because the whole point of that model is that nobody edits history.
"""

from django.contrib import admin

from .models import Alert, Attachment, AuditEntry, Incident, TriageNote


class AlertInline(admin.TabularInline):
    model = Alert
    extra = 0


class NoteInline(admin.TabularInline):
    model = TriageNote
    extra = 0
    readonly_fields = ("author", "created_at")


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("incident_id", "severity", "score", "status", "assignee", "created_at")
    list_filter = ("severity", "status")
    search_fields = ("incident_id", "title", "summary")
    inlines = [AlertInline, NoteInline]


@admin.register(AuditEntry)
class AuditEntryAdmin(admin.ModelAdmin):
    list_display = ("incident", "from_status", "to_status", "actor", "at")
    list_filter = ("to_status",)
    # History is evidence: visible in the admin, never editable through it.
    readonly_fields = ("incident", "actor", "from_status", "to_status", "at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        # Append-only: history is evidence, so not even a superuser deletes it here.
        return False


admin.site.register(TriageNote)


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    list_display = ("original_name", "incident", "uploaded_by", "uploaded_at")
    list_filter = ("uploaded_at",)
    readonly_fields = ("uploaded_at",)
