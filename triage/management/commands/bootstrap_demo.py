"""Set up a demo instance in one command: roles, users, and sample incidents.

Creates the two analyst roles (``L1``, ``L2``) as Django groups, a demo user in
each, and -- unless ``--no-data`` is given -- loads the bundled incident export
so the queue is not empty on first run. Everything is idempotent: re-running it
does not duplicate groups or users, and passwords are reset to the demo values.

    manage.py bootstrap_demo

Demo credentials (development only -- never ship these):
    analyst / analyst-demo   (L1: may triage, escalate, close-from-triaged)
    lead    / lead-demo      (L2: may also close an escalated incident; can
                              reach the Django admin, incl. the read-only audit)
"""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import transaction

_DEMO_USERS = [
    # username, password, group, is_staff (so L2 can reach the admin)
    ("analyst", "analyst-demo", "L1", False),
    ("lead", "lead-demo", "L2", True),
]

# Admin model permissions for the L2 (SOC lead) group, so the read-only audit
# trail and the incident admin are actually reachable as `lead`. AuditEntryAdmin
# blocks add/change/delete itself, so `view_auditentry` is enough to read it.
_L2_PERMISSIONS = [
    "view_incident", "change_incident",
    "view_alert",
    "view_triagenote", "change_triagenote", "delete_triagenote",
    "view_auditentry",
]

_EXPORT = Path(settings.BASE_DIR) / "exports" / "incidents.json"


class Command(BaseCommand):
    help = "Create demo roles, users, and (optionally) sample incidents."

    def add_arguments(self, parser):
        parser.add_argument(
            "--no-data",
            action="store_true",
            help="Set up roles and users only; do not load the sample export.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        User = get_user_model()

        groups = {name: Group.objects.get_or_create(name=name)[0] for name in ("L1", "L2")}
        groups["L2"].permissions.set(
            Permission.objects.filter(
                content_type__app_label="triage", codename__in=_L2_PERMISSIONS
            )
        )

        for username, password, group_name, is_staff in _DEMO_USERS:
            user, _ = User.objects.get_or_create(username=username)
            user.is_staff = is_staff
            user.set_password(password)
            user.save()
            user.groups.set([groups[group_name]])
            self.stdout.write(f"user {username!r} ({group_name}) ready")

        if options["no_data"]:
            self.stdout.write(self.style.SUCCESS("Roles and users ready (no data loaded)."))
            return

        if _EXPORT.exists():
            call_command("sync_from_siem", file=str(_EXPORT))
        else:
            self.stdout.write(self.style.WARNING(
                f"No export at {_EXPORT}; skipping sample data."
            ))
        self.stdout.write(self.style.SUCCESS("Demo instance ready."))
