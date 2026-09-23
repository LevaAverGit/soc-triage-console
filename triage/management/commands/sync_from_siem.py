"""Load incidents into the triage console from the mini-SIEM.

Two sources, same JSON shape (a list of incidents, each with an embedded
``alerts`` list):

    manage.py sync_from_siem --file exports/incidents.json
    manage.py sync_from_siem --url http://127.0.0.1:8000

``--url`` fetches ``<url>/incidents/export.json`` over REST (httpx); ``--file``
reads a local export. The actual create/update happens in ``triage.ingest`` so it
is unit-tested without either source.
"""

from __future__ import annotations

import json

import httpx
from django.core.management.base import BaseCommand, CommandError

from triage.ingest import ingest_incidents


class Command(BaseCommand):
    help = "Sync incidents into the triage console from a mini-SIEM export (URL or file)."

    def add_arguments(self, parser):
        source = parser.add_mutually_exclusive_group(required=True)
        source.add_argument("--file", help="Path to a JSON export of incidents")
        source.add_argument("--url", help="Base URL of the mini-SIEM to fetch the export from")
        parser.add_argument("--timeout", type=float, default=10.0)

    def handle(self, *args, **options):
        if options["file"]:
            try:
                with open(options["file"], encoding="utf-8") as f:
                    records = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                raise CommandError(f"Could not read export file: {exc}") from exc
        else:
            url = options["url"].rstrip("/") + "/incidents/export.json"
            try:
                response = httpx.get(url, timeout=options["timeout"])
                response.raise_for_status()
                records = response.json()
            except httpx.HTTPError as exc:
                raise CommandError(f"Could not fetch from the mini-SIEM: {exc}") from exc

        if not isinstance(records, list):
            raise CommandError("Export must be a JSON list of incidents.")

        result = ingest_incidents(records)
        self.stdout.write(self.style.SUCCESS(
            f"Synced: {result.created} created, {result.updated} updated."
        ))
