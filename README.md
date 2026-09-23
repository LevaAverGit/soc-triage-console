# SOC Triage Console

A small Django application for the human side of a SOC: an analyst signs in,
works a queue of incidents that were detected upstream, reads the alerts and
MITRE techniques behind each one, adds notes, and moves incidents through a
triage lifecycle — with role-based rules and an append-only audit trail.

It is the downstream half of a two-part setup: a detection engine (the
[mini-SIEM detection lab](https://github.com/LevaAverGit/mini-siem-detection-lab-v2))
produces incidents; this console is where people triage them. The two are
connected over a small REST sync, so the console also runs standalone from a
bundled export.

## Why this exists

Detection tooling produces incidents; a SOC still needs a place for analysts to
*work* them. This project models that workflow with the parts that actually
matter in a real console:

- **A lifecycle with teeth.** `new → triaged → escalated → closed`, where
  closing an *escalated* incident is a senior (L2) decision. The rule is defined
  in one place and enforced **server-side**, not by hiding a button.
- **An audit trail.** Every status change writes an append-only record of who
  changed what, when. The admin shows it read-only.
- **A clean upstream boundary.** Incidents mirror SIEM data and can be re-synced,
  but a re-sync never overwrites the analyst's local triage state.

## Triage lifecycle

```
        any analyst        any analyst           L2 / lead only
 new ───────────────► triaged ───────────► escalated ───────────► closed
                         │                                          ▲
                         └──────────────── any analyst ─────────────┘
```

The transition table lives in [`triage/transitions.py`](triage/transitions.py);
the view checks it on every POST, and the templates only render the moves the
current user is allowed to make.

## Roles

Roles are Django groups:

| Role | Group | May do |
|------|-------|--------|
| Analyst (L1) | `L1` | triage, escalate, close a *triaged* incident, take/release an incident, add notes |
| Lead (L2)    | `L2` | everything L1 can, **plus** close an *escalated* incident, and reach the Django admin (incl. the read-only audit trail) |

A superuser counts as every role.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python manage.py migrate
python manage.py bootstrap_demo      # roles, demo users, sample incidents
python manage.py runserver
```

Open http://127.0.0.1:8000/ and sign in with a demo account:

| Username | Password | Role |
|----------|----------|------|
| `analyst` | `analyst-demo` | L1 |
| `lead`    | `lead-demo`    | L2 |

> Demo credentials are for local use only. See [SECURITY.md](SECURITY.md).

Sign in as `analyst`, escalate an incident, then notice you cannot close it.
Sign in as `lead` and you can — that is the one rule this project is built to
demonstrate, end to end. `lead` can also open the Django admin at `/admin/`; for
unrestricted admin access, create a superuser with `python manage.py createsuperuser`.

## Syncing incidents from the mini-SIEM

`bootstrap_demo` loads the bundled [`exports/incidents.json`](exports/incidents.json).
To pull fresh data instead, use the sync command directly:

```bash
# from a file
python manage.py sync_from_siem --file exports/incidents.json

# over REST from a running mini-SIEM (GET <url>/incidents/export.json)
python manage.py sync_from_siem --url http://127.0.0.1:8000
```

Sync is an **upsert** keyed on `incident_id`: re-running it updates mirrored
fields and replaces the alert mirror, but preserves any status an analyst has
set. The create/update logic lives in [`triage/ingest.py`](triage/ingest.py),
separate from the command, so it is unit-tested without a live SIEM.

## Architecture

```
config/            project settings, root URLs, auth (login/logout) wiring
triage/
  models.py        Incident, Alert, TriageNote, AuditEntry
  transitions.py   the role-based transition table + permission checks
  views.py         login-gated queue (ListView), detail (DetailView),
                   status change + add-note (function views)
  ingest.py        upsert incidents/alerts from SIEM records
  admin.py         SOC-lead admin; audit entries read-only
  management/commands/
    sync_from_siem.py   load incidents from --file or --url
    bootstrap_demo.py   one-command demo: roles, users, sample data
  tests/           transitions, ingest, views, commands, models
templates/         dark SOC theme: queue, incident detail, login
```

### What it demonstrates

- **Data modelling & migrations** — four related models, a JSON field, choices,
  meaningful `Meta.ordering`, an append-only audit model.
- **Class-based and function views** — `ListView`/`DetailView` for read paths,
  function views for the two write actions.
- **Authorisation done properly** — permission logic isolated in one module and
  enforced server-side; the UI reflects it rather than defining it. A test
  crafts a forbidden POST directly to prove the button is not the control.
- **Django admin** as a real operator tool, with history made read-only.
- **Management commands** for sync and demo bootstrap.
- **REST integration** — `httpx` fetch of a SIEM export, with the parsing logic
  kept testable in isolation.

## Tests

```bash
python manage.py test
```

42 tests cover the transition rules (including that an L1 cannot close an
escalated incident, by table logic *and* by direct POST), the ingest upsert,
status-preservation and its handling of malformed upstream data (a bad record is
skipped, not fatal), the SIEM sync command over both `--file` and a mocked
`--url` REST fetch plus each of its error paths, view access control, filtering,
the take/release assignment, and the demo bootstrap. CI runs the suite plus
`manage.py check` and a migration-drift check on every push — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## License

MIT — see [LICENSE](LICENSE).
