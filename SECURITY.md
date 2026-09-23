# Security

This is a portfolio / demo project, not a production deployment. It ships with
development defaults that are deliberately insecure and must be changed before
running anywhere real.

## Not safe for production as-is

- `DEBUG = True` and a hard-coded `SECRET_KEY` live in `config/settings.py`.
  Set `DEBUG = False`, load `SECRET_KEY` from the environment, and fill
  `ALLOWED_HOSTS` before exposing the app.
- The `bootstrap_demo` command creates users with well-known demo passwords
  (`analyst-demo`, `lead-demo`). These exist only to make the demo runnable and
  must never be used on a reachable instance.
- SQLite is used for zero-setup local runs; use a managed database in production.

## What the app does enforce

- Every view is login-gated (`LoginRequiredMixin` / `@login_required`).
- The privileged action -- changing an incident's status -- is authorised
  server-side against the transition table in `triage/transitions.py`, not just
  by hiding the button. Closing an *escalated* incident is L2-only, and a
  hand-crafted POST from an L1 is refused (see `tests/test_views.py`).
- Status changes are recorded in an append-only `AuditEntry`; the admin exposes
  those entries read-only, with add, change, and delete permissions all disabled
  (even for a superuser) so the trail cannot be tampered with through the admin.
- CSRF protection is on for every form (Django default middleware).

## Reporting

Found something? Open an issue, or email levaaverianov@gmail.com.
