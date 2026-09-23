"""Who may move an incident from one status to another.

The rules live here, not scattered across views, so the triage workflow is
reviewable in one place: what transitions exist at all, and which role each one
needs. Roles are Django groups: an analyst in "L2" is senior to one in "L1".

The one rule that carries weight: closing an escalated incident is L2-only. An
L1 can raise and escalate, but signing off that an escalation is resolved is a
senior decision, and the view enforces it through this table rather than through
a hidden button.
"""

from __future__ import annotations

# from_status -> {to_status: required_group_or_None}
# None means any authenticated analyst may perform it.
_TRANSITIONS: dict[str, dict[str, str | None]] = {
    "new": {"triaged": None},
    "triaged": {"escalated": None, "closed": None},
    "escalated": {"closed": "L2"},
}


def _has_role(user, group_name: str) -> bool:
    """True if ``user`` is in ``group_name`` (a superuser counts as every role)."""
    return user.is_superuser or user.groups.filter(name=group_name).exists()


def is_l2(user) -> bool:
    return _has_role(user, "L2")


def allowed_targets(user, current_status: str) -> list[str]:
    """Status values ``user`` may move an incident to from ``current_status``."""
    targets = []
    for to_status, required in _TRANSITIONS.get(current_status, {}).items():
        if required is None or _has_role(user, required):
            targets.append(to_status)
    return targets


def can_transition(user, current_status: str, to_status: str) -> bool:
    return to_status in allowed_targets(user, current_status)
