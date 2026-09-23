"""The transition permission table -- the one rule with real weight.

An L1 analyst may triage, escalate, and close an incident that is still in
triage; only an L2 (or a superuser) may close one that has been escalated.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase

from triage.transitions import allowed_targets, can_transition, is_l2

User = get_user_model()


class TransitionRuleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        l1 = Group.objects.create(name="L1")
        l2 = Group.objects.create(name="L2")
        cls.analyst = User.objects.create_user("analyst", password="x")
        cls.analyst.groups.add(l1)
        cls.lead = User.objects.create_user("lead", password="x")
        cls.lead.groups.add(l2)
        cls.admin = User.objects.create_superuser("root", password="x")

    def test_is_l2(self):
        self.assertFalse(is_l2(self.analyst))
        self.assertTrue(is_l2(self.lead))
        self.assertTrue(is_l2(self.admin))  # superuser counts as every role

    def test_l1_open_transitions(self):
        self.assertEqual(allowed_targets(self.analyst, "new"), ["triaged"])
        self.assertCountEqual(
            allowed_targets(self.analyst, "triaged"), ["escalated", "closed"]
        )

    def test_l1_cannot_close_escalated(self):
        self.assertEqual(allowed_targets(self.analyst, "escalated"), [])
        self.assertFalse(can_transition(self.analyst, "escalated", "closed"))

    def test_l2_can_close_escalated(self):
        self.assertEqual(allowed_targets(self.lead, "escalated"), ["closed"])
        self.assertTrue(can_transition(self.lead, "escalated", "closed"))

    def test_superuser_can_close_escalated(self):
        self.assertTrue(can_transition(self.admin, "escalated", "closed"))

    def test_illegal_and_unknown_transitions_are_refused(self):
        # A jump that is not in the table at all.
        self.assertFalse(can_transition(self.lead, "new", "closed"))
        # Backwards.
        self.assertFalse(can_transition(self.lead, "closed", "new"))
        # From a status that does not exist.
        self.assertEqual(allowed_targets(self.lead, "bogus"), [])
        self.assertFalse(can_transition(self.lead, "triaged", ""))
