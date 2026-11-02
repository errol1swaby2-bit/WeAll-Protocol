"""PR77 non-authoritative ban-state consistency candidate boundary tests."""

from __future__ import annotations

import copy
import unittest

from tooling.ban_state_contract_candidate import STATUS, review_ban_state_candidate


def _state(*, account_banned: bool, index_banned: bool | None) -> dict:
    bans = {}
    if index_banned is not None:
        bans["@target"] = {
            "account_id": "@target",
            "banned": index_banned,
            "auto": True,
            "set_at_nonce": 7,
            "reason": "synthetic",
        }
    return {
        "accounts": {"@target": {"banned": account_banned}},
        "reputation": {"bans": bans},
        "height": 20,
    }


def _check(state: dict) -> dict:
    return review_ban_state_candidate(state, account_id="@target")


class BanStateCandidateTests(unittest.TestCase):
    def test_clear_account_with_active_index_is_detected_without_mutation(self) -> None:
        state = _state(account_banned=False, index_banned=True)
        before = copy.deepcopy(state)
        result = _check(state)
        self.assertEqual(result["classification"], "DIVERGENT_ACCOUNT_CLEAR_INDEX_ACTIVE")
        self.assertEqual(result["status"], STATUS)
        self.assertEqual(result["observed"]["ban_index_auto"], True)
        self.assertEqual(state, before)
        self.assertFalse(result["may_apply_transition"])

    def test_active_account_with_clear_index_is_distinct(self) -> None:
        result = _check(_state(account_banned=True, index_banned=False))
        self.assertEqual(result["classification"], "DIVERGENT_ACCOUNT_ACTIVE_INDEX_CLEAR")

    def test_consistent_active_and_clear_are_observations_not_permissions(self) -> None:
        for banned in (False, True):
            with self.subTest(banned=banned):
                result = _check(_state(account_banned=banned, index_banned=banned))
                self.assertEqual(result["classification"], "CONSISTENT_ACTIVE" if banned else "CONSISTENT_CLEAR")
                self.assertEqual(result["constitutional_authorization"], "NOT_ESTABLISHED")
                self.assertFalse(result["may_enqueue_system_tx"])
                self.assertFalse(result["may_activate_new_policy"])

    def test_missing_index_is_not_implicitly_repaired(self) -> None:
        for banned in (False, True):
            with self.subTest(banned=banned):
                state = _state(account_banned=banned, index_banned=None)
                original = copy.deepcopy(state)
                result = _check(state)
                self.assertEqual(
                    result["classification"],
                    "INDEX_ABSENT_ACCOUNT_ACTIVE" if banned else "INDEX_ABSENT_ACCOUNT_CLEAR",
                )
                self.assertEqual(state, original)

    def test_missing_account_is_not_imputed_from_ban_index(self) -> None:
        state = _state(account_banned=False, index_banned=True)
        state["accounts"].clear()
        result = _check(state)
        self.assertEqual(result["classification"], "ACCOUNT_NOT_FOUND")
        self.assertIsNone(result["observed"]["account_banned"])

    def test_string_account_flag_does_not_count_as_boolean(self) -> None:
        state = _state(account_banned=False, index_banned=True)
        state["accounts"]["@target"]["banned"] = "false"
        result = _check(state)
        self.assertEqual(result["classification"], "ACCOUNT_BAN_FLAG_MISSING_OR_INVALID")
        self.assertIsNone(result["observed"]["account_banned"])

    def test_invalid_index_record_is_not_silently_accepted(self) -> None:
        state = _state(account_banned=False, index_banned=True)
        state["reputation"]["bans"]["@target"] = ["not-a-record"]
        result = _check(state)
        self.assertEqual(result["classification"], "BAN_INDEX_RECORD_INVALID")
        self.assertFalse(result["observed"]["ban_index_present"])

    def test_invalid_index_flag_is_not_silently_accepted(self) -> None:
        state = _state(account_banned=False, index_banned=True)
        state["reputation"]["bans"]["@target"]["banned"] = "true"
        result = _check(state)
        self.assertEqual(result["classification"], "BAN_INDEX_FLAG_MISSING_OR_INVALID")
        self.assertIsNone(result["observed"]["ban_index_banned"])

    def test_pretend_juror_approval_does_not_turn_review_into_authority(self) -> None:
        state = _state(account_banned=False, index_banned=True)
        state["disputes_by_id"] = {
            "fake": {
                "initial_yes": 25,
                "appeal_yes": 25,
                "appeal_waived": True,
                "finalized": True,
            }
        }
        first = _check(state)
        second = _check(copy.deepcopy(state))
        self.assertEqual(first, second)
        self.assertFalse(first["may_apply_transition"])
        self.assertFalse(first["may_enqueue_system_tx"])
        self.assertEqual(first["constitutional_authorization"], "NOT_ESTABLISHED")

    def test_no_history_is_conjured_from_overwritten_index(self) -> None:
        result = _check(_state(account_banned=True, index_banned=True))
        self.assertTrue(
            result["implementation_observation"]["ban_index_is_not_append_only_event_history"]
        )
        self.assertFalse(
            result["implementation_observation"]["full_authoritative_sanction_model_established"]
        )


if __name__ == "__main__":
    unittest.main()
