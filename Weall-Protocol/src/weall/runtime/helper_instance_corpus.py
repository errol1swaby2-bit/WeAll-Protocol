from __future__ import annotations

from typing import Any

Json = dict[str, Any]


def build_default_helper_instance_corpus() -> list[Json]:
    """Return deterministic exemplar transactions for concrete helper-safety proofs."""

    return [
        {"tx_type": "ACCOUNT_REGISTER", "payload": {"account_id": "@alice"}},
        {"tx_type": "ACCOUNT_KEY_ADD", "payload": {"account_id": "@alice", "key_id": "key-main"}},
        {"tx_type": "BALANCE_TRANSFER", "payload": {"from_account_id": "@alice", "to_account_id": "@bob"}},
        {"tx_type": "FEE_PAY", "payload": {"from_account_id": "@alice", "to_account_id": "@fees"}},
        {"tx_type": "POH_APPLICATION_SUBMIT", "payload": {"account_id": "@alice", "application_id": "app-001"}},
        {"tx_type": "CONTENT_POST_CREATE", "payload": {"account_id": "@alice", "post_id": "post-001"}},
        {"tx_type": "CONTENT_MEDIA_DECLARE", "payload": {"account_id": "@alice", "post_id": "post-001", "media_id": "media-001"}},
        {"tx_type": "CONTENT_COMMENT_CREATE", "payload": {"account_id": "@alice", "post_id": "post-001", "comment_id": "comment-001"}},
        {"tx_type": "NOTIFICATION_SUBSCRIBE", "payload": {"account_id": "@alice", "topic_id": "topic-news"}},
        {"tx_type": "CONTENT_SHARE_CREATE", "payload": {"account_id": "@alice", "share_id": "share-001"}},
        {"tx_type": "STORAGE_OFFER_CREATE", "payload": {"lease_id": "offer-001", "provider_id": "@alice"}},
        {"tx_type": "STORAGE_LEASE_CREATE", "payload": {"lease_id": "lease-001", "provider_id": "@alice"}},
        {"tx_type": "STORAGE_PROOF_SUBMIT", "payload": {"lease_id": "lease-001", "provider_id": "@alice"}},
    ]


DEFAULT_HELPER_INSTANCE_CORPUS = build_default_helper_instance_corpus()


__all__ = ["DEFAULT_HELPER_INSTANCE_CORPUS", "build_default_helper_instance_corpus"]
