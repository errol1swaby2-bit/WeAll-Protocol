# WeAll M1–M3 Phase 0 System Map

Status: read-only source snapshot map; no Git identity is available in the supplied archive.

## Canonical transaction surface
- Canon version: `1.25.0`.
- Canonical transaction count: **236**.
- Source canon: `Weall-Protocol/specs/tx_canon/tx_canon.yaml`.
- Generated runtime index: `Weall-Protocol/generated/tx_index.json`.

### Cases (3)
`CASE_BIND_TO_DISPUTE`, `CASE_OUTCOME_RECEIPT`, `CASE_TYPE_REGISTER`

### Consensus (16)
`BLOCK_ATTEST`, `BLOCK_FINALIZE`, `BLOCK_PROPOSE`, `EPOCH_CLOSE`, `EPOCH_OPEN`, `SLASH_EXECUTE`, `SLASH_PROPOSE`, `SLASH_VOTE`, `VALIDATOR_CANDIDATE_APPROVE`, `VALIDATOR_CANDIDATE_REGISTER`, `VALIDATOR_DEREGISTER`, `VALIDATOR_HEARTBEAT`, `VALIDATOR_REGISTER`, `VALIDATOR_REMOVE`, `VALIDATOR_SET_UPDATE`, `VALIDATOR_SUSPEND`

### Content (15)
`CONTENT_COMMENT_CREATE`, `CONTENT_COMMENT_DELETE`, `CONTENT_ESCALATE_TO_DISPUTE`, `CONTENT_FLAG`, `CONTENT_LABEL_SET`, `CONTENT_MEDIA_BIND`, `CONTENT_MEDIA_DECLARE`, `CONTENT_MEDIA_REPLACE`, `CONTENT_MEDIA_UNBIND`, `CONTENT_POST_CREATE`, `CONTENT_POST_DELETE`, `CONTENT_POST_EDIT`, `CONTENT_REACTION_SET`, `CONTENT_THREAD_LOCK_SET`, `CONTENT_VISIBILITY_SET`

### Dispute (14)
`DISPUTE_APPEAL`, `DISPUTE_EVIDENCE_BIND`, `DISPUTE_EVIDENCE_DECLARE`, `DISPUTE_FINAL_RECEIPT`, `DISPUTE_JUROR_ACCEPT`, `DISPUTE_JUROR_ASSIGN`, `DISPUTE_JUROR_ATTENDANCE`, `DISPUTE_JUROR_DECLINE`, `DISPUTE_JUROR_TIMEOUT`, `DISPUTE_JUROR_WITHDRAW`, `DISPUTE_OPEN`, `DISPUTE_RESOLVE`, `DISPUTE_STAGE_SET`, `DISPUTE_VOTE_SUBMIT`

### Economics (7)
`BALANCE_TRANSFER`, `ECONOMICS_ACTIVATION`, `FEE_PAY`, `FEE_POLICY_SET`, `MEMPOOL_REJECT_RECEIPT`, `RATE_LIMIT_POLICY_SET`, `RATE_LIMIT_STRIKE_APPLY`

### Governance (19)
`CONSTITUTION_UPGRADE_ACTIVATE`, `CONSTITUTION_UPGRADE_DECLARE`, `GOV_EXECUTE`, `GOV_EXECUTION_RECEIPT`, `GOV_PROPOSAL_COMMENT`, `GOV_PROPOSAL_CREATE`, `GOV_PROPOSAL_EDIT`, `GOV_PROPOSAL_FINALIZE`, `GOV_PROPOSAL_RECEIPT`, `GOV_PROPOSAL_WITHDRAW`, `GOV_QUORUM_SET`, `GOV_RULES_SET`, `GOV_STAGE_SET`, `GOV_TALLY_PUBLISH`, `GOV_VOTE_CAST`, `GOV_VOTE_REVOKE`, `GOV_VOTING_CLOSE`, `PROTOCOL_UPGRADE_ACTIVATE`, `PROTOCOL_UPGRADE_DECLARE`

### Groups (20)
`GROUP_CREATE`, `GROUP_EMISSARY_BALLOT_CAST`, `GROUP_EMISSARY_ELECTION_CREATE`, `GROUP_EMISSARY_ELECTION_FINALIZE`, `GROUP_MEMBERSHIP_DECIDE`, `GROUP_MEMBERSHIP_REMOVE`, `GROUP_MEMBERSHIP_REQUEST`, `GROUP_MODERATORS_SET`, `GROUP_ROLE_GRANT`, `GROUP_ROLE_REVOKE`, `GROUP_SIGNERS_SET`, `GROUP_TREASURY_AUDIT_ANCHOR_SET`, `GROUP_TREASURY_CREATE`, `GROUP_TREASURY_POLICY_SET`, `GROUP_TREASURY_SPEND_CANCEL`, `GROUP_TREASURY_SPEND_EXECUTE`, `GROUP_TREASURY_SPEND_EXPIRE`, `GROUP_TREASURY_SPEND_PROPOSE`, `GROUP_TREASURY_SPEND_SIGN`, `GROUP_UPDATE`

### Identity (18)
`ACCOUNT_DEVICE_REGISTER`, `ACCOUNT_DEVICE_REVOKE`, `ACCOUNT_GUARDIAN_ADD`, `ACCOUNT_GUARDIAN_REMOVE`, `ACCOUNT_KEY_ADD`, `ACCOUNT_KEY_REVOKE`, `ACCOUNT_LOCK`, `ACCOUNT_RECOVERY_APPROVE`, `ACCOUNT_RECOVERY_CANCEL`, `ACCOUNT_RECOVERY_CONFIG_SET`, `ACCOUNT_RECOVERY_FINALIZE`, `ACCOUNT_RECOVERY_RECEIPT`, `ACCOUNT_RECOVERY_REQUEST`, `ACCOUNT_REGISTER`, `ACCOUNT_SECURITY_POLICY_SET`, `ACCOUNT_SESSION_KEY_ISSUE`, `ACCOUNT_SESSION_KEY_REVOKE`, `ACCOUNT_UNLOCK`

### Indexing (8)
`COLD_SYNC_COMPLETE`, `COLD_SYNC_REQUEST`, `INDEX_ANCHOR_SET`, `INDEX_TOPIC_ANCHOR_SET`, `INDEX_TOPIC_REGISTER`, `STATE_SNAPSHOT_ACCEPT`, `STATE_SNAPSHOT_DECLARE`, `TX_RECEIPT_EMIT`

### Moderation (2)
`FLAG_ESCALATION_RECEIPT`, `MOD_ACTION_RECEIPT`

### Networking (6)
`PEER_ADVERTISE`, `PEER_BAN_SET`, `PEER_RENDEZVOUS_TICKET_CREATE`, `PEER_RENDEZVOUS_TICKET_REVOKE`, `PEER_REPUTATION_SIGNAL`, `PEER_REQUEST_CONNECT`

### Notifications (3)
`NOTIFICATION_EMIT_RECEIPT`, `NOTIFICATION_SUBSCRIBE`, `NOTIFICATION_UNSUBSCRIBE`

### Performance (5)
`CREATOR_PERFORMANCE_REPORT`, `NODE_OPERATOR_PERFORMANCE_REPORT`, `PERFORMANCE_EVALUATE`, `PERFORMANCE_SCORE_APPLY`, `VALIDATOR_PERFORMANCE_REPORT`

### PoH (34)
`POH_APPLICATION_SUBMIT`, `POH_ASYNC_EVIDENCE_BIND`, `POH_ASYNC_EVIDENCE_DECLARE`, `POH_ASYNC_FINALIZE`, `POH_ASYNC_JUROR_ACCEPT`, `POH_ASYNC_JUROR_ASSIGN`, `POH_ASYNC_JUROR_DECLINE`, `POH_ASYNC_RECEIPT`, `POH_ASYNC_REQUEST_OPEN`, `POH_ASYNC_REVIEW_SUBMIT`, `POH_BOOTSTRAP_TIER2_GRANT`, `POH_CHALLENGE_OPEN`, `POH_CHALLENGE_RESOLVE`, `POH_EVIDENCE_BIND`, `POH_EVIDENCE_DECLARE`, `POH_LIVE_ATTENDANCE_MARK`, `POH_LIVE_FINALIZE`, `POH_LIVE_JUROR_ACCEPT`, `POH_LIVE_JUROR_ASSIGN`, `POH_LIVE_JUROR_DECLINE`, `POH_LIVE_JUROR_REPLACE`, `POH_LIVE_RECEIPT`, `POH_LIVE_REQUEST_OPEN`, `POH_LIVE_SESSION_INIT`, `POH_LIVE_VERDICT_SUBMIT`, `POH_TIER2_FINALIZE`, `POH_TIER2_JUROR_ACCEPT`, `POH_TIER2_JUROR_ASSIGN`, `POH_TIER2_JUROR_DECLINE`, `POH_TIER2_RECEIPT`, `POH_TIER2_REQUEST_OPEN`, `POH_TIER2_REVIEW_SUBMIT`, `POH_TIER_REVOKE`, `POH_TIER_SET`

### Reputation (6)
`ACCOUNT_BAN`, `ACCOUNT_REINSTATE`, `REPUTATION_DELTA_APPLY`, `REPUTATION_THRESHOLD_CROSS`, `ROLE_ELIGIBILITY_REVOKE`, `ROLE_ELIGIBILITY_SET`

### Rewards (6)
`BLOCK_REWARD_DISTRIBUTE`, `BLOCK_REWARD_MINT`, `CREATOR_REWARD_ALLOCATE`, `FORFEITURE_APPLY`, `REWARD_POOL_OPT_IN_SET`, `TREASURY_REWARD_ALLOCATE`

### Roles (21)
`NODE_OPERATOR_HELPER_OPT_IN`, `NODE_OPERATOR_RESPONSIBILITY_UPDATE`, `NODE_OPERATOR_STORAGE_OPT_IN`, `NODE_OPERATOR_VALIDATOR_OPT_IN`, `REVIEWER_LANE_OPT_IN`, `REVIEWER_LANE_OPT_OUT`, `ROLE_EMISSARY_NOMINATE`, `ROLE_EMISSARY_REMOVE`, `ROLE_EMISSARY_SEAT`, `ROLE_EMISSARY_VOTE`, `ROLE_GOV_EXECUTOR_SET`, `ROLE_JUROR_ACTIVATE`, `ROLE_JUROR_ENROLL`, `ROLE_JUROR_REINSTATE`, `ROLE_JUROR_SUSPEND`, `ROLE_NODE_OPERATOR_ACTIVATE`, `ROLE_NODE_OPERATOR_ENROLL`, `ROLE_NODE_OPERATOR_SUSPEND`, `ROLE_VALIDATOR_ACTIVATE`, `ROLE_VALIDATOR_SUSPEND`, `VALIDATOR_READINESS_VERIFY`

### Social (5)
`BLOCK_SET`, `CONTENT_SHARE_CREATE`, `FOLLOW_SET`, `MUTE_SET`, `PROFILE_UPDATE`

### Storage (13)
`IPFS_PIN_CONFIRM`, `IPFS_PIN_REQUEST`, `STORAGE_CAPACITY_PROOF_VERIFY`, `STORAGE_CHALLENGE_ISSUE`, `STORAGE_CHALLENGE_RESPOND`, `STORAGE_LEASE_CREATE`, `STORAGE_LEASE_RENEW`, `STORAGE_LEASE_REVOKE`, `STORAGE_OFFER_CREATE`, `STORAGE_OFFER_WITHDRAW`, `STORAGE_PAYOUT_EXECUTE`, `STORAGE_PROOF_SUBMIT`, `STORAGE_REPORT_ANCHOR`

### Treasury (15)
`TREASURY_AUDIT_ANCHOR_SET`, `TREASURY_CREATE`, `TREASURY_POLICY_SET`, `TREASURY_PROGRAM_CLOSE`, `TREASURY_PROGRAM_CREATE`, `TREASURY_PROGRAM_UPDATE`, `TREASURY_SIGNERS_SET`, `TREASURY_SIGNER_ADD`, `TREASURY_SIGNER_REMOVE`, `TREASURY_SPEND_CANCEL`, `TREASURY_SPEND_EXECUTE`, `TREASURY_SPEND_EXPIRE`, `TREASURY_SPEND_PROPOSE`, `TREASURY_SPEND_SIGN`, `TREASURY_WALLET_CREATE`

## Canonical execution flow
1. Payload model and field normalization: `src/weall/runtime/tx_schema.py`.
2. Canon lookup for origin, context, receipt-only status, and subject gate: `generated/tx_index.json`.
3. Canonical admission: `src/weall/runtime/tx_admission.py`.
4. Gate evaluation: `src/weall/runtime/gate_expr.py`.
5. Atomic apply and bounded rollback: `src/weall/runtime/domain_apply.py`.
6. Apply-time canon enforcement and handler dispatch: `src/weall/runtime/domain_dispatch.py`.
7. State mutation: `src/weall/runtime/apply/*.py`.
8. Block-level admission/replay: `src/weall/runtime/block_admission.py` and `block_replay.py`.
9. Persistence/state roots: `src/weall/runtime/sqlite_db.py` and `state_root.py`.

## State mutation modules
- `Weall-Protocol/src/weall/runtime/apply/consensus.py` — _as_dict, _as_list, _as_str, _as_int, _ensure_root_dict, _get_params, _enforce_proposer, _enforce_finality_attestations
- `Weall-Protocol/src/weall/runtime/apply/content.py` — _canonical_hash, _as_dict, _as_list, _as_str, _as_int, _require_public_cid, _canonical_account_list, _identity_variants
- `Weall-Protocol/src/weall/runtime/apply/dispute.py` — _canonical_hash, _require_active_dispute_ballot_profile, _dispute_ballot_receipts, _dispute_ballot_nullifier, _aggregate_dispute_counts, _dispute_ballot_nullifiers, _dispute_voted_juror_ids, _record_deattributed_resolution_option
- `Weall-Protocol/src/weall/runtime/apply/economics.py` — _as_str, _as_int, _as_bool, _as_dict, _accounts_root, _require_existing_account, _require_system_env, _ensure_params
- `Weall-Protocol/src/weall/runtime/apply/governance.py` — _d, _l, _s, _i, _sorted_dict, _canonical_json_hash, _require_active_ballot_profile, _ballot_admission_receipts
- `Weall-Protocol/src/weall/runtime/apply/groups.py` — _as_str, _as_dict, _as_int, _same_journal_target, _strict_positive_int_from_state, _ensure_roles_root, _ensure_groups_root, _ensure_group_spends
- `Weall-Protocol/src/weall/runtime/apply/identity.py` — _as_int, _as_str, _payload, _ensure, _expect_nonce, _require_known_not_banned_allow_locked, _guardian_recovery_admission_enabled, _require_guardian_recovery_admission
- `Weall-Protocol/src/weall/runtime/apply/indexing.py` — _as_dict, _as_list, _as_str, _as_int, _require_system_env, _ensure_root_dict, _ensure_root_list, _ensure_indexing
- `Weall-Protocol/src/weall/runtime/apply/networking.py` — _as_dict, _as_str, _as_int, _pick, _mk_id, _require_system_env, _ensure_root_dict, _account_record
- `Weall-Protocol/src/weall/runtime/apply/notifications.py` — _as_dict, _as_list, _as_str, _require_system_env, _ensure_notify_root, _normalize_topics, _apply_notification_subscribe, _apply_notification_unsubscribe
- `Weall-Protocol/src/weall/runtime/apply/poh.py` — _require_system_tx, _validate_commitment_format, _validate_ipfs_uri, _as_str, _as_int, _state_poh_param_int, _state_poh_param_str, _live_poh_policy_mode
- `Weall-Protocol/src/weall/runtime/apply/protocol.py` — _as_dict, _as_str, _as_int, _require_system_env, _parent_ref, _require_parent_ref, _ensure_root_dict, _ensure_protocol
- `Weall-Protocol/src/weall/runtime/apply/reputation.py` — _as_dict, _as_str, _as_int, _require_system_env, _delta_units_from_payload, _ensure_root_dict, _ensure_root_list, _ensure_reputation
- `Weall-Protocol/src/weall/runtime/apply/rewards.py` — _as_dict, _as_list, _as_int, _as_str, _pick, _require_system_env, _ensure_root_dict, _ensure_root_list
- `Weall-Protocol/src/weall/runtime/apply/roles.py` — _as_str, _as_int, _as_list, _as_dict, _touch, _account_match_key, _same_account, _content_target_owner_for_dispute
- `Weall-Protocol/src/weall/runtime/apply/social.py` — _as_dict, _as_list, _as_str, _as_bool, _ensure_root_dict, _ensure_profiles, _ensure_edges, _mk_edge_key
- `Weall-Protocol/src/weall/runtime/apply/storage.py` — _as_dict, _as_str, _as_int, _require_system_env, _ensure_root_dict, _height, _pick, _mk_id
- `Weall-Protocol/src/weall/runtime/apply/treasury.py` — _as_str, _as_int, _as_dict, _require_system_env, _ensure_treasury_root, _ensure_wallets, _ensure_treasury_policy, _accounts_root

## Consensus, mempool, helper, and persistence modules
### Admission And Execution
- `src/weall/runtime/tx_schema.py` — present; classes: _StrictModel, AccountRegisterPayload, AccountKeyAddPayload, AccountKeyRevokePayload, AccountDeviceRegisterPayload, AccountDeviceRevokePayload, AccountSessionKeyIssuePayload, AccountSessionKeyRevokePayload, AccountGuardianAddPayload, AccountGuardianRemovePayload, AccountSecurityPolicySetPayload, AccountLockPayload, AccountUnlockPayload, AccountRecoveryConfigSetPayload, AccountRecoveryRequestPayload, AccountRecoveryApprovePayload, AccountRecoveryCancelPayload, AccountRecoveryFinalizePayload, AccountRecoveryReceiptPayload, PohTierSetPayload, PohApplicationSubmitPayload, PohEvidenceDeclarePayload, PohEvidenceBindPayload, PohChallengeOpenPayload, PohChallengeResolvePayload, PohAsyncRequestOpenPayload, PohAsyncEvidenceDeclarePayload, PohAsyncEvidenceBindPayload, PohAsyncJurorAssignPayload, PohAsyncJurorAcceptPayload, PohAsyncJurorDeclinePayload, PohAsyncReviewSubmitPayload, PohAsyncFinalizePayload, PohAsyncReceiptPayload, PohTier2RequestOpenPayload, PohTier2JurorAssignPayload, PohTier2JurorAcceptPayload, PohTier2JurorDeclinePayload, PohTier2ReviewSubmitPayload, PohTier2FinalizePayload, PohTier2ReceiptPayload, PohLiveRequestOpenPayload, PohLiveSessionInitPayload, PohLiveJurorAssignPayload, PohLiveJurorAcceptPayload, PohLiveJurorDeclinePayload, PohLiveJurorReplacePayload, PohLiveAttendanceMarkPayload, PohLiveVerdictSubmitPayload, PohLiveFinalizePayload, PohLiveReceiptPayload, PohBootstrapTier2GrantPayload, PohTierRevokePayload, ContentPostCreatePayload, ContentPostEditPayload, ContentPostDeletePayload, ContentCommentCreatePayload, ContentCommentDeletePayload, ContentReactionSetPayload, ContentFlagPayload, ContentMediaDeclarePayload, ContentMediaBindPayload, ProfileUpdatePayload, _EdgeTargetPayload, FollowSetPayload, BlockSetPayload, MuteSetPayload, ContentShareCreatePayload, _TopicPayloadBase, NotificationSubscribePayload, NotificationUnsubscribePayload, _OptionalCidPayload, PeerAdvertisePayload, PeerRendezvousTicketCreatePayload, PeerRendezvousTicketRevokePayload, PeerRequestConnectPayload, PeerBanSetPayload, PeerReputationSignalPayload, StorageOfferCreatePayload, StorageOfferWithdrawPayload, StorageLeaseCreatePayload, StorageLeaseRenewPayload, StorageLeaseRevokePayload, StorageProofSubmitPayload, StorageChallengeIssuePayload, StorageChallengeRespondPayload, StoragePayoutExecutePayload, StorageReportAnchorPayload, IpfsPinRequestPayload, IpfsPinConfirmPayload, TreasuryCreatePayload, TreasurySignersSetPayload, TreasuryWalletCreatePayload, TreasurySignerAddPayload, TreasurySignerRemovePayload, TreasuryPolicySetPayload, TreasurySpendProposePayload, TreasurySpendSignPayload, TreasurySpendCancelPayload, TreasurySpendExpirePayload, TreasurySpendExecutePayload, TreasuryProgramCreatePayload, TreasuryProgramUpdatePayload, TreasuryProgramClosePayload, TreasuryAuditAnchorSetPayload, _PublicGroupPermissionsPayload, GroupCreatePayload, GroupUpdatePayload, GroupRoleGrantPayload, GroupRoleRevokePayload, GroupMembershipRequestPayload, GroupMembershipDecidePayload, GroupMembershipRemovePayload, GroupSignersSetPayload, GroupModeratorsSetPayload, GroupTreasuryCreatePayload, GroupTreasuryPolicySetPayload, GroupTreasurySpendProposePayload, GroupTreasurySpendSignPayload, GroupTreasurySpendCancelPayload, GroupTreasurySpendExpirePayload, GroupTreasurySpendExecutePayload, GroupTreasuryAuditAnchorSetPayload, GroupEmissaryElectionCreatePayload, GroupEmissaryBallotCastPayload, GroupEmissaryElectionFinalizePayload, GovProposalCreatePayload, GovVoteCastPayload, GovProposalEditPayload, GovProposalCommentPayload, GovProposalWithdrawPayload, GovStageSetPayload, GovQuorumSetPayload, GovRulesSetPayload, GovExecutePayload, GovExecutionReceiptPayload, ProtocolUpgradeDeclarePayload, ProtocolUpgradeActivatePayload, ConstitutionUpgradeDeclarePayload, ConstitutionUpgradeActivatePayload, GovVoteRevokePayload, GovVotingClosePayload, GovTallyPublishPayload, GovProposalFinalizePayload, GovProposalReceiptPayload, DisputeOpenPayload, DisputeStageSetPayload, DisputeJurorAssignPayload, DisputeJurorAcceptPayload, DisputeJurorDeclinePayload, DisputeJurorWithdrawPayload, DisputeJurorTimeoutPayload, DisputeJurorAttendancePayload, DisputeEvidenceDeclarePayload, DisputeEvidenceBindPayload, DisputeVoteSubmitPayload, DisputeResolvePayload, DisputeAppealPayload, DisputeFinalReceiptPayload, CaseTypeRegisterPayload, CaseBindToDisputePayload, CaseOutcomeReceiptPayload, ModActionReceiptPayload, FlagEscalationReceiptPayload, AccountBanPayload, AccountReinstatePayload, BalanceTransferPayload, FeePayPayload, EconomicsActivationPayload, FeePolicySetPayload, RateLimitPolicySetPayload, RateLimitStrikeApplyPayload, MempoolRejectReceiptPayload, RewardPoolOptInSetPayload, BlockRewardMintPayload, BlockRewardDistributePayload, CreatorRewardAllocatePayload, TreasuryRewardAllocatePayload, ForfeitureApplyPayload, SubjectPerformanceReportPayload, PerformanceReceiptPayload, ContentLabelSetPayload, ContentVisibilitySetPayload, ContentThreadLockSetPayload, ContentMediaReplacePayload, ContentMediaUnbindPayload, ContentEscalateToDisputePayload, NotificationEmitReceiptPayload, IndexAnchorSetPayload, StateSnapshotDeclarePayload, StateSnapshotAcceptPayload, ColdSyncRequestPayload, ColdSyncCompletePayload, IndexTopicRegisterPayload, IndexTopicAnchorSetPayload, TxReceiptEmitPayload, RoleEligibilitySetPayload, RoleEligibilityRevokePayload, RoleEmissaryNominatePayload, RoleEmissaryVotePayload, RoleEmissarySeatPayload, RoleEmissaryRemovePayload, RoleGovExecutorSetPayload, AccountScopedRolePayload, ReputationDeltaApplyPayload, ReputationThresholdCrossPayload, ValidatorRegisterPayload, ValidatorCandidateRegisterPayload, ValidatorCandidateApprovePayload, ValidatorSuspendPayload, ValidatorRemovePayload, ValidatorDeregisterPayload, ValidatorSetUpdatePayload, ValidatorHeartbeatPayload, ValidatorPerformanceReportPayload, BlockProposePayload, BlockAttestPayload, BlockFinalizePayload, EpochTransitionPayload, SlashProposePayload, SlashVotePayload, SlashExecutePayload, TxEnvelopeModel; functions: _validate_public_cid_value, _normalized_public_cid_values, model_for_tx_type, validate_tx_envelope
- `src/weall/runtime/tx_admission.py` — present; classes: AdmissionRejection, AdmissionVerdict; functions: _mode, _env_int, _json_bytes, _walk_limits, _lookup_canon_spec, _payload_limit_int, _payload_limits_ok, _rej, _as_ledgerview, _required, _mvp_payload_checks, _should_apply_account_semantics
- `src/weall/runtime/gate_expr.py` — present; classes: _Tok, _ParseError, _Node, _Parser; functions: _tokenize, _as_dict, _ledger_from_any, _tier_ok, _identity_variants, _matches_identity_collection, _truthy, _record_blocked, _record_active, _record_for_identity, _collection_has_blocked_record, _active_role
- `src/weall/runtime/domain_apply.py` — present; classes: NonceSideEffectError; functions: _is_system, _signer, _nonce, _get_signer_account, _consume_nonce_if_possible, _enforce_nonce_convergence, _require_valid_signer_format, apply_tx_atomic_deepcopy, apply_tx_atomic_meta_deepcopy, apply_tx_atomic_meta_bounded_rollback, apply_tx_atomic_meta, apply_tx_atomic
- `src/weall/runtime/domain_dispatch.py` — present; classes: none; functions: _consensus_bootstrap_open_enabled, _bootstrap_allowlist_enabled, _canonical_system_signers, _consensus_bootstrap_policy_mode, _get, _tx_type, _load_index, _get_txdef, _enforce_apply_time_canon, apply_tx
- `src/weall/runtime/domain_registry.py` — missing; classes: none; functions: none
- `src/weall/runtime/tx_conflicts.py` — present; classes: TxFamily, BarrierClass, TxConflictRule, ConflictDescriptor; functions: _norm_str, _tx_type, _payload, _field, _field_many, _stable_tx_id, _sorted_unique, _key, _signer, _account_subject, _proposal_id, _group_id
- `src/weall/runtime/executor.py` — present; classes: ExecutorMeta, ExecutorError, WeAllExecutor; functions: _call_admit_bft_block, _call_admit_bft_commit_block, _normalize_mempool_selection_policy, _sanitize_mempool_selection_marker, _normalize_helper_timeout_ms, _helper_execution_profile, _sanitize_helper_execution_profile, _helper_execution_profile_hash, _state_meta_view, _pinned_mempool_selection_policy, _genesis_bootstrap_profile_hash, _pinned_helper_execution_profile
- `src/weall/runtime/executor_atomic.py` — missing; classes: none; functions: none

### Mempool And Block Path
- `src/weall/runtime/mempool.py` — present; classes: PersistentMempool; functions: _mode, _env_int, _env_bool, _env_str, _selection_policy_name, _read_selection_policy, _envelope_for_id, compute_tx_id, _expires_ms, _extract_height_field, _height_or_zero, _elapsed_ms
- `src/weall/runtime/block_builder.py` — present; classes: none; functions: produce_block, build_block_candidate
- `src/weall/runtime/block_admission.py` — present; classes: BlockReject, TxReject; functions: _env_bool, _mode, _as_int, _as_str, _as_dict, _ledger_with_account_nonce, _as_list, _get_active_validators_from_state, _get_validator_pubkeys_from_state, _validator_set_hash_from_validators, _current_validator_epoch_from_state, _current_validator_set_hash_from_state
- `src/weall/runtime/block_commit.py` — present; classes: none; functions: commit_block_candidate
- `src/weall/runtime/block_replay.py` — present; classes: none; functions: apply_block

### Consensus
- `src/weall/runtime/bft_hotstuff.py` — present; classes: BftVote, QuorumCert, TimeoutCertificate, BftTimeout, HotStuffBFT; functions: normalize_consensus_phase, fault_tolerance_for_validator_count, consensus_security_summary, consensus_contract_summary, _as_int, _as_str, _bft_sig_profile, _bft_sig_allowed, _verify_bft_signature, normalize_validators, quorum_threshold, leader_for_view
- `src/weall/runtime/bft_journal.py` — present; classes: BftJournal; functions: none
- `src/weall/runtime/consensus_loop.py` — missing; classes: none; functions: none
- `src/weall/runtime/consensus_profile.py` — missing; classes: none; functions: none
- `src/weall/runtime/consensus_contract.py` — missing; classes: none; functions: none

### Helper And Parallel Execution
- `src/weall/runtime/parallel_execution.py` — authoritative helper/parallel planner; production lane planning and merge execution live here.
- `src/weall/testing/helper_planner.py` — testing/reference planner only; not production mechanism authority.
- `src/weall/testing/conflict_lanes.py` — testing/reference conflict partitioner only; not production mechanism authority.
- `src/weall/runtime/helper_execution_runtime.py` — present; classes: none; functions: _root_committed_map, _helper_mode_enabled_runtime, _requested_helper_execution_profile, _effective_helper_execution_profile, _helper_fast_path_enabled, _helper_lane_journal_path, _helper_dispatch_context, _build_helper_execution_metadata
- `src/weall/runtime/helper_merge_admission.py` — present; classes: HelperMergeCandidate, HelperMergeAdmissionDecision; functions: canonical_receipts_root, canonical_state_delta_hash, canonical_lane_plan_id, merge_state_deltas, helper_receipts_from_candidates, admit_helper_merge
- `src/weall/runtime/helper_receipts.py` — present; classes: HelperReceipt; functions: _normalize_tx_ids, _signing_material, sign_helper_receipt, verify_helper_receipt; commitment hashing delegates to `runtime/commitments.py`.
- `src/weall/runtime/helper_restart_replay.py` — present; classes: HelperRestartSnapshot; functions: _lane_plan_map, _lane_plan_digest, _journal_history_consistent, build_helper_restart_snapshot; commitment hashing delegates to `runtime/commitments.py`.
- `src/weall/runtime/parallel_execution.py` — present; classes: LanePlan, LaneDecision, MergeHelperLaneResults, SerialHelperEquivalenceReport; functions: _canonical_json, lane_descriptor_hash, canonical_lane_plan_fingerprint, _canonical_tx_id, _tx_type, _tx_namespace_prefixes, _uses_explicit_access_sets, _explicit_lane_override, _expected_parallel_lane_from_access, _effective_parallel_lane_id, _access_conflicts, _plan_helper_assignment
- `src/weall/runtime/helper_lane_journal.py` — present; classes: HelperLaneJournal; functions: none

### Persistence
- `src/weall/runtime/sqlite_db.py` — present; classes: SqliteDB, SqliteLedgerStore; functions: derive_aux_db_path, _process_local_write_lock_for, _canon_json, _mode, _env_int
- `src/weall/runtime/bft_journal.py` — present; classes: BftJournal; functions: none
- `src/weall/runtime/state.py` — missing; classes: none; functions: none
- `src/weall/runtime/state_root.py` — missing; classes: none; functions: none
- `src/weall/runtime/snapshot.py` — missing; classes: none; functions: none

## Test and closure surface
- Backend Python test files: **926**.
- Frontend source/E2E test files located by filename pattern: **56**.
- M2 traceability declares **10** unique test references.
- M3 traceability declares **30** unique test references.
- Closure-related shell scripts audited: **24**.

## Evidence surface
- M2 manifest present: **True**.
- M3 manifest present: **False**.
- Integrated M1–M3 manifest present: **False**.
- M2 manifest-declared files missing from this reduced export: **16**.
