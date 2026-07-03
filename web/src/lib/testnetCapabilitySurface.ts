export type LaunchMatrixCapabilityRecord = {
  enabled: boolean;
  feature: string;
  phase: string;
  blocked_by_launch_matrix: boolean;
  disabled_reason: string;
  truth_boundary: string;
};

export type ProtocolUpgradeLifecycleSurface = {
  public_record_state?: boolean;
  declaration_tx?: string;
  scheduled_activation_tx?: string;
  required_parent_boundary?: string;
  activation_clock?: string;
  activation_record_only?: boolean;
  automatic_software_apply_enabled?: boolean;
  migration_execution_enabled?: boolean;
  rollback_execution_enabled?: boolean;
  economics_activation_enabled_by_upgrade?: boolean;
  reviewer_surface?: string;
  truth_boundary?: string;
};

export type DeterministicLifecycleSurface = {
  public_record_state?: boolean;
  progression_clock?: string;
  scheduler?: string;
  manual_wall_clock_protocol_state_allowed?: boolean;
  ui_time_estimates_only?: boolean;
  deterministic_receipt_txs?: string[];
  private_identity_evidence_publicly_exposed?: boolean;
  reviewer_surface?: string;
  truth_boundary?: string;
};

export type MinimumReviewerCivicLoopSurface = {
  public_only_visibility?: boolean;
  economics_locked_by_default?: boolean;
  steps?: string[];
  frontend_entrypoints?: Record<string, string>;
  truth_boundary?: string;
};

export type TestnetCapabilitySurface = {
  schema: string;
  phase: string;
  capabilities: Record<string, LaunchMatrixCapabilityRecord>;
  blocked_capabilities: string[];
  controlled_testnet_mechanisms_complete: boolean;
  public_beta_ready_claimed: boolean;
  protocol_upgrade_lifecycle?: ProtocolUpgradeLifecycleSurface;
  governance_lifecycle?: DeterministicLifecycleSurface;
  dispute_lifecycle?: DeterministicLifecycleSurface;
  minimum_reviewer_civic_loop?: MinimumReviewerCivicLoopSurface;
  truth_boundaries: Record<string, boolean>;
};

export const HIGH_RISK_TESTNET_CAPABILITIES = [
  "live_transfers",
  "live_rewards",
  "treasury_spend",
  "live_economics",
  "public_validator_join",
  "public_multi_validator_bft",
  "automatic_protocol_upgrade_apply",
  "production_helper_execution",
] as const;

export function summarizeTestnetCapabilitySurface(surface: Partial<TestnetCapabilitySurface> | null | undefined) {
  const capabilities = surface?.capabilities || {};
  const blocked = Array.isArray(surface?.blocked_capabilities) ? surface!.blocked_capabilities : [];
  return {
    controlledTestnetMechanismsComplete: Boolean(surface?.controlled_testnet_mechanisms_complete),
    publicBetaReadyClaimed: Boolean(surface?.public_beta_ready_claimed),
    blockedCapabilities: blocked,
    highRiskCapabilitiesStillBlocked: HIGH_RISK_TESTNET_CAPABILITIES.every((key) => {
      const record = capabilities[key];
      return !record || record.enabled === false || record.blocked_by_launch_matrix === true;
    }),
    message:
      surface?.public_beta_ready_claimed === true
        ? "Public beta readiness is claimed by this node. Verify external go-gate evidence before relying on it."
        : "Controlled testnet mechanisms may be present, but public beta readiness is not claimed until the final go-gates pass.",
  };
}
