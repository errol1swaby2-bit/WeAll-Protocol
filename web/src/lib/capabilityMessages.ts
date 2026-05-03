import { blockedByVerificationMessage, normalizeVerificationTier, verificationLabel } from "./userLanguage";

export type CapabilityState =
  | "allowed"
  | "blocked_by_verification"
  | "blocked_by_responsibility"
  | "blocked_by_assignment"
  | "blocked_by_state"
  | "blocked_by_account"
  | "blocked_by_session"
  | "saving"
  | "done"
  | "failed";

export type Requirement = {
  label: string;
  satisfied: boolean;
  helpText?: string;
};

export type CapabilityResult = {
  key: string;
  state: CapabilityState;
  allowed: boolean;
  reasonCode?: string;
  message: string;
  requirements: Requirement[];
};

export function requirement(label: string, satisfied: boolean, helpText?: string): Requirement {
  return { label, satisfied, helpText };
}

export function allowedCapability(key: string, message = "You can use this action now.", requirements: Requirement[] = []): CapabilityResult {
  return { key, state: "allowed", allowed: true, message, requirements };
}

export function blockedCapability(args: {
  key: string;
  state: Exclude<CapabilityState, "allowed" | "saving" | "done" | "failed">;
  reasonCode: string;
  message: string;
  requirements?: Requirement[];
}): CapabilityResult {
  return {
    key: args.key,
    state: args.state,
    allowed: false,
    reasonCode: args.reasonCode,
    message: args.message,
    requirements: args.requirements || [],
  };
}

export function verificationCapability(key: string, currentTier: unknown, requiredTier: number): CapabilityResult {
  const current = normalizeVerificationTier(currentTier);
  const required = normalizeVerificationTier(requiredTier);
  const requirements = [
    requirement(verificationLabel(required), current >= required, current >= required ? "Requirement met." : blockedByVerificationMessage(required)),
  ];
  if (current >= required) return allowedCapability(key, "Your account verification meets this requirement.", requirements);
  return blockedCapability({
    key,
    state: "blocked_by_verification",
    reasonCode: required >= 2 ? "requires_trusted_verified_person" : "requires_verified_person",
    message: blockedByVerificationMessage(required),
    requirements,
  });
}

export function sessionCapability(key: string, loggedIn: boolean, canSign: boolean): CapabilityResult {
  const requirements = [
    requirement("Signed in", loggedIn, "Sign in or create an account before continuing."),
    requirement("Device session ready", canSign, "Restore the local signer for this account before continuing."),
  ];
  if (!loggedIn) {
    return blockedCapability({
      key,
      state: "blocked_by_session",
      reasonCode: "requires_sign_in",
      message: "Sign in or create an account before continuing.",
      requirements,
    });
  }
  if (!canSign) {
    return blockedCapability({
      key,
      state: "blocked_by_session",
      reasonCode: "requires_device_signer",
      message: "This device is missing the local signer for this account. Restore the signer before continuing.",
      requirements,
    });
  }
  return allowedCapability(key, "Your session is ready.", requirements);
}

export function responsibilityCapability(key: string, label: string, satisfied: boolean): CapabilityResult {
  const requirements = [requirement(label, satisfied, `${label} is required for this action.`)];
  if (satisfied) return allowedCapability(key, `You have the ${label} responsibility.`, requirements);
  return blockedCapability({
    key,
    state: "blocked_by_responsibility",
    reasonCode: "requires_trusted_responsibility",
    message: `You need the ${label} trusted responsibility before using this action.`,
    requirements,
  });
}

export function assignmentCapability(key: string, assigned: boolean): CapabilityResult {
  const requirements = [requirement("Assigned to this item", assigned, "Only selected reviewers can complete this review.")];
  if (assigned) return allowedCapability(key, "You were selected for this review.", requirements);
  return blockedCapability({
    key,
    state: "blocked_by_assignment",
    reasonCode: "requires_assignment",
    message: "You were not selected to review this item.",
    requirements,
  });
}

export function combineCapabilities(key: string, checks: CapabilityResult[], allowedMessage = "You can use this action now."): CapabilityResult {
  const requirements = checks.flatMap((check) => check.requirements || []);
  const firstBlocked = checks.find((check) => !check.allowed);
  if (firstBlocked) {
    return {
      ...firstBlocked,
      key,
      requirements,
    };
  }
  return allowedCapability(key, allowedMessage, requirements);
}
