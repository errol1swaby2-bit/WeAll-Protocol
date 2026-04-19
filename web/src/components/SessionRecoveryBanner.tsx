import React from "react";

import type { SessionHealth } from "../auth/session";
import { nav } from "../lib/router";

type Props = {
  health: SessionHealth;
  compact?: boolean;
};

function titleForState(health: SessionHealth): string {
  switch (health.state) {
    case "expiring_soon":
      return "Session expiring soon";
    case "expired":
      return "Session expired";
    case "missing_local_signer":
      return "Signer missing on this device";
    case "invalid":
      return "Session needs recovery";
    case "anonymous":
      return "Sign in required";
    case "active":
    default:
      return "Session active";
  }
}

function toneForState(health: SessionHealth): "ok" | "warning" | "danger" | "neutral" {
  switch (health.state) {
    case "active":
      return "ok";
    case "expiring_soon":
      return "warning";
    case "expired":
    case "missing_local_signer":
    case "invalid":
      return "danger";
    case "anonymous":
    default:
      return "neutral";
  }
}

function primaryActionLabel(health: SessionHealth): string {
  if (health.recoverableAccount) return "Open session recovery";
  return "Open login";
}

export default function SessionRecoveryBanner({ health, compact = false }: Props): JSX.Element | null {
  if (health.state === "active") return null;

  const tone = toneForState(health);

  return (
    <section className={`sessionRecoveryBanner sessionRecoveryBanner-${tone} ${compact ? "compact" : ""}`.trim()}>
      <div className="sessionRecoveryBannerCopy">
        <div className="eyebrow">Protected route recovery</div>
        <h2 className="cardTitle">{titleForState(health)}</h2>
        <p className="cardDesc">{health.message}</p>
      </div>
      <div className="sessionRecoveryBannerActions">
        <span className={`statusPill ${tone === "warning" ? "warning" : tone === "danger" ? "danger" : tone === "ok" ? "ok" : ""}`.trim()}>
          {health.state.replace(/_/g, " ")}
        </span>
        <button className="btn btnPrimary" onClick={() => nav(health.recoverableAccount ? "/session" : "/login")}>
          {primaryActionLabel(health)}
        </button>
      </div>
    </section>
  );
}
