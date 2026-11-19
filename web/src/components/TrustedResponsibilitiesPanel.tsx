import React from "react";

import { nav } from "../lib/router";
import { TRUSTED_RESPONSIBILITIES, blockedByVerificationMessage } from "../lib/userLanguage";

type Props = {
  account: string | null;
  accountLevel: number;
  contentReviewActive: boolean;
  contentReviewOptedIn: boolean;
  contentReviewStatusLabel: string;
  reviewerBusy: "optIn" | "optOut" | null;
  signerBusy: boolean;
  hasLocalKeypair: boolean;
  onUpdateContentReviewLane: (active: boolean) => void;
};

/**
 * A Tier-2 eligibility surface; real review-lane authority is applied by
 * the backend, never granted by rendering this component or clicking a button.
 */
export default function TrustedResponsibilitiesPanel({
  account,
  accountLevel,
  contentReviewActive,
  contentReviewOptedIn,
  contentReviewStatusLabel,
  reviewerBusy,
  signerBusy,
  hasLocalKeypair,
  onUpdateContentReviewLane,
}: Props): JSX.Element {
  if (accountLevel < 2) {
    return (
      <details className="advancedDisclosure" data-testid="trusted-responsibilities-locked">
        <summary>Later: trusted responsibilities (live verification required)</summary>
        <p className="miniMuted">
          Reviewer, juror, validator and operator responsibilities require additional authorization.
          They remain unavailable until the canonical account tier and applicable role-specific rules permit them.
        </p>
      </details>
    );
  }

  return (
    <section className="card" data-testid="trusted-responsibilities-eligible">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Trusted Responsibilities</div>
            <h2 className="cardTitle">Responsibilities you can earn over time</h2>
          </div>
          <span className="statusPill ok">Eligible to apply</span>
        </div>
        <p className="cardDesc">
          Verification proves account status. Responsibilities prove specific service
          permission, such as reviewing reports or helping operate network services.
          Applying or opting into a lane does not grant authority by itself.
        </p>
        <div className="infoCard compact">
          <div className="infoCardHeader">
            <strong>Content review selection</strong>
            <span className={`statusPill ${contentReviewActive ? "ok" : contentReviewOptedIn ? "warning" : ""}`}>
              {contentReviewStatusLabel}
            </span>
          </div>
          <div className="infoCardText">
            Tier 2 makes you eligible, but the protocol only selects reviewers who
            explicitly opt into content_review and are not the author of the flagged content.
          </div>
          <div className="buttonRowWide">
            {!contentReviewActive ? (
              <button
                className="btn btnPrimary"
                onClick={() => onUpdateContentReviewLane(true)}
                disabled={!account || accountLevel < 2 || reviewerBusy !== null || signerBusy || !hasLocalKeypair}
              >
                {reviewerBusy === "optIn" ? "Opting in…" : accountLevel < 2 ? blockedByVerificationMessage(2) : "Opt into content review"}
              </button>
            ) : (
              <button
                className="btn"
                onClick={() => onUpdateContentReviewLane(false)}
                disabled={!account || reviewerBusy !== null || signerBusy || !hasLocalKeypair}
              >
                {reviewerBusy === "optOut" ? "Opting out…" : "Opt out of content review"}
              </button>
            )}
            <button
              className="btn btnGhost"
              onClick={() => nav(account ? `/account/${encodeURIComponent(account)}` : "/login")}
              disabled={!account}
            >
              Open all responsibility controls
            </button>
          </div>
        </div>
        <div className="infoGrid">
          {TRUSTED_RESPONSIBILITIES.map((responsibility) => (
            <div key={responsibility.key} className="infoCard compact">
              <div className="infoCardHeader">
                <strong>{responsibility.label}</strong>
                <span className="statusPill ok">Can apply</span>
              </div>
              <div className="infoCardText">{responsibility.description}</div>
              <div className="miniTag">Requires: {responsibility.requires}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
