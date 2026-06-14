import React from "react";

import { nav } from "../lib/router";

type Step = {
  label: string;
  ok: boolean;
  warn?: boolean;
  value: React.ReactNode;
};

function statusClass(okish: boolean, warn = false): string {
  if (okish) return "statusPill ok";
  if (warn) return "statusPill warn";
  return "statusPill";
}

function DetailRow({ label, value, ok, warn }: Step): JSX.Element {
  return (
    <div className="progressRow">
      <span>{label}</span>
      <span className={statusClass(!!ok, !!warn)}>{value}</span>
    </div>
  );
}

export default function ValidatorReadinessWizard({
  steps,
  observerMode,
  validatorEffective,
  helperEffective,
  chainId,
  baseUrl,
}: {
  steps: Step[];
  observerMode: boolean;
  validatorEffective: boolean;
  helperEffective: boolean;
  chainId: string;
  baseUrl: string;
}): JSX.Element {
  const allReady = steps.every((step) => step.ok);
  const nextBlocker = steps.find((step) => !step.ok)?.label || "No local blocker detected";
  const safeCommand = `cd ~/WeAll-Protocol && Weall-Protocol/scripts/reboot_promoted_observer_as_validator.sh --chain ${chainId || "<chain-id>"}`;

  return (
    <section className="card" aria-labelledby="operator-wizard-heading">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Validator readiness wizard</div>
            <h2 id="operator-wizard-heading" className="cardTitle">Fix readiness blockers in order</h2>
            <p className="cardDesc">
              Validator readiness is backend-derived. This wizard cannot grant roles; it only explains the next safe step before you switch an observer into production validator posture.
            </p>
          </div>
          <span className={statusClass(allReady, steps.some((step) => step.warn))}>Backend-derived</span>
        </div>

        <div className="summaryCardGrid summaryCardGridThree" aria-label="Validator production switch summary">
          <article className="summaryCard">
            <span className="summaryCardLabel">Next blocker</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{nextBlocker}</div>
            <div className="summaryCardHint">Resolve blockers top-to-bottom. No hidden state mutation is performed here.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Observer posture</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{observerMode ? "Observer-only" : "Service-capable"}</div>
            <div className="summaryCardHint">Observer mode cannot sign blocks or attest as a validator.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Authority boundary</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{validatorEffective ? "Validator effective" : "Not validator effective"}</div>
            <div className="summaryCardHint">Helper production remains {helperEffective ? "effective for this node" : "disabled or gated"} unless explicitly active.</div>
          </article>
        </div>

        <div className="progressList">
          {steps.map((step) => (
            <DetailRow key={step.label} {...step} />
          ))}
        </div>

        <div className="calloutInfo">
          <strong>Safe switch command preview:</strong>
          <pre className="codePanel mono" style={{ marginTop: 8 }}>{safeCommand}</pre>
          <div className="cardDesc">Run only after the backend reports validator readiness and the account has explicitly opted into validator responsibility.</div>
        </div>

        <div className="buttonRow buttonRowWide">
          <button className="btn" onClick={() => nav("/profile")}>Open account operator setup</button>
          <button className="btn" onClick={() => nav("/poh")}>Open proof of humanity</button>
          <button className="btn" onClick={() => nav("/transactions")}>View transaction status</button>
          <button className="btn" onClick={() => nav("/settings")}>Confirm backend target</button>
        </div>

        <div className="mutedText">Backend target: {baseUrl || "same-origin"}</div>
      </div>
    </section>
  );
}
