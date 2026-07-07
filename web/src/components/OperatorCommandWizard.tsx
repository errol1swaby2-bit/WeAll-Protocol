import React from "react";

export type OperatorWizardCommand = {
  label: string;
  scope: string;
  command: string;
  note: string;
};

function commandForCurl(baseUrl: string, path: string): string {
  const base = baseUrl || "http://127.0.0.1:8000";
  const trimmed = base.endsWith("/") ? base.slice(0, -1) : base;
  return `curl -fsS ${trimmed}${path} | python -m json.tool`;
}

function copyCommand(command: string): void {
  if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) return;
  void navigator.clipboard.writeText(command).catch(() => undefined);
}

export default function OperatorCommandWizard({
  nodeMode,
  chainId,
  baseUrl,
  observerMode,
  validatorEffective,
  validatorCandidate,
}: {
  nodeMode: string;
  chainId: string;
  baseUrl: string;
  observerMode: boolean;
  validatorEffective: boolean;
  validatorCandidate: boolean;
}): JSX.Element {
  const commands: OperatorWizardCommand[] = [
    {
      label: "Diagnostic-only status check",
      scope: "diagnostic-only / read-only",
      command: commandForCurl(baseUrl, "/v1/status"),
      note: "Reads chain identity, mode, height, and public readiness boundaries; it does not mutate protocol state.",
    },
    {
      label: "Local-only operator status",
      scope: "local-only / diagnostic-only",
      command: commandForCurl(baseUrl, "/v1/status/operator"),
      note: "Shows backend-derived responsibility and authority blockers; local output is not a role grant.",
    },
    {
      label: "Observer-only tx queue check",
      scope: "observer-only / diagnostic-only",
      command: commandForCurl(baseUrl, "/v1/observer/edge/status"),
      note: "Shows whether a public observer has verified upstreams and local queue evidence; local acceptance is not confirmation.",
    },
    {
      label: "Validator readiness receipt helper",
      scope: "requires protocol state before use",
      command: "cd ~/WeAll-Protocol/Weall-Protocol && PYTHONPATH=src python scripts/validator_readiness_check.py generate --help",
      note: "Generates help for the signed readiness receipt path. A receipt alone does not grant validator authority unless committed protocol state activates it.",
    },
    {
      label: "Operator incident evidence bundle",
      scope: "diagnostic-only / evidence capture",
      command: "cd ~/WeAll-Protocol/Weall-Protocol && PYTHONPATH=src python scripts/build_operator_incident_report.py --help",
      note: "Use this before changing settings. It collects the incident packet reviewers need without granting authority or mutating protocol state.",
    },
    {
      label: "Public observer launch transcript helper",
      scope: "external transcript / read-only",
      command: "cd ~/WeAll-Protocol/Weall-Protocol && PYTHONPATH=src:scripts python scripts/gen_public_observer_launch_transcript_v1_5.py --help",
      note: "Prepares the external observer transcript checklist. A local transcript does not close independent external evidence gates.",
    },
    {
      label: "Promoted validator live gate",
      scope: "requires protocol state / fail-closed",
      command: `cd ~/WeAll-Protocol/Weall-Protocol && WEALL_EXPECTED_CHAIN_ID=${chainId || "<chain-id>"} bash scripts/promoted_validator_live_gate.sh`,
      note: "Run only after node-operator, validator responsibility, readiness receipt, and validator activation are visible in protocol state.",
    },
  ];

  return (
    <section className="card" aria-labelledby="operator-command-wizard-heading">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Operator wizard</div>
            <h2 id="operator-command-wizard-heading" className="cardTitle">Safe guided commands</h2>
            <p className="cardDesc">
              This wizard is a read-only guide for the current node mode. It distinguishes observer, node operator, validator-candidate, and validator authority; script execution or copied commands never grant authority by themselves.
            </p>
          </div>
          <span className={`statusPill ${validatorEffective ? "ok" : validatorCandidate ? "warn" : ""}`}>{nodeMode}</span>
        </div>

        <div className="summaryCardGrid summaryCardGridThree" aria-label="Operator role boundaries">
          <article className="summaryCard">
            <span className="summaryCardLabel">Observer</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{observerMode ? "Current mode" : "Available as read-only posture"}</div>
            <div className="summaryCardHint">Can read and sync public state. Cannot sign blocks, activate economics, or bypass validator gates.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Node operator / validator-candidate</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{validatorCandidate ? "Candidate path visible" : "Protocol state required"}</div>
            <div className="summaryCardHint">Baseline operator setup and validator-candidate readiness are protocol-state facts, not frontend toggles.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Validator authority</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{validatorEffective ? "Effective" : "Not granted"}</div>
            <div className="summaryCardHint">Validator signing is allowed only after protocol state and fail-closed local checks agree.</div>
          </article>
        </div>

        <div className="txRecordList compact" aria-label="Safe copyable operator commands">
          {commands.map((row) => (
            <article key={row.label} className="txRecordCard unknown">
              <div className="txRecordHeader">
                <strong>{row.label}</strong>
                <span className="statusPill">{row.scope}</span>
              </div>
              <pre className="codePanel mono wrapAnywhere">{row.command}</pre>
              <div className="buttonRow">
                <button className="btn ghost" type="button" onClick={() => copyCommand(row.command)}>Copy command</button>
              </div>
              <div className="mutedText">{row.note}</div>
            </article>
          ))}
        </div>

        <div className="calloutWarn">
          <strong>Authority boundary:</strong> these are safe command categories, not launch switches. Commands marked local-only, observer-only, diagnostic-only, or requires protocol state must remain inside that scope until backend protocol state proves otherwise. Commands marked external transcript or evidence capture also stay non-authoritative until independent evidence is verified.
        </div>
        <div className="calloutInfo">
          <strong>Safe next action:</strong> when the dashboard shows a warning, copy the matching diagnostic command first, save the output in the incident response packet, then decide whether a documented runbook command is appropriate.
        </div>
      </div>
    </section>
  );
}
