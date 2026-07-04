import React from "react";

export type OperatorIncidentItem = {
  label: string;
  status: "ok" | "warn" | "info";
  detail: string;
  command?: string;
};

function statusClass(status: OperatorIncidentItem["status"]): string {
  if (status === "ok") return "statusPill ok";
  if (status === "warn") return "statusPill warn";
  return "statusPill";
}

function copyCommand(command: string | undefined): void {
  if (!command || typeof navigator === "undefined" || !navigator.clipboard?.writeText) return;
  void navigator.clipboard.writeText(command).catch(() => undefined);
}

export default function OperatorIncidentTimeline({
  items,
}: {
  items: OperatorIncidentItem[];
}): JSX.Element {
  return (
    <section className="card" aria-labelledby="operator-incident-timeline-heading">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Operator incident timeline</div>
            <h2 id="operator-incident-timeline-heading" className="cardTitle">Unified diagnostics</h2>
            <p className="cardDesc">
              Read-only timeline for node mode, chain identity, peer and seed status, mempool backlog, block/finalized height, BFT/validator authority, storage/helper/economics/protocol-upgrade blockers, and the next safe diagnostic commands.
            </p>
          </div>
          <span className="statusPill">Read-only diagnostics</span>
        </div>

        <div className="progressList" aria-label="Operator incident diagnostic timeline">
          {items.map((item) => (
            <div key={item.label} className="progressRow diagnosticTimelineRow">
              <span>
                <strong>{item.label}</strong>
                <span className="mutedText"> · {item.detail}</span>
                {item.command ? <pre className="codePanel mono wrapAnywhere compactCodePanel">{item.command}</pre> : null}
              </span>
              <span className="buttonRow">
                {item.command ? <button className="btn ghost" type="button" onClick={() => copyCommand(item.command)}>Copy</button> : null}
                <span className={statusClass(item.status)}>{item.status === "ok" ? "OK" : item.status === "warn" ? "Needs attention" : "Observed"}</span>
              </span>
            </div>
          ))}
        </div>

        <div className="calloutInfo">
          This timeline is not a mutating incident action lane. Use it to collect evidence before running existing explicit tools such as <span className="mono">build_operator_incident_report.py</span> or <span className="mono">run_operator_incident_lane.py</span>.
        </div>
      </div>
    </section>
  );
}
