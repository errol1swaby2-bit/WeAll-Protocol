import React from "react";

export type TxTimelineEvidence = "observed" | "pending" | "unavailable" | "terminal" | "rejected";

export type TxTimelineStep = {
  label: string;
  done: boolean;
  detail?: string;
  evidence?: TxTimelineEvidence;
};

function evidenceLabel(step: TxTimelineStep): string {
  if (step.evidence === "terminal") return "Terminal evidence";
  if (step.evidence === "rejected") return "Rejected";
  if (step.evidence === "unavailable") return "Unknown / unavailable";
  if (step.done || step.evidence === "observed") return "Observed";
  return "Pending evidence";
}

function evidenceClass(step: TxTimelineStep): string {
  if (step.evidence === "rejected") return "warn";
  if (step.evidence === "terminal") return "ok";
  if (step.evidence === "unavailable") return "";
  return step.done || step.evidence === "observed" ? "ok" : "";
}

export default function TxPropagationTimeline({
  title,
  steps,
}: {
  title: string;
  steps: TxTimelineStep[];
}): JSX.Element {
  return (
    <div className="progressList compact" aria-label={`Propagation lifecycle for ${title}; peer propagation timeline`}>
      <div className="mutedText">Propagation lifecycle separates local submission, local acceptance, queued/pending, forwarded/gossiped, included in block, finalized/confirmed, rejected, and removed from mempool. It also renders unknown/unavailable evidence as non-final Pending evidence.</div>
      <div className="mutedText">Mempool acceptance, observer queueing, and gossip propagation are never rendered as confirmation by themselves.</div>
      {steps.map((step) => (
        <div key={step.label} className="progressRow">
          <span>
            {step.label}
            {step.detail ? <span className="mutedText"> · {step.detail}</span> : null}
          </span>
          <span className={`statusPill ${evidenceClass(step)}`}>{evidenceLabel(step)}</span>
        </div>
      ))}
    </div>
  );
}
