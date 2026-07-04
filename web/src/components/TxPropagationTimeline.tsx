import React from "react";

export type TxTimelineStep = {
  label: string;
  done: boolean;
  detail?: string;
};

export default function TxPropagationTimeline({
  title,
  steps,
}: {
  title: string;
  steps: TxTimelineStep[];
}): JSX.Element {
  return (
    <div className="progressList compact" aria-label={`Propagation lifecycle for ${title}; peer propagation timeline`}>
      <div className="mutedText">Propagation lifecycle separates local submission, local acceptance, queued/pending, forwarded/gossiped, included in block, finalized/confirmed, rejected, and removed from mempool. Unknown propagation remains Pending evidence.</div>
      {steps.map((step) => (
        <div key={step.label} className="progressRow">
          <span>
            {step.label}
            {step.detail ? <span className="mutedText"> · {step.detail}</span> : null}
          </span>
          <span className={`statusPill ${step.done ? "ok" : ""}`}>{step.done ? "Observed" : "Pending evidence"}</span>
        </div>
      ))}
    </div>
  );
}
