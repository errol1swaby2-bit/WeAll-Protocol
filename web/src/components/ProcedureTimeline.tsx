import React from "react";

import { estimateProcedureClock } from "../lib/procedureClock";

type Props = {
  title: string;
  stage: string;
  currentHeight?: unknown;
  deadlineHeight?: unknown;
  targetBlockIntervalMs?: unknown;
  authorityLabel?: string;
  nextAction?: string;
  children?: React.ReactNode;
};

export default function ProcedureTimeline({
  title,
  stage,
  currentHeight,
  deadlineHeight,
  targetBlockIntervalMs,
  authorityLabel = "Finalized block height is authority. Time shown here is only an estimate.",
  nextAction = "Follow the stage-specific actions shown below.",
  children,
}: Props): JSX.Element {
  const clock = estimateProcedureClock({ currentHeight, deadlineHeight, targetBlockIntervalMs });
  return (
    <section className="card procedureTimelineCard">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Constitutional procedure</div>
            <h2 className="cardTitle">{title}</h2>
          </div>
          <div className="statusSummary">
            <span className="statusPill">Stage: {stage || "unknown"}</span>
            <span className="statusPill">Block clock</span>
          </div>
        </div>
        <div className="summaryCardGrid">
          <article className="summaryCard">
            <div className="summaryCardLabel">Current procedure block</div>
            <div className="summaryCardValue mono">{clock.currentHeight || "—"}</div>
            <div className="summaryCardText">Backend/protocol supplied height.</div>
          </article>
          <article className="summaryCard">
            <div className="summaryCardLabel">Next deadline block</div>
            <div className="summaryCardValue mono">{clock.hasDeadline ? clock.deadlineHeight : "—"}</div>
            <div className="summaryCardText">Stages open only when backend/protocol state reaches this block height.</div>
          </article>
          <article className="summaryCard">
            <div className="summaryCardLabel">Blocks remaining</div>
            <div className="summaryCardValue mono">{clock.hasDeadline ? clock.blocksRemaining : "—"}</div>
            <div className="summaryCardText">No browser timer can advance this stage.</div>
          </article>
          <article className="summaryCard">
            <div className="summaryCardLabel">Estimated time</div>
            <div className="summaryCardValue">{clock.hasDeadline ? clock.estimatedLabel : "not scheduled"}</div>
            <div className="summaryCardText">Display estimate only. Backend block height is protocol truth; wall-clock time cannot advance a stage.</div>
          </article>
        </div>
        <div className="calloutInfo">{authorityLabel}</div>
        <div className="cardDesc">{nextAction}</div>
        {children}
      </div>
    </section>
  );
}
