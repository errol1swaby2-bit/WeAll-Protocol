import React from "react";

import type { Requirement } from "../lib/capabilityMessages";

export default function RequirementList({
  title = "To use this action, you need:",
  requirements,
}: {
  title?: string;
  requirements?: Requirement[] | null;
}): JSX.Element | null {
  const items = (requirements || []).filter(Boolean);
  if (!items.length) return null;

  return (
    <div className="requirementList" role="list" aria-label={title}>
      <div className="requirementListTitle">{title}</div>
      {items.map((item, index) => (
        <div key={`${item.label}-${index}`} className={`requirementRow ${item.satisfied ? "requirementRow-ok" : "requirementRow-blocked"}`} role="listitem">
          <span className="requirementMark" aria-hidden="true">
            {item.satisfied ? "✓" : "✕"}
          </span>
          <span className="requirementText">
            <strong>{item.label}</strong>
            {item.helpText ? <span>{item.helpText}</span> : null}
          </span>
        </div>
      ))}
    </div>
  );
}
