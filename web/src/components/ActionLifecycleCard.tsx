import React from "react";

const STEPS = [
  { key: "ready", label: "Ready", detail: "The page has what it needs for the user to begin." },
  { key: "saving", label: "Saving", detail: "The action is being sent and duplicate clicks are blocked." },
  { key: "done", label: "Done", detail: "The action was accepted or recorded." },
  { key: "updating", label: "Updating", detail: "The page is refreshing until the result is visible." },
  { key: "visible", label: "Visible", detail: "The result is now shown on the affected page." },
  { key: "failed", label: "Failed", detail: "The user sees a plain-language reason and an honest next step." },
] as const;

export default function ActionLifecycleCard({
  title = "Action lifecycle",
  intro,
}: {
  title?: string;
  intro?: string;
}): JSX.Element {
  return (
    <section className="card">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">User feedback contract</div>
            <h2 className="cardTitle">{title}</h2>
            <div className="cardDesc">
              {intro ||
                "Every important action should move through clear, human-readable states so users know when something is saving, done, updating, or blocked."}
            </div>
          </div>
        </div>
        <div className="surfaceBoundaryList">
          {STEPS.map((step) => (
            <span key={step.key} className="surfaceBoundaryTag" title={step.detail}>
              {step.label}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
