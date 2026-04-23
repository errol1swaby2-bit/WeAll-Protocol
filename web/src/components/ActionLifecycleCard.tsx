import React from "react";

const STEPS = [
  { key: "validating", label: "Validating", detail: "Check local prerequisites and serialize the signer lane before submission." },
  { key: "submitting", label: "Submitting", detail: "Send the signed transaction to the node and wait for the first authoritative response." },
  { key: "recorded", label: "Recorded", detail: "A transaction id exists or the backend reports that the action has been accepted." },
  { key: "refreshing", label: "Reconciling", detail: "Refresh the affected route and supporting state slices until the object is visible." },
  { key: "confirmed", label: "Visible confirmed", detail: "The action is now visible on the dependent route or object surface." },
  { key: "failed", label: "Failed", detail: "Show the reason clearly and keep the retry path honest." },
] as const;

export default function ActionLifecycleCard({
  title = "Submission lifecycle",
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
            <div className="eyebrow">Lifecycle contract</div>
            <h2 className="cardTitle">{title}</h2>
            <div className="cardDesc">
              {intro ||
                "Every signed action on this page should move through the same explicit states so route truth stays aligned with chain truth."}
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
