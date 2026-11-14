type Step = { id: string; label: string };

type Props = {
  label: string;
  steps: readonly Step[];
  current: string;
  detail?: string;
};

/**
 * Non-interactive, accessible progress indicator. This is LOCAL UI guidance,
 * not an assertion that a PoH transaction was accepted or a tier awarded.
 */
export default function PohStepProgress({ label, steps, current, detail }: Props): JSX.Element {
  const index = steps.findIndex((step) => step.id === current);
  const active = index >= 0 ? steps[index] : null;
  return (
    <div data-testid="poh-guided-step-progress">
      <ol
        className="statusRowWrap"
        aria-label={label}
        style={{ listStyle: "none", padding: 0, margin: 0 }}
      >
        {steps.map((step, stepIndex) => (
          <li
            key={step.id}
            className={`statusPill ${step.id === current ? "ok" : ""}`}
            aria-current={step.id === current ? "step" : undefined}
          >
            {stepIndex + 1}. {step.label}
          </li>
        ))}
      </ol>
      <p className="miniMuted" role="status" aria-live="polite">
        {active ? `Step ${index + 1} of ${steps.length}: ${active.label}` : "Current step is unavailable."}
        {detail ? ` ${detail}` : ""}
      </p>
    </div>
  );
}
