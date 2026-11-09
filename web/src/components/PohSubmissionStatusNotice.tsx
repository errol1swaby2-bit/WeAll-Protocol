import type { PohJournalKind, PohJournalRead } from "../lib/pohSubmissionJournal";
import { normalizePohJournalBase } from "../lib/pohSubmissionJournal";

type Props = {
  kind: PohJournalKind;
  journal: PohJournalRead;
  currentNodeBase: string;
  onTrack: () => void;
};

/**
 * A local warning, never a case receipt or an identity verification claim.
 * The journal stores no proof material; its absence alone cannot attest that
 * the network has no pending case.
 */
export default function PohSubmissionStatusNotice({ kind, journal, currentNodeBase, onTrack }: Props): JSX.Element | null {
  if (journal.status === "none") return null;
  const label = kind === "async" ? "recorded evidence" : "live verification";
  const pending = journal.status === "pending" ? journal.record : null;
  const wrongNode = pending !== null && pending.nodeBase !== normalizePohJournalBase(currentNodeBase);
  return (
    <div className="calloutDanger" role="status" aria-live="polite" data-testid={`poh-${kind}-interrupted-warning`}>
      <strong>Earlier {label} may still be in progress.</strong>
      {pending ? (
        <>
          <p>
            This device recorded the local step <strong>{pending.phase.replace(/_/g, " ")}</strong>.
            That is not evidence of a successful upload, confirmed transaction, reviewer decision or tier change.
          </p>
          {pending.caseId ? <p>Original case reference: <code>{pending.caseId}</code></p> : (
            <p>The live request was interrupted before a canonical case reference could be recorded.</p>
          )}
          {pending.txId ? <p>Recorded transaction reference: <code>{pending.txId}</code></p> : null}
          {wrongNode ? <p>The configured node has changed. Reconcile the earlier request using the original node and its authenticated canonical history.</p> : null}
        </>
      ) : (
        <p>The browser cannot read its local submission record. This is an unknown state, not permission to repeat a signed request. Verify local storage and prior network activity before continuing.</p>
      )}
      <p>New submissions are disabled until the original case is independently visible on the configured node. Refreshing history does not resend a transaction.</p>
      <button type="button" className="btn" onClick={onTrack}>Check case history</button>
    </div>
  );
}
