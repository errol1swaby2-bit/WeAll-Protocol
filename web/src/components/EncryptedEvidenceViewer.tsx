import React, { useEffect, useMemo, useRef, useState } from "react";

import { weall } from "../api/weall";
import {
  decryptEvidenceCiphertext,
  loadEvidenceKemKeypair,
  unwrapEvidenceKeyForRecipient,
} from "../auth/evidenceCrypto";
import { getAuthHeaders } from "../auth/session";
import { normalizeAccount } from "../auth/keys";

type EvidenceItem = {
  evidenceId: string;
  ciphertextCid: string;
  ciphertextCommitment: string;
  mimeType: string;
  filename: string;
};

type ViewerState = {
  busy?: boolean;
  error?: string;
  objectUrl?: string;
};

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

function findRecipientEnvelope(bind: unknown, account: string): Record<string, unknown> | null {
  const envelopes = asRecord(asRecord(bind).key_envelope_commitments ?? asRecord(bind).keyEnvelopes);
  const normalized = normalizeAccount(account);
  for (const [recipient, envelope] of Object.entries(envelopes)) {
    if (normalizeAccount(recipient) === normalized && envelope && typeof envelope === "object" && !Array.isArray(envelope)) {
      return envelope as Record<string, unknown>;
    }
  }
  return null;
}

export default function EncryptedEvidenceViewer(props: {
  base: string;
  account: string;
  caseId: string;
  applicant: string;
  items: EvidenceItem[];
  evidenceBinds: Record<string, unknown>;
}): JSX.Element {
  const { base, account, caseId, applicant, items, evidenceBinds } = props;
  const [states, setStates] = useState<Record<string, ViewerState>>({});
  const objectUrls = useRef<Set<string>>(new Set());

  const cleanAccount = normalizeAccount(account);
  const cleanApplicant = normalizeAccount(applicant);
  const evidenceContext = useMemo(
    () => `weall:poh-evidence:v1:${String(caseId || "").trim()}:${cleanApplicant}`,
    [caseId, cleanApplicant],
  );

  useEffect(() => {
    return () => {
      for (const objectUrl of objectUrls.current) URL.revokeObjectURL(objectUrl);
      objectUrls.current.clear();
    };
  }, []);

  async function decryptItem(item: EvidenceItem): Promise<void> {
    const evidenceId = String(item.evidenceId || "").trim();
    if (!evidenceId || !item.ciphertextCid) return;
    const previousUrl = states[evidenceId]?.objectUrl;
    if (previousUrl) {
      URL.revokeObjectURL(previousUrl);
      objectUrls.current.delete(previousUrl);
    }
    setStates((prev) => ({ ...prev, [evidenceId]: { busy: true } }));

    try {
      const keypair = loadEvidenceKemKeypair(cleanAccount);
      if (!keypair?.secretKeyB64) {
        throw new Error("This browser does not have your ML-KEM evidence key. Restore your recovery file before reviewing protected evidence.");
      }
      const directBind = evidenceBinds[evidenceId];
      const matchingBind = directBind || Object.values(evidenceBinds).find((value) =>
        String(asRecord(value).evidence_id || "").trim() === evidenceId,
      );
      const envelope = findRecipientEnvelope(matchingBind, cleanAccount);
      if (!envelope) throw new Error("No case-scoped key envelope is available for this accepted reviewer.");

      const recipientContext = `${evidenceContext}:${cleanAccount}`;
      const contentKey = await unwrapEvidenceKeyForRecipient({
        envelope,
        recipientSecretKeyB64: keypair.secretKeyB64,
        context: recipientContext,
      });

      const response = await fetch(weall.mediaProxyUrl(item.ciphertextCid, base), {
        method: "GET",
        headers: getAuthHeaders(cleanAccount),
        credentials: "same-origin",
        cache: "no-store",
      });
      if (!response.ok) throw new Error(`Encrypted evidence fetch failed with HTTP ${response.status}.`);
      const ciphertext = await response.arrayBuffer();
      const plaintext = await decryptEvidenceCiphertext({
        ciphertext,
        contentKey,
        context: evidenceContext,
        expectedCiphertextCommitment: item.ciphertextCommitment,
        mimeType: item.mimeType || "video/webm",
      });
      const objectUrl = URL.createObjectURL(plaintext);
      objectUrls.current.add(objectUrl);
      setStates((prev) => ({ ...prev, [evidenceId]: { objectUrl } }));
    } catch (error: any) {
      setStates((prev) => ({
        ...prev,
        [evidenceId]: { error: String(error?.message || error || "Unable to decrypt evidence.") },
      }));
    }
  }

  if (!items.length) return <></>;
  return (
    <div className="infoCard" data-testid="encrypted-reviewer-evidence">
      <div className="feedMediaTitle">Restricted encrypted reviewer evidence</div>
      <p className="cardDesc">
        Ciphertext is fetched only after chain-visible reviewer acceptance. The case key is unwrapped and the recording is decrypted only in this browser session; plaintext is never uploaded or persisted by WeAll.
      </p>
      <div className="pageStack">
        {items.map((item) => {
          const state = states[item.evidenceId] || {};
          return (
            <div className="formStack" key={item.evidenceId}>
              <div className="feedMediaMeta mono">{item.filename || item.evidenceId}</div>
              {state.objectUrl ? (
                <video
                  controls
                  controlsList="nodownload noplaybackrate"
                  disablePictureInPicture
                  preload="metadata"
                  src={state.objectUrl}
                  data-testid={`decrypted-evidence-${item.evidenceId}`}
                />
              ) : (
                <button
                  className="btn btnPrimary"
                  type="button"
                  disabled={state.busy}
                  onClick={() => void decryptItem(item)}
                  data-testid={`decrypt-evidence-${item.evidenceId}`}
                >
                  {state.busy ? "Decrypting…" : "Decrypt restricted evidence"}
                </button>
              )}
              {state.error ? <div className="calloutWarn">{state.error}</div> : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}
