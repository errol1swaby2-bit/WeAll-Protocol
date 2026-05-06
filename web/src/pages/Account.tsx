import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import FeedView from "../components/FeedView";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { createNodeKeyFile, downloadNodeKeyFile, type NodeKeyFile } from "../auth/nodeKeys";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { refreshMutationSlices } from "../lib/revalidation";
import { nav } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { verificationLabel } from "../lib/userLanguage";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || e?.error?.message || e?.message || "error";
  return { msg, details };
}

function reputationTone(rep: number): { label: string; note: string } {
  if (rep <= -1) {
    return {
      label: "Auto-ban threshold",
      note: "This account is at or below the network ban boundary.",
    };
  }
  if (rep < 0) {
    return {
      label: "At risk",
      note: "The account is below neutral and needs recovery.",
    };
  }
  if (rep < 0.75) {
    return {
      label: "Building trust",
      note: "Participation is possible, but the account is not in the higher-trust posting band.",
    };
  }
  return {
    label: "Strong standing",
    note: "Reputation is in the creator-safe range.",
  };
}

function num(v: any, fallback = 0): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function asRecord(v: any): Record<string, any> {
  return v && typeof v === "object" && !Array.isArray(v) ? v : {};
}

type DeviceRecord = {
  deviceId: string;
  device_type?: string;
  kind?: string;
  type?: string;
  label?: string | null;
  pubkey?: string | null;
  revoked?: boolean;
  [key: string]: any;
};

function isNodeDevice(deviceId: string, rec: DeviceRecord): boolean {
  const did = String(deviceId || "").trim();
  const deviceType = String(rec?.device_type || rec?.kind || rec?.type || "")
    .trim()
    .toLowerCase();
  const label = String(rec?.label || "").trim().toLowerCase();
  return deviceType === "node" || did.startsWith("node:") || label.startsWith("node");
}

export default function Account({ account }: { account: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const acct = useMemo(() => normalizeAccount(account), [account]);
  const session = getSession();
  const viewer = session ? normalizeAccount(session.account) : "";
  const isSelf = !!viewer && viewer === acct;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();

  const [poh, setPoh] = useState<any>(null);
  const [nonce, setNonce] = useState<any>(null);
  const [acctView, setAcctView] = useState<any>(null);
  const [registered, setRegistered] = useState<any>(null);
  const [following, setFollowing] = useState<any>(null);
  const [socialMe, setSocialMe] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  const [opErr, setOpErr] = useState<{ msg: string; details: any } | null>(null);
  const [opResult, setOpResult] = useState<any>(null);
  const [busy, setBusy] = useState<"register" | "enroll" | null>(null);
  const [nodeDeviceId, setNodeDeviceId] = useState<string>("");
  const [nodeLabel, setNodeLabel] = useState<string>("Primary node");
  const [nodeKeyFile, setNodeKeyFile] = useState<NodeKeyFile | null>(null);

  async function load(): Promise<void> {
    setErr(null);
    const headers = isSelf ? getAuthHeaders(acct) : undefined;

    const calls: Record<string, Promise<any>> = {
      poh: weall.pohState(acct, base),
      nonce: weall.accountNonce(acct, base),
      account: weall.account(acct, base),
      registered: weall.accountRegistered(acct, base),
      following: weall.socialFollowing(acct, base),
    };

    if (isSelf) calls.socialMe = weall.socialMe(base, headers);

    const entries = Object.entries(calls);
    const settled = await Promise.allSettled(entries.map(([, p]) => p));
    const out: Record<string, any> = {};
    const failures: Array<{ key: string; error: any }> = [];

    settled.forEach((res, idx) => {
      const key = entries[idx][0];
      if (res.status === "fulfilled") out[key] = res.value;
      else failures.push({ key, error: res.reason });
    });

    setPoh(out.poh ?? null);
    setNonce(out.nonce ?? null);
    setAcctView(out.account ?? null);
    setRegistered(out.registered ?? null);
    setFollowing(out.following ?? null);
    setSocialMe(out.socialMe ?? null);

    if (failures.length) {
      setErr(
        prettyErr({
          message: failures.map((f) => f.key).join(", "),
          data: failures,
        }),
      );
    }
  }

  useEffect(() => {
    void load();
  }, [acct, isSelf]);

  useEffect(() => {
    if (!nodeDeviceId) setNodeDeviceId(`node:${acct}`);
  }, [acct, nodeDeviceId]);

  const state = acctView?.state ?? null;
  const refreshAccountSurface = async () => {
    await refreshMutationSlices(load, refreshAccountContext);
  };
  const tier = num(state?.poh_tier ?? poh?.poh_tier, 0);
  const reputation = num(state?.reputation ?? poh?.reputation, 0);
  const banned = !!state?.banned;
  const locked = !!state?.locked;
  const follows = Array.isArray(following?.following) ? following.following : [];
  const tone = reputationTone(reputation);
  const accountExists = !!acctView?.ok && !!state;
  const registeredState = registered?.registered ?? accountExists;
  const canLikeComment = tier >= 1 && accountExists && !banned && !locked;
  const canPost = tier >= 2 && accountExists && !banned && !locked && reputation >= 0.75;
  const canServe = tier >= 2 && accountExists && !banned && !locked;

  const localKeypair = isSelf ? getKeypair(acct) : null;
  const localPubkey = String(localKeypair?.pubkeyB64 || "");
  const devicesById = asRecord(asRecord(state?.devices).by_id);
  const activeDevices: DeviceRecord[] = Object.entries(devicesById)
    .filter(
      ([, rec]) =>
        rec && typeof rec === "object" && (rec as Record<string, any>).revoked !== true,
    )
    .map(
      ([deviceId, rec]) =>
        ({
          deviceId,
          ...((rec as Record<string, any>) || {}),
        }) as DeviceRecord,
    );

  const nodeDevices: DeviceRecord[] = activeDevices.filter((rec) =>
    isNodeDevice(String(rec.deviceId || ""), rec),
  );
  const nodePubkey = String(nodeKeyFile?.publicKeyB64 || "").trim();
  const matchingNodeDevice =
    nodeDevices.find((rec) => !!nodePubkey && String(rec.pubkey || "") === nodePubkey) || null;
  const hasAnyNodeDevice = nodeDevices.length > 0;
  const nodeOperatorBucket = asRecord(asRecord(state?.roles).node_operators);
  const nodeOperatorById = asRecord(nodeOperatorBucket.by_id);
  const nodeOperatorRecord = asRecord(nodeOperatorById[acct]);
  const nodeOperatorEnrolled = !!nodeOperatorRecord.enrolled;
  const nodeOperatorActive =
    !!nodeOperatorRecord.active ||
    (Array.isArray(nodeOperatorBucket.active_set) &&
      nodeOperatorBucket.active_set.map((v: any) => String(v)).includes(acct));
  const nodeDeviceReady = canServe && !!nodePubkey && !!matchingNodeDevice;
  const operatorReady = nodeDeviceReady && nodeOperatorActive;
  const activationPending = nodeOperatorEnrolled && !nodeOperatorActive;
  const configDeviceId =
    String(nodeDeviceId || `node:${acct}`).trim() || `node:${acct}`;

  const configBlock = [
    `WEALL_ACCOUNT_ID=${acct}`,
    `WEALL_NODE_ID=${configDeviceId}`,
    `WEALL_PEER_ID=${configDeviceId}`,
    `WEALL_NODE_PUBKEY=${nodePubkey || "<GENERATE_NODE_KEY_FIRST>"}`,
    `WEALL_NODE_PRIVKEY_FILE=/secure/path/${nodeKeyFile ? "weall-node.key" : "weall-node-key.json"}`,
    `WEALL_NET_REQUIRE_PEER_IDENTITY=1`,
    `# Optional but recommended`,
    `# WEALL_NET_ADVERTISE_URI=tcp://your-hostname-or-ip:30303`,
  ].join("\n");

  const snapshot = resolveOnboardingSnapshot({
    account: acct,
    session: isSelf ? session : null,
    keypair: isSelf ? localKeypair : null,
    accountView: acctView,
    registrationView: registered,
  });

  const requirements = summarizeNextRequirements(snapshot);

  const localOwnership = isSelf
    ? localKeypair
      ? "This browser holds the saved account key for this account."
      : "This is your account, but this browser does not currently hold the signer."
    : "You are viewing this account publicly from outside its local session.";
  const accountPosture = !registeredState
    ? "Unregistered"
    : banned
      ? "Banned"
      : locked
        ? "Locked"
        : "Active";
  const nextUnlock = snapshot.next.label || "No immediate unlock action";
  const signerSubmission = useSignerSubmissionBusy(isSelf ? acct : null);
  const signerBusy = signerSubmission.busy;

  function generateAndDownloadNodeKey(): void {
    const next = createNodeKeyFile({
      account: acct,
      nodeId: configDeviceId,
      deviceId: configDeviceId,
      label: nodeLabel,
    });
    setNodeKeyFile(next);
    downloadNodeKeyFile(next);
  }

  async function runOperatorTx(kind: "register" | "enroll") {
    if (!isSelf) return;

    setBusy(kind);
    setOpErr(null);
    setOpResult(null);

    try {
      if (!accountExists) throw new Error("register_the_account_first");
      if (signerBusy) throw new Error("signer_submission_busy");
      if (tier < 2) throw new Error("live_verification_required_for_regular_node_onboarding");
      if (!localPubkey) throw new Error("missing_account_signer");
      if (kind === "register" && !nodePubkey) throw new Error("generate_node_key_first");

      const r = await tx.runTx({
        title: kind === "register" ? "Register node device" : "Submit node operator enrollment",
        pendingMessage: "Submitting operator action…",
        successMessage:
          kind === "register"
            ? "Node device registered."
            : "Node operator enrollment submitted\nWaiting for eligibility\nNode Operator status active\nValidator and storage responsibilities are optional opt-in responsibilities — Checking eligibility — the protocol automatically activates baseline Node Operator status once prerequisites are met. Activation now requires network approval.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () => {
          if (kind === "register") {
            return submitSignedTx({
              account: acct,
              tx_type: "ACCOUNT_DEVICE_REGISTER",
              payload: {
                device_id: configDeviceId,
                device_type: "node",
                label: String(nodeLabel || "Primary node").trim() || "Primary node",
                pubkey: nodePubkey,
              },
              base,
            });
          }
          return submitSignedTx({
            account: acct,
            tx_type: "ROLE_NODE_OPERATOR_ENROLL",
            payload: { account_id: acct },
            base,
          });
        },
      });

      setOpResult(r);
      await load();
      await refreshAccountContext();
    } catch (e: any) {
      setOpErr(prettyErr(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="pageStack pageNarrow utilityPage accountPage">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Account</div>
              <h1 className="heroTitle heroTitleSm">{acct}</h1>
              <p className="heroText">
                See this account's profile, verification status, posts, and trusted responsibilities in one place.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Status</div>
              <div className="heroInfoList">
                <span className={`statusPill ${registeredState ? "ok" : ""}`}>
                  {registeredState ? "Registered" : "Not registered"}
                </span>
                <span className={`statusPill ${tier >= 2 ? "ok" : ""}`}>{verificationLabel(tier)}</span>
                <span className={`statusPill ${!banned ? "ok" : ""}`}>
                  {banned ? "Banned" : "Not banned"}
                </span>
                <span className={`statusPill ${!locked ? "ok" : ""}`}>
                  {locked ? "Locked" : "Unlocked"}
                </span>
              </div>
            </div>
          </div>

          <div className="heroActions">
            {snapshot.next.route ? (
              <button className="btn btnPrimary" onClick={() => nav(snapshot.next.route)}>
                {snapshot.next.label}
              </button>
            ) : null}
            <button className="btn" onClick={() => nav("/verification")}>
              Open Account Verification
            </button>
            <button className="btn" onClick={() => nav("/feed")}>
              Browse feed
            </button>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Reputation</span>
              <span className="statValue">{reputation}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Interaction</span>
              <span className="statValue">{canLikeComment ? "Enabled" : "Locked"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Posting</span>
              <span className="statValue">{canPost ? "Enabled" : "Locked"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Trusted responsibility</span>
              <span className="statValue">{canServe ? "Eligible" : "Locked"}</span>
            </div>
          </div>

          <div className="detailFocusStrip utilityFocusStrip">
            <article className="detailFocusCard utilityFocusCard">
              <div className="detailFocusLabel">Profile view</div>
              <div className="detailFocusValue">Account status</div>
              <div className="detailFocusText">This page shows the account's public standing and clear next steps without exposing technical details first.</div>
            </article>
            <article className="detailFocusCard utilityFocusCard">
              <div className="detailFocusLabel">This device</div>
              <div className="detailFocusValue">{isSelf ? (localKeypair ? "Saved account key present" : "View only") : "Public view"}</div>
              <div className="detailFocusText">Some actions require this browser to hold the local account key before they can be saved.</div>
            </article>
            <article className="detailFocusCard utilityFocusCard">
              <div className="detailFocusLabel">Next step</div>
              <div className="detailFocusValue">{nextUnlock}</div>
              <div className="detailFocusText">Use the main action above when there is a setup or verification step to finish.</div>
            </article>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={refreshAccountSurface} onDismiss={() => setErr(null)} />

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Account posture</div>
          <div className="summaryCardValue">{accountPosture}</div>
          <div className="summaryCardText">
            {tone.note} Public profile information stays separate from this device's ability to save actions.
          </div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Next unlock</div>
          <div className="summaryCardValue">{nextUnlock}</div>
          <div className="summaryCardText">
            {snapshot.next.route
              ? "Use the primary action above to continue the current account setup step."
              : "This account currently has no required onboarding follow-up from this client."}
          </div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Device access</div>
          <div className="summaryCardValue">{isSelf ? "This device session" : "Public view"}</div>
          <div className="summaryCardText">{localOwnership}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Trusted responsibility prep</div>
          <div className="summaryCardValue">{operatorReady ? "Ready" : canServe ? "Almost ready" : "Locked"}</div>
          <div className="summaryCardText">
            {operatorReady
              ? "This account is activated for network helper service and has a matching node device."
              : activationPending
                ? "Enrollment is submitted. Network activation is still pending before this account can serve."
                : canServe
                  ? "Account status is sufficient, but node-device registration or operator enrollment is still incomplete."
                  : "Account status, standing, or signer prerequisites are still blocking operator setup."}
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Readiness</div>
              <h2 className="cardTitle">Account checklist</h2>
            </div>
          </div>

          <div className="infoGrid">
            {requirements.map((item) => (
              <div key={item.label} className="infoCard compact">
                <div className="infoCardHeader">
                  <span className={`statusPill ${item.ok ? "ok" : ""}`}>
                    {item.ok ? "Ready" : "Needed"}
                  </span>
                  <strong>{item.label}</strong>
                </div>
                <div className="infoCardText">{item.hint}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Capability summary</div>
                <h2 className="cardTitle">What this account can do now</h2>
              </div>
            </div>

            <div className="progressList">
              <div className="progressRow">
                <span>Like and comment</span>
                <span className={`statusPill ${canLikeComment ? "ok" : ""}`}>
                  {canLikeComment ? "Enabled" : "Locked"}
                </span>
              </div>
              <div className="progressRow">
                <span>Create posts</span>
                <span className={`statusPill ${canPost ? "ok" : ""}`}>
                  {canPost ? "Enabled" : "Locked"}
                </span>
              </div>
              <div className="progressRow">
                <span>Serve as Community Reviewer</span>
                <span className={`statusPill ${canServe ? "ok" : ""}`}>
                  {canServe ? "Eligible" : "Locked"}
                </span>
              </div>
            </div>

            <div className="infoCard">
              <div className="feedMediaTitle">{tone.label}</div>
              <div className="feedMediaMeta">{tone.note}</div>
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Social account</div>
                <h2 className="cardTitle">Account details</h2>
              </div>
            </div>

            <div className="statsGrid statsGridCompact">
              <div className="statCard">
                <span className="statLabel">Saved actions</span>
                <span className="statValue">{num(nonce?.next_nonce ?? nonce?.nonce ?? state?.nonce, 0)}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">Followers tracked</span>
                <span className="statValue">{follows.length}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">Viewer mode</span>
                <span className="statValue">{isSelf ? "Owner view" : "Public view"}</span>
              </div>
            </div>

            <details className="detailsPanel">
              <summary>Advanced: raw account and social payloads</summary>
              <pre className="codePanel mono">
                {JSON.stringify({ poh, nonce, registered, following, socialMe }, null, 2)}
              </pre>
            </details>
          </div>
        </article>
      </section>

      {isSelf ? (
        <details className="detailsPanel accountAdvancedOperatorPanel">
          <summary>Advanced: Network helper setup</summary>
          <section className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Operator setup</div>
                <h2 className="cardTitle">Regular node onboarding</h2>
              </div>
              <div className="statusSummary">
                <span className={`statusPill ${tier >= 2 ? "ok" : ""}`}>
                  {tier >= 2 ? "Live verification reached" : "Live verification needed"}
                </span>
                <span className={`statusPill ${localPubkey ? "ok" : ""}`}>
                  {localPubkey ? "Saved account key present" : "Missing saved account key"}
                </span>
                <span className={`statusPill ${nodeOperatorEnrolled ? "ok" : ""}`}>
                  {nodeOperatorEnrolled ? "Enrollment submitted" : "Enrollment needed"}
                </span>
                <span className={`statusPill ${nodeOperatorActive ? "ok" : ""}`}>
                  {nodeOperatorActive ? "Activated" : "Checking eligibility"}
                </span>
              </div>
            </div>

            <p className="heroText">
              Live verification unlocks eligibility to enroll as a node operator. Generate a separate
              node key for service operation, register that node public key to your account, then submit
              enrollment. Network service activation is approved by governance or system authority.
            </p>

            <ErrorBanner
              message={opErr?.msg}
              details={opErr?.details}
              onRetry={refreshAccountSurface}
              onDismiss={() => setOpErr(null)}
            />

            <div className="statsGrid statsGridCompact">
              <div className="statCard">
                <span className="statLabel">Account key</span>
                <span className="statValue">{localPubkey ? "Loaded" : "Missing"}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">Registered node devices</span>
                <span className="statValue">{nodeDevices.length}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">Enrollment</span>
                <span className="statValue">{nodeOperatorEnrolled ? "Submitted" : "Not submitted"}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">Activation</span>
                <span className="statValue">{nodeOperatorActive ? "Approved" : "Pending"}</span>
              </div>
            </div>

            <div className="infoCard">
              <div className="feedMediaTitle">Operator checklist</div>
              <div className="progressList">
                <div className="progressRow">
                  <span>1. Account exists and is registered</span>
                  <span className={`statusPill ${registeredState ? "ok" : ""}`}>
                    {registeredState ? "Ready" : "Needed"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>2. Live verification complete</span>
                  <span className={`statusPill ${tier >= 2 ? "ok" : ""}`}>
                    {tier >= 2 ? "Ready" : "Needed"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>3. Account key available to sign enrollment</span>
                  <span className={`statusPill ${localPubkey ? "ok" : ""}`}>
                    {localPubkey ? "Ready" : "Missing"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>4. Separate node key generated and downloaded</span>
                  <span className={`statusPill ${nodePubkey ? "ok" : ""}`}>
                    {nodePubkey ? "Ready" : "Needed"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>5. Node device registered with node public key</span>
                  <span className={`statusPill ${matchingNodeDevice ? "ok" : ""}`}>
                    {matchingNodeDevice ? "Ready" : "Not yet"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>6. Node operator enrollment submitted</span>
                  <span className={`statusPill ${nodeOperatorEnrolled ? "ok" : ""}`}>
                    {nodeOperatorEnrolled ? "Submitted" : "Pending"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>7. Node Operator status active</span>
                  <span className={`statusPill ${nodeOperatorActive ? "ok" : ""}`}>
                    {nodeOperatorActive ? "Approved" : "Awaiting network approval"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>8. Copy config into node software and boot service mode</span>
                  <span className={`statusPill ${operatorReady ? "ok" : ""}`}>
                    {operatorReady ? "Ready to boot" : "Wait for activation"}
                  </span>
                </div>
              </div>
            </div>

            <div className="grid2">
              <div className="formStack">
                <label>
                  <div className="eyebrow">Node device id</div>
                  <input
                    value={nodeDeviceId}
                    onChange={(e) => setNodeDeviceId(e.target.value)}
                    placeholder={`node:${acct}`}
                  />
                </label>
                <label>
                  <div className="eyebrow">Node label</div>
                  <input
                    value={nodeLabel}
                    onChange={(e) => setNodeLabel(e.target.value)}
                    placeholder="Primary node"
                  />
                </label>
                <div className="infoCard compact">
                  <div className="feedMediaTitle">Separate node key</div>
                  <div className="feedMediaMeta">
                    Generate a dedicated operation key for this node. Do not use your account recovery
                    key as the node server key. Download the file and place it on the node host securely.
                  </div>
                  <div className="buttonRow">
                    <button className="btn" disabled={!canServe || busy !== null} onClick={generateAndDownloadNodeKey}>
                      Generate and download node key
                    </button>
                  </div>
                  {nodePubkey ? <div className="feedMediaMeta mono">Node public key: {nodePubkey}</div> : null}
                </div>
                <div className="buttonRow buttonRowWide">
                  <button
                    className="btn btnPrimary"
                    disabled={
                      busy !== null || !canServe || !localPubkey || !nodePubkey || !!matchingNodeDevice
                    }
                    onClick={() => void runOperatorTx("register")}
                  >
                    {busy === "register"
                      ? "Registering…"
                      : matchingNodeDevice
                        ? "Node device registered"
                        : "Register node device"}
                  </button>
                  <button
                    className="btn"
                    disabled={busy !== null || !canServe || !matchingNodeDevice || nodeOperatorEnrolled}
                    onClick={() => void runOperatorTx("enroll")}
                  >
                    {busy === "enroll"
                      ? "Submitting enrollment…"
                      : nodeOperatorEnrolled
                        ? "Enrollment submitted"
                        : "Submit node operator enrollment"}
                  </button>
                </div>
                {!localPubkey ? (
                  <div className="emptyState compactEmpty">
                    <div className="emptyTitle">This browser is missing the account signer</div>
                    <div className="emptyText">
                      Import or restore the account recovery key in Settings first, then return here to sign node registration.
                    </div>
                    <div className="buttonRow">
                      <button className="btn" onClick={() => nav("/settings")}>
                        Open settings
                      </button>
                    </div>
                  </div>
                ) : null}
                {nodeOperatorEnrolled ? (
                  <div className="infoCard compact">
                    <div className="feedMediaTitle">
                      {nodeOperatorActive ? "Node operator activated" : "Checking eligibility"}
                    </div>
                    <div className="feedMediaMeta">
                      {nodeOperatorActive
                        ? "Network approval is complete. This account can use the registered node device for service mode."
                        : "Your enrollment is submitted. Network approval is required before this account can serve as a node operator."}
                    </div>
                  </div>
                ) : null}
              </div>

              <div className="formStack">
                <div className="feedMediaCard">
                  <div className="feedMediaTitle">Current node-device state</div>
                  <div className="feedMediaMeta">
                    {hasAnyNodeDevice
                      ? `This account currently has ${nodeDevices.length} active node device${nodeDevices.length === 1 ? "" : "s"}.`
                      : "No active node device is currently registered for this account."}
                  </div>
                </div>

                {nodeDevices.length ? (
                  <div className="milestoneList">
                    {nodeDevices.map((rec) => (
                      <div key={String(rec.deviceId)} className="feedMediaCard">
                        <div className="feedMediaTitle mono">{String(rec.deviceId)}</div>
                        <div className="feedMediaMeta">
                          {String(rec.label || rec.device_type || "node")} ·{" "}
                          {String(rec.pubkey || "(no pubkey)")}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            </div>

            <div className="feedMediaCard">
              <div className="feedMediaTitle">Node config block</div>
              <div className="feedMediaMeta">
                Use this only after generating the separate node key, registering its public key,
                submitting enrollment, and receiving network activation. The node software should read
                the node private key from a protected file, not from your account recovery key.
              </div>
            </div>
            <pre className="codePanel mono">{configBlock}</pre>

            <details className="detailsPanel">
              <summary>Why this is required</summary>
              <div className="infoCard">
                <p>
                  The network helper gate expects an authoritative node device record, a submitted
                  node operator enrollment, and network activation. Enrollment is user-submitted;
                  activation is governance or system controlled. Validator status is a separate role.
                </p>
              </div>
            </details>

            {opResult ? (
              <details className="detailsPanel" open>
                <summary>Last operator action result</summary>
                <pre className="codePanel mono">{JSON.stringify(opResult, null, 2)}</pre>
              </details>
            ) : null}
          </div>
          </section>
        </details>
      ) : null}

      <div>
        <FeedView
          base={base}
          title="Public posts"
          scope={{ kind: "account", account: acct }}
          defaultSort="new"
          defaultFilters={{ visibility: "public" }}
        />
      </div>
    </div>
  );
}
