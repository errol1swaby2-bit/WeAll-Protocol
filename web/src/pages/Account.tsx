import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import FeedView from "../components/FeedView";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { nav } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";

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
  const [busy, setBusy] = useState<"register" | "enroll" | "activate" | null>(null);
  const [nodeDeviceId, setNodeDeviceId] = useState<string>("");
  const [nodeLabel, setNodeLabel] = useState<string>("Primary node");

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
  const canServe = tier >= 3 && accountExists && !banned && !locked;

  const localKeypair = isSelf ? getKeypair(acct) : null;
  const localPubkey = String(localKeypair?.pubkeyB64 || "");
  const localSecretKey = String(localKeypair?.secretKeyB64 || "");
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
  const matchingNodeDevice =
    nodeDevices.find((rec) => String(rec.pubkey || "") === localPubkey) || null;
  const hasAnyNodeDevice = nodeDevices.length > 0;
  const operatorReady = canServe && !!localPubkey && !!matchingNodeDevice;
  const configDeviceId =
    String(nodeDeviceId || `node:${acct}`).trim() || `node:${acct}`;

  const configBlock = [
    `WEALL_ACCOUNT_ID=${acct}`,
    `WEALL_NODE_ID=${acct}`,
    `WEALL_PEER_ID=${acct}`,
    `WEALL_NODE_PUBKEY=${localPubkey || "<PASTE_NODE_PUBKEY>"}`,
    `WEALL_NODE_PRIVKEY=${localSecretKey || "<PASTE_NODE_PRIVKEY>"}`,
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
      ? "This browser holds the local signer for this account."
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

  async function runOperatorTx(kind: "register" | "enroll" | "activate") {
    if (!isSelf) return;

    setBusy(kind);
    setOpErr(null);
    setOpResult(null);

    try {
      if (!accountExists) throw new Error("register_the_account_first");
      if (signerBusy) throw new Error("signer_submission_busy");
      if (tier < 3) throw new Error("tier3_required_for_regular_node_onboarding");
      if (!localPubkey) throw new Error("missing_local_keypair");

      const r = await tx.runTx({
        title:
          kind === "register"
            ? "Register node device"
            : kind === "enroll"
              ? "Enroll node operator"
              : "Activate node operator",
        pendingMessage: "Submitting operator action…",
        successMessage:
          kind === "register"
            ? "Node device registered."
            : kind === "enroll"
              ? "Node operator enrollment submitted."
              : "Node operator activation submitted.",
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
                pubkey: localPubkey,
              },
              base,
            });
          }
          if (kind === "enroll") {
            return submitSignedTx({
              account: acct,
              tx_type: "ROLE_NODE_OPERATOR_ENROLL",
              payload: { account_id: acct },
              base,
            });
          }
          return submitSignedTx({
            account: acct,
            tx_type: "ROLE_NODE_OPERATOR_ACTIVATE",
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
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Account</div>
              <h1 className="heroTitle heroTitleSm">{acct}</h1>
              <p className="heroText">
                This page maps backend account state into practical readiness:
                registration, PoH tier, reputation, posting rights, juror or steward
                access, and node-operator preparation.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Status</div>
              <div className="heroInfoList">
                <span className={`statusPill ${registeredState ? "ok" : ""}`}>
                  {registeredState ? "Registered" : "Not registered"}
                </span>
                <span className={`statusPill ${tier >= 2 ? "ok" : ""}`}>Tier {tier}</span>
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
            <button className="btn" onClick={() => nav("/poh")}>
              Open PoH
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
              <span className="statLabel">Steward role</span>
              <span className="statValue">{canServe ? "Eligible" : "Locked"}</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Account posture</div>
          <div className="summaryCardValue">{accountPosture}</div>
          <div className="summaryCardText">
            {tone.note} Public account view and authoritative standing stay separate from local device state.
          </div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Next unlock</div>
          <div className="summaryCardValue">{nextUnlock}</div>
          <div className="summaryCardText">
            {snapshot.next.route
              ? "Use the primary action above to continue the current protocol progression step."
              : "This account currently has no required onboarding follow-up from this client."}
          </div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Local ownership</div>
          <div className="summaryCardValue">{isSelf ? "This device session" : "Public view"}</div>
          <div className="summaryCardText">{localOwnership}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Node operator prep</div>
          <div className="summaryCardValue">{operatorReady ? "Ready" : canServe ? "Almost ready" : "Locked"}</div>
          <div className="summaryCardText">
            {operatorReady
              ? "A matching node device is already present for the local signer."
              : canServe
                ? "Tier and account posture are sufficient, but the node device record or signer alignment is still incomplete."
                : "Tier, account posture, or signer prerequisites are still blocking operator setup."}
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Readiness</div>
              <h2 className="cardTitle">Backend-aligned account checklist</h2>
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
                <span>Serve as juror / steward</span>
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
                <div className="eyebrow">Social + chain</div>
                <h2 className="cardTitle">Live account markers</h2>
              </div>
            </div>

            <div className="statsGrid statsGridCompact">
              <div className="statCard">
                <span className="statLabel">Nonce</span>
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
              <summary>Raw account + social payloads</summary>
              <pre className="codePanel mono">
                {JSON.stringify({ poh, nonce, registered, following, socialMe }, null, 2)}
              </pre>
            </details>
          </div>
        </article>
      </section>

      {isSelf ? (
        <section className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Operator setup</div>
                <h2 className="cardTitle">Regular node onboarding</h2>
              </div>
              <div className="statusSummary">
                <span className={`statusPill ${tier >= 3 ? "ok" : ""}`}>
                  {tier >= 3 ? "Tier 3 reached" : `Tier ${tier}`}
                </span>
                <span className={`statusPill ${localPubkey ? "ok" : ""}`}>
                  {localPubkey ? "Local signer present" : "Missing local signer"}
                </span>
                <span className={`statusPill ${operatorReady ? "ok" : ""}`}>
                  {operatorReady ? "Node-ready" : "Not ready"}
                </span>
              </div>
            </div>

            <p className="heroText">
              Tier 3 unlocks operator eligibility. To boot a regular node, this account
              needs a live local signer, an on-chain node-device registration tied to that
              signer pubkey, and matching node config in the node software.
            </p>

            <ErrorBanner
              message={opErr?.msg}
              details={opErr?.details}
              onRetry={load}
              onDismiss={() => setOpErr(null)}
            />

            <div className="statsGrid statsGridCompact">
              <div className="statCard">
                <span className="statLabel">Local signer pubkey</span>
                <span className="statValue">{localPubkey ? "Loaded" : "Missing"}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">Registered node devices</span>
                <span className="statValue">{nodeDevices.length}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">Matching device</span>
                <span className="statValue">{matchingNodeDevice ? "Yes" : "No"}</span>
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
                  <span>2. Tier 3 Proof of Humanity</span>
                  <span className={`statusPill ${tier >= 3 ? "ok" : ""}`}>
                    {tier >= 3 ? "Ready" : `Tier ${tier}`}
                  </span>
                </div>
                <div className="progressRow">
                  <span>3. Local signer available on this device</span>
                  <span className={`statusPill ${localPubkey ? "ok" : ""}`}>
                    {localPubkey ? "Ready" : "Missing"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>4. Node device registered with same pubkey</span>
                  <span className={`statusPill ${matchingNodeDevice ? "ok" : ""}`}>
                    {matchingNodeDevice ? "Ready" : "Not yet"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>5. Copy env block into node software and boot</span>
                  <span className={`statusPill ${operatorReady ? "ok" : ""}`}>
                    {operatorReady ? "Ready to boot" : "Pending"}
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
                <div className="buttonRow buttonRowWide">
                  <button
                    className="btn btnPrimary"
                    disabled={
                      busy !== null || !canServe || !localPubkey || !!matchingNodeDevice
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
                    disabled={busy !== null || !canServe || !matchingNodeDevice}
                    onClick={() => void runOperatorTx("enroll")}
                  >
                    {busy === "enroll" ? "Enrolling…" : "Enroll node operator role"}
                  </button>
                  <button
                    className="btn"
                    disabled={busy !== null || !canServe || !matchingNodeDevice}
                    onClick={() => void runOperatorTx("activate")}
                  >
                    {busy === "activate" ? "Activating…" : "Activate node operator role"}
                  </button>
                </div>
                {!localPubkey ? (
                  <div className="emptyState compactEmpty">
                    <div className="emptyTitle">This device is missing the node signer</div>
                    <div className="emptyText">
                      Import or restore the account keypair in Settings first, then return here.
                    </div>
                    <div className="buttonRow">
                      <button className="btn" onClick={() => nav("/settings")}>
                        Open settings
                      </button>
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
                Use the same account id and signer keypair that was registered on-chain.
                The node software also needs the private key to sign peer-identity
                handshakes.
              </div>
            </div>
            <pre className="codePanel mono">{configBlock}</pre>

            <details className="detailsPanel">
              <summary>Why this is required</summary>
              <div className="infoCard">
                <p>
                  The mesh gate expects an on-chain node-device record tied to the same
                  pubkey the node presents. After that, the node can boot as a regular
                  node. Validator status is a separate role.
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
