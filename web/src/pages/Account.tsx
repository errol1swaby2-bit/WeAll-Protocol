import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import FeedView from "../components/FeedView";
import WalletPanel from "../components/WalletPanel";
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
import { REVIEW_CENTER_LABEL, REVIEW_LANES, type ReviewLaneId } from "../lib/reviewLanes";

const REVIEWER_LANE_IDS: ReviewLaneId[] = ["content_review", "dispute_review", "poh_async_review", "poh_live_review"];

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
      note: "Participation is possible; reputation can still affect future trusted responsibilities and ranking.",
    };
  }
  return {
    label: "Strong standing",
    note: "Reputation is in the higher-trust service range.",
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
  const [operatorStatus, setOperatorStatus] = useState<any>(null);
  const [reviewerStatus, setReviewerStatus] = useState<any>(null);
  const [reputationMatrix, setReputationMatrix] = useState<any>(null);
  const [registered, setRegistered] = useState<any>(null);
  const [following, setFollowing] = useState<any>(null);
  const [socialMe, setSocialMe] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  const [opErr, setOpErr] = useState<{ msg: string; details: any } | null>(null);
  const [opResult, setOpResult] = useState<any>(null);
  const [busy, setBusy] = useState<"register" | "enroll" | "validator" | "storage" | "helper" | "reviewerLane" | "reviewerLaneExit" | "jurorPause" | "validatorPause" | "nodePause" | null>(null);
  const [nodeDeviceId, setNodeDeviceId] = useState<string>("");
  const [nodeLabel, setNodeLabel] = useState<string>("Primary node");
  const [nodeKeyFile, setNodeKeyFile] = useState<NodeKeyFile | null>(null);
  const [storageCapacityGb, setStorageCapacityGb] = useState<string>("100");
  const [storageEndpointCommitment, setStorageEndpointCommitment] = useState<string>("");
  const [validatorReadinessCommitment, setValidatorReadinessCommitment] = useState<string>("");

  async function load(): Promise<void> {
    setErr(null);
    const headers = isSelf ? getAuthHeaders(acct) : undefined;

    const calls: Record<string, Promise<any>> = {
      poh: weall.pohState(acct, base),
      nonce: weall.accountNonce(acct, base),
      account: weall.account(acct, base),
      operatorStatus: weall.accountOperatorStatus(acct, base, headers),
      reviewerStatus: weall.accountReviewerStatus(acct, base, headers),
      reputationMatrix: weall.reputationSummary(acct, base, headers),
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
    setOperatorStatus(out.operatorStatus ?? null);
    setReviewerStatus(out.reviewerStatus ?? null);
    setReputationMatrix(out.reputationMatrix ?? null);
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
  const matrixDimensions = asRecord(reputationMatrix?.dimensions);
  const matrixPublicDimensionRows = Object.values(matrixDimensions).filter(
    (row: any) => row && typeof row === "object" && row.visibility !== "private",
  );
  const matrixAggregateScore = num(reputationMatrix?.aggregate_public_score_milli, 0);
  const accountExists = !!acctView?.ok && !!state;
  const registeredState = registered?.registered ?? accountExists;
  const canLikeComment = tier >= 1 && accountExists && !banned && !locked;
  const canPost = tier >= 2 && accountExists && !banned && !locked;
  const canServe = tier >= 2 && accountExists && !banned && !locked;

  const reviewerTruth = asRecord(reviewerStatus?.reviewer);
  const reviewerLaneTruth = asRecord(reviewerTruth.lanes);
  const reviewerEnrolled = reviewerTruth.enrolled === true;
  const reviewerActive = reviewerTruth.active === true;
  const reviewerLaneLabels = REVIEW_LANES.filter((lane) => REVIEWER_LANE_IDS.includes(lane.id)).map((lane) => ({ lane: lane.id, label: lane.label, duty: lane.purpose }));
  const reviewerLaneActive = (lane: string): boolean => {
    const rec = asRecord(reviewerLaneTruth[lane]);
    return rec.active === true;
  };
  const reviewerEligibilityBlockers = Array.isArray(reviewerTruth.eligibility_blockers) ? reviewerTruth.eligibility_blockers.map((x: any) => String(x)) : [];
  const contentReviewActive = reviewerLaneActive("content_review");
  const anyReviewerLaneActive = reviewerLaneLabels.some((row) => reviewerLaneActive(row.lane));

  const rolesState = asRecord(state?.roles);
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
  const nodeOperatorBucket = asRecord(rolesState.node_operators);
  const nodeOperatorById = asRecord(nodeOperatorBucket.by_id);
  const nodeOperatorRecord = asRecord(nodeOperatorById[acct]);
  const operatorTruth = asRecord(operatorStatus?.node_operator);
  const baselineTruth = asRecord(operatorTruth.baseline);
  const validatorTruth = asRecord(operatorTruth.validator);
  const storageTruth = asRecord(operatorTruth.storage);
  const helperTruth = asRecord(operatorTruth.helper);
  const validatorDetails = asRecord(validatorTruth.details);
  const storageDetails = asRecord(storageTruth.details);
  const helperDetails = asRecord(helperTruth.details);
  const nodeOperatorEnrolled = !!nodeOperatorRecord.enrolled || String(baselineTruth.status || "") !== "not_opted_in";
  const nodeOperatorActive =
    baselineTruth.active === true ||
    !!nodeOperatorRecord.active ||
    (Array.isArray(nodeOperatorBucket.active_set) &&
      nodeOperatorBucket.active_set.map((v: any) => String(v)).includes(acct));
  const nodeOperatorResponsibilities = asRecord(nodeOperatorRecord.responsibilities);
  const validatorResponsibility = asRecord(nodeOperatorResponsibilities.validator);
  const validatorStatus = String(validatorTruth.status || "");
  const validatorOptedIn = !!validatorResponsibility.opted_in || (!!validatorStatus && validatorStatus !== "not_opted_in");
  const validatorActive = validatorTruth.active === true || !!validatorResponsibility.active;
  const validatorReadinessStatus = String(validatorStatus || validatorResponsibility.readiness_status || (validatorOptedIn ? "pending" : "not requested"));
  const validatorReputationRequired = num(validatorDetails.reputation_required_milli ?? validatorResponsibility.reputation_required_milli, 5000);
  const storageResponsibility = asRecord(nodeOperatorResponsibilities.storage);
  const storageStatus = String(storageTruth.status || "");
  const storageOptedIn = !!storageResponsibility.opted_in || (!!storageStatus && storageStatus !== "not_opted_in");
  const storageDeclaredCapacityBytes = num(storageDetails.declared_capacity_bytes ?? storageResponsibility.declared_capacity_bytes, 0);
  const storageProvenCapacityBytes = num(storageDetails.proven_capacity_bytes ?? storageResponsibility.proven_capacity_bytes, 0);
  const storageProofStatus = String(storageDetails.proof_status || storageStatus || storageResponsibility.proof_status || (storageOptedIn ? "pending" : "not requested"));
  const storageEligibleForAllocation = storageTruth.active === true || (storageOptedIn && storageProvenCapacityBytes > 0);
  const baselineReasons = Array.isArray(baselineTruth.reasons) ? baselineTruth.reasons : [];
  const validatorReasons = Array.isArray(validatorTruth.reasons) ? validatorTruth.reasons : [];
  const storageReasons = Array.isArray(storageTruth.reasons) ? storageTruth.reasons : [];
  const helperStatus = String(helperTruth.status || "not_opted_in");
  const helperReasons = Array.isArray(helperTruth.reasons) ? helperTruth.reasons : [];
  const helperOptedIn = helperDetails.opted_in === true || (!!helperStatus && helperStatus !== "not_opted_in");
  const helperActive = helperTruth.active === true;
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

  async function runReviewerTx(lane: string, active = true) {
    if (!isSelf) return;

    setBusy(active ? "reviewerLane" : "reviewerLaneExit");
    setOpErr(null);
    setOpResult(null);

    try {
      if (!accountExists) throw new Error("register_the_account_first");
      if (signerBusy) throw new Error("signer_submission_busy");
      if (tier < 2) throw new Error("trusted_verified_person_required_for_reviewer_responsibility");
      if (!localPubkey) throw new Error("missing_account_signer");

      const r = await tx.runTx({
        title: active ? "Opt into reviewer lane responsibility" : "Opt out of reviewer lane responsibility",
        pendingMessage: active ? "Submitting reviewer lane opt-in…" : "Submitting reviewer lane opt-out…",
        successMessage: active
          ? "Reviewer lane availability is active only for the selected responsibility lane."
          : "Reviewer lane opt-out recorded. Active assignments may still need to be resolved by protocol policy.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () => submitSignedTx({
          account: acct,
          tx_type: active ? "REVIEWER_LANE_OPT_IN" : "REVIEWER_LANE_OPT_OUT",
          payload: {
            account_id: acct,
            lane,
          },
          base,
        }),
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

  async function runResponsibilityPause(kind: "juror" | "validator" | "node") {
    if (!isSelf) return;

    const busyKind = kind === "juror" ? "jurorPause" : kind === "validator" ? "validatorPause" : "nodePause";
    setBusy(busyKind);
    setOpErr(null);
    setOpResult(null);

    try {
      if (!accountExists) throw new Error("register_the_account_first");
      if (signerBusy) throw new Error("signer_submission_busy");
      if (!localPubkey) throw new Error("missing_account_signer");
      const txType = kind === "juror" ? "ROLE_JUROR_SUSPEND" : kind === "validator" ? "ROLE_VALIDATOR_SUSPEND" : "ROLE_NODE_OPERATOR_SUSPEND";
      const title = kind === "juror" ? "Pause all reviewer responsibilities" : kind === "validator" ? "Pause validator authority" : "Pause node operator service";
      const r = await tx.runTx({
        title,
        pendingMessage: "Submitting responsibility pause…",
        successMessage: "Pause request recorded. The backend state remains the source of truth for when active work is fully withdrawn.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () => submitSignedTx({
          account: acct,
          tx_type: txType,
          payload: { account_id: acct },
          base,
        }),
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

  async function runOperatorTx(kind: "register" | "enroll" | "validator" | "storage" | "helper") {
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
      if ((kind === "validator" || kind === "storage" || kind === "helper") && !nodeOperatorActive) throw new Error("baseline_node_operator_required");

      const r = await tx.runTx({
        title:
          kind === "register"
            ? "Register node device"
            : kind === "validator"
              ? "Opt into validator responsibility"
              : kind === "storage"
                ? "Opt into storage responsibility"
                : kind === "helper"
                  ? "Opt into helper execution responsibility"
                  : "Submit node operator enrollment",
        pendingMessage: "Submitting operator action…",
        successMessage:
          kind === "register"
            ? "Node device registered."
            : kind === "validator"
              ? "Validator responsibility opt-in recorded. Validator readiness and reputation checks are still pending before consensus authority."
              : kind === "storage"
                ? "Storage responsibility opt-in recorded. Protocol capacity probe is still pending before allocation."
                : "Node operator enrollment submitted\nWaiting for eligibility\nNode Operator status active\nValidator and storage responsibilities are optional opt-in responsibilities — Checking eligibility — the protocol automatically activates baseline Node Operator status once prerequisites are met.",
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
          if (kind === "validator") {
            return submitSignedTx({
              account: acct,
              tx_type: "NODE_OPERATOR_VALIDATOR_OPT_IN",
              payload: {
                account_id: acct,
                validator_opt_in: true,
                node_pubkey: nodePubkey,
                validator_readiness_commitment: String(validatorReadinessCommitment || "").trim() || undefined,
              },
              base,
            });
          }
          if (kind === "helper") {
            return submitSignedTx({
              account: acct,
              tx_type: "NODE_OPERATOR_HELPER_OPT_IN",
              payload: {
                account_id: acct,
                helper_opt_in: true,
                node_pubkey: nodePubkey,
                helper_capacity_units: 4,
              },
              base,
            });
          }
          if (kind === "storage") {
            const gb = Number(storageCapacityGb || "0");
            const declaredCapacityBytes = Number.isFinite(gb) && gb > 0 ? Math.floor(gb * 1024 * 1024 * 1024) : 0;
            if (declaredCapacityBytes <= 0) throw new Error("declared_storage_capacity_required");
            return submitSignedTx({
              account: acct,
              tx_type: "NODE_OPERATOR_STORAGE_OPT_IN",
              payload: {
                account_id: acct,
                storage_opt_in: true,
                declared_capacity_bytes: declaredCapacityBytes,
                node_pubkey: nodePubkey,
                storage_endpoint_commitment: String(storageEndpointCommitment || "").trim() || undefined,
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
                ? "Enrollment is submitted. The protocol is checking eligibility for baseline Node Operator status."
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
              <div className="eyebrow">Trusted responsibilities</div>
              <h2 className="cardTitle">Opt into reviewer and service duties</h2>
            </div>
            <span className={`statusPill ${canServe ? "ok" : ""}`}>
              {canServe ? "Eligible" : "Locked until Trusted Verified Person"}
            </span>
          </div>
          <p className="heroText">
            Tier 2 unlocks eligibility, but responsibility is explicit. Opt in before the protocol can assign
            you unconflicted review work or storage validation duties. Accepted assignments may affect reputation
            if they are missed or abandoned late.
          </p>

          <div className="grid2">
            <article className="feedMediaCard">
              <div className="feedMediaTitle">Community reviewer</div>
              <div className="feedMediaMeta">
                Choose exact review lanes rather than a generic reviewer bucket. Content disputes, dispute juror work,
                PoH async review, and PoH live review stay separated so assignments are never implied by Tier-2 status alone.
              </div>
              <div className="progressList">
                <div className="progressRow">
                  <span>Base reviewer enrollment</span>
                  <span className={`statusPill ${reviewerEnrolled ? "ok" : ""}`}>{reviewerEnrolled ? "Submitted" : "Not enrolled"}</span>
                </div>
                <div className="progressRow">
                  <span>Exact lane availability</span>
                  <span className={`statusPill ${anyReviewerLaneActive ? "ok" : ""}`}>{anyReviewerLaneActive ? "At least one lane active" : "No lane active"}</span>
                </div>
                <div className="progressRow">
                  <span>Reviewer truth source</span>
                  <span className="miniMuted">/v1/accounts/{account}/reviewer-status</span>
                </div>
                <div className="progressRow">
                  <span>Conflict rule</span>
                  <span className="statusPill ok">Original poster excluded</span>
                </div>
              </div>
              {reviewerEligibilityBlockers.length ? (
                <div className="inlineNote">Reviewer responsibility is not assignment-ready yet: {reviewerEligibilityBlockers.join(", ")}</div>
              ) : null}
              <div className="milestoneList">
                {reviewerLaneLabels.map((row) => {
                  const active = reviewerLaneActive(row.lane);
                  return (
                    <div key={row.lane} className="feedMediaCard">
                      <div className="feedMediaTitle">{row.label}</div>
                      <div className="feedMediaMeta">{row.duty}</div>
                      <div className="buttonRow">
                        <span className={`statusPill ${active ? "ok" : ""}`}>{active ? "Active" : "Not opted in"}</span>
                        {!active ? (
                          <button className="btn btnPrimary" disabled={busy !== null || !canServe || !localPubkey} onClick={() => void runReviewerTx(row.lane, true)}>
                            {busy === "reviewerLane" ? "Opting in…" : `Opt into ${row.label}`}
                          </button>
                        ) : (
                          <button className="btn" disabled={busy !== null || !localPubkey} onClick={() => void runReviewerTx(row.lane, false)}>
                            {busy === "reviewerLaneExit" ? "Opting out…" : `Opt out of ${row.label}`}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="calloutInfo">
                <strong>Responsibility exit controls</strong>
                <div style={{ marginTop: 6 }}>
                  Individual reviewer lanes can be opted out above. Use the whole-role pause only when you intend to pause all reviewer duties; active or already-accepted work may still have protocol-specific withdrawal consequences.
                </div>
              </div>
              <div className="buttonRow">
                <button className="btn" onClick={() => nav("/reviews")}>Open {REVIEW_CENTER_LABEL}</button>
                <button className="btn" disabled={busy !== null || !reviewerEnrolled || !localPubkey} onClick={() => void runResponsibilityPause("juror")}>
                  {busy === "jurorPause" ? "Pausing reviewer role…" : "Pause all reviewer duties"}
                </button>
              </div>
            </article>

            <article className="feedMediaCard">
              <div className="feedMediaTitle">Storage validation and provider duty</div>
              <div className="feedMediaMeta">
                Storage is also opt-in. Register a node device, enroll as a node operator, then declare capacity.
                The protocol must still verify capacity before assigning storage obligations.
              </div>
              <div className="progressList">
                <div className="progressRow">
                  <span>Node operator</span>
                  <span className={`statusPill ${nodeOperatorActive ? "ok" : ""}`}>{nodeOperatorActive ? "Active" : nodeOperatorEnrolled ? "Pending" : "Not enrolled"}</span>
                </div>
                <div className="progressRow">
                  <span>Storage opt-in</span>
                  <span className={`statusPill ${storageOptedIn ? "ok" : ""}`}>{storageOptedIn ? "Declared" : "Not opted in"}</span>
                </div>
                <div className="progressRow">
                  <span>Capacity proof</span>
                  <span className={`statusPill ${storageProvenCapacityBytes > 0 ? "ok" : ""}`}>{storageProvenCapacityBytes > 0 ? "Proven" : storageProofStatus}</span>
                </div>
              </div>
              <div className="buttonRow">
                <button className="btn" disabled={busy !== null || !nodeOperatorActive || !nodePubkey || storageOptedIn} onClick={() => void runOperatorTx("storage")}>
                  {busy === "storage" ? "Recording storage opt-in…" : storageOptedIn ? "Storage opt-in recorded" : "Opt into storage validation"}
                </button>
                <button className="btn" onClick={() => nav("/node")}>Open node controls</button>
              </div>
              {!nodeOperatorActive || !nodePubkey ? (
                <div className="feedMediaMeta">Finish node setup in the advanced network helper section below before storage validation can be submitted.</div>
              ) : null}
            </article>
          </div>
        </div>
      </section>

      <WalletPanel account={acct} base={base} />

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Reputation Matrix</div>
              <h2 className="cardTitle">Public trust dimensions</h2>
            </div>
            <span className="statusPill ok">Deterministic read model</span>
          </div>

          <div className="summaryCardGrid">
            <article className="summaryCard">
              <div className="summaryCardLabel">Public aggregate</div>
              <div className="summaryCardValue">{matrixAggregateScore}</div>
              <div className="summaryCardText">
                Derived from canonical protocol state and public matrix dimensions only.
              </div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Formula version</div>
              <div className="summaryCardValue">v{num(reputationMatrix?.version, 1)}</div>
              <div className="summaryCardText">
                Integer milli-units, no frontend-only scoring, and no local wall-clock penalties.
              </div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Private boundary</div>
              <div className="summaryCardValue">{reputationMatrix?.visibility?.private_revealed ? "Owner view" : "Public view"}</div>
              <div className="summaryCardText">
                Internal abuse-risk signals stay hidden unless the account owner is authenticated.
              </div>
            </article>
          </div>

          <div className="infoGrid">
            {matrixPublicDimensionRows.length ? (
              matrixPublicDimensionRows.map((row: any) => (
                <div key={String(row.dimension)} className="infoCard compact">
                  <div className="infoCardHeader">
                    <span className={`statusPill ${num(row.score_milli, 0) >= 0 ? "ok" : ""}`}>
                      {String(row.level || "neutral")}
                    </span>
                    <strong>{String(row.dimension || "dimension").replace(/_/g, " ")}</strong>
                  </div>
                  <div className="infoCardText">
                    {num(row.score_milli, 0)} milli • {num(row.event_count, 0)} event{num(row.event_count, 0) === 1 ? "" : "s"}
                  </div>
                </div>
              ))
            ) : (
              <div className="infoCard compact">
                <div className="infoCardHeader">
                  <span className="statusPill">Loading</span>
                  <strong>Matrix unavailable</strong>
                </div>
                <div className="infoCardText">The reputation matrix read model has not loaded yet.</div>
              </div>
            )}
          </div>
        </div>
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
              enrollment. The protocol automatically activates baseline Node Operator status when prerequisites are met. Validator and storage responsibilities are optional opt-in responsibilities.
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
                        ? "Baseline Node Operator status is active. Optional validator and storage responsibilities are still separately gated."
                        : "Your enrollment is submitted. The protocol is checking eligibility and will automatically activate baseline status once prerequisites are met."}
                    </div>
                    {baselineReasons.length ? (
                      <div className="feedMediaMeta">Backend readiness reasons: {baselineReasons.join(", ")}</div>
                    ) : null}
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
              <div className="feedMediaTitle">Helper Execution Responsibility</div>
              <div className="feedMediaMeta">
                Helper execution is optional and separate from baseline Node Operator status. Opting in does not override the production helper release gate; it only records your exact consent for helper work if the lane is active.
              </div>
              <div className="progressList">
                <div className="progressRow">
                  <span>Helper opt-in</span>
                  <span className={`statusPill ${helperOptedIn ? "ok" : ""}`}>{helperOptedIn ? "Opted in" : "Not opted in"}</span>
                </div>
                <div className="progressRow">
                  <span>Helper active state</span>
                  <span className={`statusPill ${helperActive ? "ok" : ""}`}>{helperActive ? "Active" : helperStatus}</span>
                </div>
              </div>
              {helperReasons.length ? (
                <div className="feedMediaMeta">Backend helper blockers: {helperReasons.join(", ")}</div>
              ) : null}
              <div className="buttonRow">
                <button
                  className="btn"
                  disabled={busy !== null || !nodeOperatorActive || !nodePubkey || helperOptedIn}
                  onClick={() => void runOperatorTx("helper")}
                >
                  {busy === "helper"
                    ? "Recording helper opt-in…"
                    : helperOptedIn
                      ? "Helper opt-in recorded"
                      : "Opt into helper execution"}
                </button>
                <button className="btn" disabled>
                  Helper-specific opt-out not yet available in UI
                </button>
              </div>
              <div className="feedMediaMeta">Helper-specific withdrawal does not have a dedicated UI transaction yet. Pause the baseline node operator role only if you intend to pause all node service responsibilities.</div>
            </div>

            <div className="feedMediaCard">
              <div className="feedMediaTitle">Validator Responsibility</div>
              <div className="feedMediaMeta">
                Help finalize blocks and secure the network. Validator responsibility is optional. Baseline Node Operator status does not grant validator authority; validator readiness and reputation checks must pass first.
              </div>
              <div className="progressList">
                <div className="progressRow">
                  <span>Validator opt-in</span>
                  <span className={`statusPill ${validatorOptedIn ? "ok" : ""}`}>{validatorOptedIn ? "Opted in" : "Not opted in"}</span>
                </div>
                <div className="progressRow">
                  <span>Validator readiness</span>
                  <span className={`statusPill ${validatorActive ? "ok" : ""}`}>{validatorActive ? "Active" : validatorReadinessStatus}</span>
                </div>
                <div className="progressRow">
                  <span>Reputation gate</span>
                  <span className="statusPill">Requires {validatorReputationRequired} reputation milli</span>
                </div>
                <div className="progressRow">
                  <span>Consensus authority</span>
                  <span className={`statusPill ${validatorActive ? "ok" : ""}`}>{validatorActive ? "Enabled" : "Blocked until readiness"}</span>
                </div>
              </div>
              {validatorReasons.length ? (
                <div className="feedMediaMeta">Backend readiness reasons: {validatorReasons.join(", ")}</div>
              ) : null}
              <label>
                <div className="eyebrow">Validator readiness commitment</div>
                <input
                  value={validatorReadinessCommitment}
                  onChange={(e) => setValidatorReadinessCommitment(e.target.value)}
                  placeholder="optional readiness commitment"
                />
              </label>
              <div className="buttonRow">
                <button
                  className="btn"
                  disabled={busy !== null || !nodeOperatorActive || !nodePubkey || validatorOptedIn}
                  onClick={() => void runOperatorTx("validator")}
                >
                  {busy === "validator"
                    ? "Recording validator opt-in…"
                    : validatorOptedIn
                      ? "Validator opt-in recorded"
                      : "Opt into validator responsibility"}
                </button>
                <button className="btn" disabled={busy !== null || !validatorOptedIn || !localPubkey} onClick={() => void runResponsibilityPause("validator")}>
                  {busy === "validatorPause" ? "Pausing validator…" : "Pause validator authority"}
                </button>
              </div>
            </div>

            <div className="feedMediaCard">
              <div className="feedMediaTitle">Storage Responsibility</div>
              <div className="feedMediaMeta">
                Help store and serve WeAll data. Storage responsibility is optional. Declared capacity is not allocation authority; a protocol capacity probe must confirm the declared space size and availability before the protocol allocates data to this node.
              </div>
              <div className="progressList">
                <div className="progressRow">
                  <span>Storage opt-in</span>
                  <span className={`statusPill ${storageOptedIn ? "ok" : ""}`}>{storageOptedIn ? "Declared" : "Not opted in"}</span>
                </div>
                <div className="progressRow">
                  <span>Declared capacity</span>
                  <span className={`statusPill ${storageDeclaredCapacityBytes > 0 ? "ok" : ""}`}>{storageDeclaredCapacityBytes > 0 ? `${storageDeclaredCapacityBytes} bytes` : "None"}</span>
                </div>
                <div className="progressRow">
                  <span>Protocol capacity probe</span>
                  <span className={`statusPill ${storageProvenCapacityBytes > 0 ? "ok" : ""}`}>{storageProvenCapacityBytes > 0 ? "Proven" : storageProofStatus}</span>
                </div>
                <div className="progressRow">
                  <span>Eligible for allocation</span>
                  <span className={`statusPill ${storageEligibleForAllocation ? "ok" : ""}`}>{storageEligibleForAllocation ? "Eligible" : "Blocked until proof / capacity probe verification"}</span>
                </div>
              </div>
              {storageReasons.length ? (
                <div className="feedMediaMeta">Backend readiness reasons: {storageReasons.join(", ")}</div>
              ) : null}
              <div className="grid2">
                <label>
                  <div className="eyebrow">Declared capacity in GB</div>
                  <input
                    value={storageCapacityGb}
                    onChange={(e) => setStorageCapacityGb(e.target.value)}
                    placeholder="100"
                  />
                </label>
                <label>
                  <div className="eyebrow">Storage endpoint commitment</div>
                  <input
                    value={storageEndpointCommitment}
                    onChange={(e) => setStorageEndpointCommitment(e.target.value)}
                    placeholder="optional endpoint commitment"
                  />
                </label>
              </div>
              <div className="buttonRow">
                <button
                  className="btn"
                  disabled={busy !== null || !nodeOperatorActive || !nodePubkey || storageOptedIn}
                  onClick={() => void runOperatorTx("storage")}
                >
                  {busy === "storage"
                    ? "Recording storage opt-in…"
                    : storageOptedIn
                      ? "Storage capacity declared"
                      : "Opt into storage responsibility"}
                </button>
                <button className="btn" disabled>
                  Storage-specific opt-out not yet available in UI
                </button>
                <button className="btn" disabled={busy !== null || !nodeOperatorActive || !localPubkey} onClick={() => void runResponsibilityPause("node")}>
                  {busy === "nodePause" ? "Pausing node operator…" : "Pause node operator service"}
                </button>
              </div>
              <div className="feedMediaMeta">Storage-specific withdrawal is not exposed as a separate UI action yet. Pausing node operator service is broader and may affect validator, helper, and storage duties together.</div>
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
                  node operator enrollment. Enrollment is user-submitted;
                  baseline activation is protocol-scheduled once eligibility checks pass. Validator and storage responsibilities
                  are optional opt-in responsibilities under Node Operator status. Validator readiness and reputation checks must pass before consensus authority.
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
