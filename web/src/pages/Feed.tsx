// projects/web/src/pages/Feed.tsx
import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import FeedView from "../components/FeedView";
import GateBanner from "../components/GateBanner";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";
import { FeedScope, FeedSort } from "../lib/feed";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

export default function Feed(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);

  // Session
  const [viewer, setViewer] = useState<string | null>(null);
  const [canSign, setCanSign] = useState(false);
  const [acctState, setAcctState] = useState<any | null>(null);

  function refreshSession() {
    const s = getSession();
    const a = s ? normalizeAccount(s.account) : null;
    setViewer(a);
    const kp = a ? getKeypair(a) : null;
    setCanSign(!!kp?.secretKeyB64);
  }

  async function refreshAccountState() {
    if (!viewer) return setAcctState(null);
    try {
      const r: any = await weall.account(viewer, base);
      setAcctState(r?.state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  useEffect(() => {
    refreshSession();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    refreshSession();
    refreshAccountState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewer]);

  // Scope / sort
  const [scopeKind, setScopeKind] = useState<"public" | "following" | "mine" | "private">("public");
  const [sort, setSort] = useState<FeedSort>("new");

  const scope: FeedScope = useMemo(() => {
    if (scopeKind === "public") return { kind: "public" };
    if (scopeKind === "following") return { kind: "following" };
    if (scopeKind === "mine") return { kind: "mine" };
    return { kind: "private" };
  }, [scopeKind]);

  const requireLogin = scopeKind !== "public";

  // Composer
  const [body, setBody] = useState("");
  const [visibility, setVisibility] = useState<"public" | "private">("public");
  const [files, setFiles] = useState<File[]>([]);
  const [posting, setPosting] = useState(false);
  const [postErr, setPostErr] = useState<{ msg: string; details: any } | null>(null);

  const postGate = checkGates({ loggedIn: !!viewer, canSign, accountState: acctState, requireTier: 3, minRep: 1 });

  async function submitPost() {
    setPostErr(null);
    if (!viewer) return setPostErr({ msg: "not_logged_in", details: null });
    if (!postGate.ok) return setPostErr({ msg: postGate.reason || "gated", details: acctState });

    const b = (body || "").trim();
    if (!b && files.length === 0) return setPostErr({ msg: "body_or_media_required", details: null });

    setPosting(true);
    try {
      const headers = getAuthHeaders();

      // 1) Upload each file to IPFS (via the node) and declare media on-chain.
      const mediaIds: string[] = [];

      for (const f of files) {
        const up: any = await weall.mediaUpload(f, base, headers);
        const cid = String(up?.cid || "").trim();
        if (!cid) throw new Error("upload_failed_missing_cid");

        // Declare media (stores cid + metadata on-chain)
        await submitSignedTx({
          account: viewer,
          tx_type: "CONTENT_MEDIA_DECLARE",
          payload: {
            cid,
            kind: String(f.type || "").startsWith("image/") ? "image" : "file",
            mime: f.type || "application/octet-stream",
            name: f.name,
            size: f.size,
          },
          parent: null,
          base,
        });

        // Deterministic media_id rule in protocol: media:<signer>:<nonce>
        // We don't have nonce returned from submitSignedTx, so we fetch the latest nonce from chain view.
        // This is safe in single-device flow; for concurrent txs, users should avoid multi-tab posting.
        const nonceR: any = await weall.accountNonce(viewer, base);
        const n = Number(nonceR?.nonce ?? 0);
        // After declaring, account nonce is advanced to that nonce, so the media_id is (n)
        const mediaId = `media:${viewer}:${n}`;
        mediaIds.push(mediaId);
      }

      // 2) Create post with media_ids
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_POST_CREATE",
        payload: {
          body: b,
          visibility,
          media: mediaIds,
        },
        parent: null,
        base,
      });

      setBody("");
      setFiles([]);
      await refreshAccountState();
    } catch (e: any) {
      setPostErr(prettyErr(e));
    } finally {
      setPosting(false);
    }
  }

  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button onClick={() => nav("/home")}>← Home</button>
        <h2 style={{ margin: 0 }}>Feed</h2>

        <div style={{ display: "flex", gap: 8, alignItems: "center", marginLeft: 10, flexWrap: "wrap" }}>
          <label style={{ fontSize: 13, opacity: 0.75 }}>Scope</label>
          <select value={scopeKind} onChange={(e) => setScopeKind(e.target.value as any)}>
            <option value="public">Public</option>
            <option value="following">Following</option>
            <option value="mine">My posts</option>
            <option value="private">Private</option>
          </select>

          <label style={{ fontSize: 13, opacity: 0.75, marginLeft: 8 }}>Sort</label>
          <select value={sort} onChange={(e) => setSort(e.target.value as any)}>
            <option value="new">New</option>
            <option value="top">Top</option>
            <option value="hot">Hot</option>
          </select>
        </div>
      </div>

      {requireLogin && !viewer ? (
        <div style={{ marginTop: 10, background: "#fff3cd", border: "1px solid #ffe69c", borderRadius: 12, padding: 12 }}>
          <div style={{ fontWeight: 700 }}>Login required</div>
          <div style={{ opacity: 0.8, marginTop: 6 }}>
            This feed scope is gated behind your on-chain session key. Go to PoH and click “Login on this device”.
          </div>
          <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button onClick={() => nav("/poh")}>Open PoH</button>
            <button onClick={() => setScopeKind("public")}>Switch to Public</button>
          </div>
        </div>
      ) : null}

      {/* Composer */}
      <div style={{ marginTop: 12, background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
          <div style={{ fontWeight: 800 }}>New post</div>
          <div style={{ opacity: 0.75, fontSize: 13 }}>
            {viewer ? (
              <>
                as <b>{viewer}</b>
                {acctState ? <> — <b>{summarizeAccountState(acctState)}</b></> : null}
              </>
            ) : (
              <>Not logged in</>
            )}
          </div>
          <div style={{ flex: 1 }} />
          <button onClick={refreshAccountState} style={{ fontSize: 13 }}>
            Refresh gates
          </button>
        </div>

        <GateBanner gate={postGate} prefix="Posting disabled" />

        <div style={{ marginTop: 10, display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <label style={{ fontSize: 13, opacity: 0.75 }}>Visibility</label>
          <select value={visibility} onChange={(e) => setVisibility(e.target.value as any)} disabled={!postGate.ok || posting}>
            <option value="public">Public</option>
            <option value="private">Private</option>
          </select>
        </div>

        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="Write something…"
          style={{ width: "100%", marginTop: 10, padding: 10, borderRadius: 10, border: "1px solid #ccc", minHeight: 90 }}
        />

        <div style={{ marginTop: 10, display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <input
            type="file"
            multiple
            disabled={!postGate.ok || posting}
            onChange={(e) => {
              const list = Array.from(e.target.files || []);
              setFiles(list);
            }}
          />
          {files.length ? <span style={{ fontSize: 13, opacity: 0.75 }}>{files.length} file(s) selected</span> : null}
        </div>

        <div style={{ marginTop: 10, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <button
            onClick={submitPost}
            disabled={!postGate.ok || posting}
            style={{
              padding: "10px 12px",
              borderRadius: 10,
              border: "1px solid #111",
              background: postGate.ok ? "#111" : "#eee",
              color: postGate.ok ? "white" : "#777",
              cursor: postGate.ok ? "pointer" : "not-allowed",
            }}
          >
            {posting ? "Posting…" : "Post"}
          </button>
          <button
            onClick={() => {
              setBody("");
              setFiles([]);
            }}
            disabled={posting}
            style={{ padding: "10px 12px", borderRadius: 10, border: "1px solid #aaa" }}
          >
            Clear
          </button>
        </div>

        <div style={{ marginTop: 10 }}>
          <ErrorBanner message={postErr?.msg} details={postErr?.details} onDismiss={() => setPostErr(null)} />
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <FeedView base={base} scope={scope} defaultSort={sort} defaultFilters={{ visibility: scopeKind === "private" ? "private" : "all" }} />
      </div>
    </div>
  );
}
