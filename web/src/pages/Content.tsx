import React, { useEffect, useMemo, useState } from "react";
import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import GateBanner from "../components/GateBanner";
import { nav } from "../lib/router";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

// Gating logic is centralized in src/lib/gates.ts

export default function Content({ id }: { id: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [item, setItem] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  // Session + gates
  const [acct, setAcct] = useState<string | null>(null);
  const [canSign, setCanSign] = useState(false);
  const [acctState, setAcctState] = useState<any | null>(null);

  // Reply composer
  const [reply, setReply] = useState("");
  const [replying, setReplying] = useState(false);
  const [replyErr, setReplyErr] = useState<{ msg: string; details: any } | null>(null);

  const [reacting, setReacting] = useState(false);
  const [reactErr, setReactErr] = useState<{ msg: string; details: any } | null>(null);

  function refreshSession() {
    const s = getSession();
    const a = s ? normalizeAccount(s.account) : null;
    setAcct(a);
    const kp = a ? getKeypair(a) : null;
    setCanSign(!!kp?.secretKeyB64);
  }

  async function refreshAccountState() {
    if (!acct) {
      setAcctState(null);
      return;
    }
    try {
      const r = await weall.account(acct, base);
      setAcctState((r as any)?.state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  async function load() {
    setErr(null);
    try {
      const r = await weall.content(id, base);
      setItem((r as any)?.content ?? (r as any)?.item ?? r);
    } catch (e: any) {
      setErr(prettyErr(e));
      setItem(null);
    }
  }

  useEffect(() => {
    refreshSession();
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  useEffect(() => {
    refreshSession();
    refreshAccountState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [acct]);

  // Tier 2+ to react (matches PoH tiers)
  const reactGate = checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 2 });
  const replyGate = checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 2, minRep: 1 });

  async function react(reaction: string) {
    setReactErr(null);
    if (!acct) return setReactErr({ msg: "not_logged_in", details: null });
    if (!reactGate.ok) return setReactErr({ msg: reactGate.reason || "gated", details: acctState });

    setReacting(true);
    try {
      await submitSignedTx({
        account: acct,
        tx_type: "CONTENT_REACTION_SET",
        payload: { target_id: id, reaction },
        parent: null,
        base,
      });
      await refreshAccountState();
    } catch (e: any) {
      setReactErr(prettyErr(e));
    } finally {
      setReacting(false);
    }
  }

  async function submitReply() {
    setReplyErr(null);
    if (!acct) return setReplyErr({ msg: "not_logged_in", details: null });
    if (!replyGate.ok) return setReplyErr({ msg: replyGate.reason || "gated", details: acctState });

    const b = (reply || "").trim();
    if (!b) return setReplyErr({ msg: "reply body required", details: null });

    setReplying(true);
    try {
      await submitSignedTx({
        account: acct,
        tx_type: "CONTENT_COMMENT_CREATE",
        payload: { post_id: id, body: b },
        parent: null,
        base,
      });
      setReply("");
      await refreshAccountState();
      // Thread view shows replies; send user there.
      nav(`/thread/${encodeURIComponent(id)}`);
    } catch (e: any) {
      setReplyErr(prettyErr(e));
    } finally {
      setReplying(false);
    }
  }

  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button onClick={() => nav("/feed")}>← Feed</button>
        <h2 style={{ margin: 0 }}>Content</h2>
        <button onClick={load}>Refresh</button>
        <button onClick={() => nav(`/thread/${encodeURIComponent(id)}`)}>Open thread</button>
      </div>

      <div style={{ marginTop: 10 }}>
        <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />
      </div>

      {/* Quick actions */}
      <div style={{ marginTop: 12, background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
          <div style={{ fontWeight: 800 }}>Actions</div>
          <div style={{ opacity: 0.75, fontSize: 13 }}>
            {acct ? (
              <>
                as <b>{acct}</b>
                {acctState ? <> — <b>{summarizeAccountState(acctState)}</b></> : null}
              </>
            ) : (
              <>Not logged in</>
            )}
          </div>
          <div style={{ flex: 1 }} />
          {acct ? (
            <button onClick={() => nav(`/account/${encodeURIComponent(acct)}`)} style={{ fontSize: 13 }}>
              View account
            </button>
          ) : (
            <button onClick={() => nav("/poh")} style={{ fontSize: 13 }}>
              Go to PoH
            </button>
          )}
        </div>

        <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={() => react("like")} disabled={!reactGate.ok || reacting} title={reactGate.reason}>
            👍 Like
          </button>
          <button onClick={() => react("love")} disabled={!reactGate.ok || reacting} title={reactGate.reason}>
            ❤️ Love
          </button>
          <GateBanner gate={reactGate} prefix="Reactions disabled" />
        </div>

        <div style={{ marginTop: 10 }}>
          <ErrorBanner message={reactErr?.msg} details={reactErr?.details} onDismiss={() => setReactErr(null)} />
        </div>

        <hr style={{ border: "none", borderTop: "1px solid #eee", margin: "14px 0" }} />

        <div style={{ fontWeight: 800 }}>Reply</div>
        <GateBanner gate={replyGate} prefix="Replying disabled" />

        <textarea
          value={reply}
          onChange={(e) => setReply(e.target.value)}
          placeholder="Write a reply…"
          style={{ width: "100%", marginTop: 10, padding: 10, borderRadius: 10, border: "1px solid #ccc", minHeight: 80 }}
        />
        <div style={{ marginTop: 10, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <button
            onClick={submitReply}
            disabled={!replyGate.ok || replying}
            style={{
              padding: "10px 12px",
              borderRadius: 10,
              border: "1px solid #111",
              background: replyGate.ok ? "#111" : "#eee",
              color: replyGate.ok ? "white" : "#777",
              cursor: replyGate.ok ? "pointer" : "not-allowed",
            }}
          >
            {replying ? "Posting…" : "Post reply"}
          </button>
          <button onClick={refreshAccountState} style={{ padding: "10px 12px", borderRadius: 10, border: "1px solid #aaa" }}>
            Refresh gates
          </button>
        </div>

        <div style={{ marginTop: 10 }}>
          <ErrorBanner message={replyErr?.msg} details={replyErr?.details} onDismiss={() => setReplyErr(null)} />
        </div>
      </div>

      <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14, marginTop: 12 }}>
        <div style={{ opacity: 0.7, fontFamily: "monospace", fontSize: 12 }}>{id}</div>
        <h3 style={{ marginTop: 6 }}>{String(item?.title || item?.caption || "(untitled)")}</h3>
        <div style={{ whiteSpace: "pre-wrap" }}>{String(item?.body || item?.text || "")}</div>

        <div style={{ marginTop: 10 }}>
          <div style={{ fontWeight: 700, marginBottom: 6 }}>Raw</div>
          <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(item, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
}
