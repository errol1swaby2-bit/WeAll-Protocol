import React, { useEffect, useMemo, useState } from "react";

import { api, getApiBaseUrl } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getKeypair, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { refreshMutationSlices } from "../lib/revalidation";
import { useAccount } from "../context/AccountContext";

function prettyErr(e: any): { msg: string; details: any } {
  if (!e) return null as any;
  const status = Number(e?.status || e?.payload?.status || e?.body?.status || 0);
  const details = e?.payload?.detail || e?.payload || e?.body || e?.message || null;
  if (status === 404) return { msg: "Groups endpoint did not return a directory.", details };
  return { msg: e?.message || "Unable to load groups.", details };
}

type GroupListItem = {
  id: string;
  name: string;
  description: string;
  isPrivate: boolean;
  memberCountHint: number | null;
  raw: any;
};

function mapGroup(obj: any): GroupListItem {
  const id = String(obj?.group_id || obj?.id || "").trim();
  const charter = obj?.charter && typeof obj.charter === "object" ? obj.charter : null;
  const charterText = typeof obj?.charter === "string" ? obj.charter.trim() : "";
  const meta = obj?.meta && typeof obj.meta === "object" ? obj.meta : null;
  const roles = obj?.roles && typeof obj.roles === "object" ? obj.roles : null;
  const members = obj?.members && typeof obj.members === "object" ? obj.members : roles?.members;
  const charterLines = charterText ? charterText.split(/\n{2,}|\r\n\r\n/).map((part: string) => part.trim()).filter(Boolean) : [];
  const name = String(charter?.name || meta?.name || obj?.name || charterLines[0] || id);
  const description = String(charter?.description || meta?.description || obj?.description || charterLines.slice(1).join("\n\n") || "");
  const visibility = String(
    obj?.visibility || obj?.privacy || meta?.visibility || meta?.privacy || "public",
  ).toLowerCase();

  return {
    id,
    name: name || id,
    description: description || "",
    isPrivate: ["private", "closed", "members"].includes(visibility),
    memberCountHint: members && typeof members === "object" ? Object.keys(members).length : null,
    raw: obj,
  };
}

export default function Groups(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [groups, setGroups] = useState<GroupListItem[]>([]);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const { refresh: refreshAccountContext } = useAccount();

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const canSign = !!kp?.secretKeyB64;

  const createGate = useMemo(
    () => checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 3 }),
    [acct, canSign, acctState],
  );
  const membershipGate = useMemo(
    () => checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 2 }),
    [acct, canSign, acctState],
  );
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";

  async function loadAccountState(): Promise<void> {
    if (!acct) {
      setAcctState(null);
      return;
    }
    try {
      const r: any = await api.account(acct, base);
      setAcctState(r?.account?.state ?? r?.state ?? r?.account_state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  async function refreshGroups(): Promise<void> {
    setLoading(true);
    setErr(null);
    try {
      const r: any = await api.groups.list({ limit: 250 }, base);
      const raw = Array.isArray(r?.items) ? r.items : [];
      setGroups(raw.map(mapGroup).filter((g: GroupListItem) => !!g.id));
    } catch (e: any) {
      setErr(prettyErr(e));
      setGroups([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refreshGroups();
    void loadAccountState();
  }, []);

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Groups</div>
              <h1 className="heroTitle heroTitleSm">Browse communities without mixing creation or membership review</h1>
              <p className="heroText">
                This hub is now strictly for discovery. Creation lives on its own action route and membership decisions live on each group detail page,
                so the directory stays lightweight and predictable.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Participation posture</div>
              <div className="heroInfoList">
                <span className={`statusPill ${createGate.ok ? "ok" : ""}`}>
                  {createGate.ok ? "Create unlocked" : "Create requires Tier 3"}
                </span>
                <span className={`statusPill ${membershipGate.ok ? "ok" : ""}`}>
                  {membershipGate.ok ? "Membership unlocked" : "Membership requires Tier 2"}
                </span>
                <span className="statusPill">{accountSummary}</span>
                <span className="statusPill mono">{acct || "Read-only"}</span>
              </div>
            </div>
          </div>

          <div className="buttonRow buttonRowWide">
            <button
              className={`btn ${createGate.ok ? "btnPrimary" : ""}`.trim()}
              onClick={() => nav("/groups/create")}
              type="button"
            >
              {createGate.ok ? "Create group" : "Open create group"}
            </button>
            <button className="btn" onClick={() => void refreshMutationSlices(loadAccountState, refreshAccountContext, refreshGroups)} disabled={loading}>
              {loading ? "Refreshing…" : "Refresh directory"}
            </button>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Visible groups</span>
              <span className="statValue">{groups.length}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Create gate</span>
              <span className="statValue">{createGate.ok ? "Tier 3+ ready" : "Tier 3 required"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Membership gate</span>
              <span className="statValue">{membershipGate.ok ? "Tier 2+ ready" : "Tier 2 required"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Directory mode</span>
              <span className="statValue">Hub only</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => {
          void refreshMutationSlices(loadAccountState, refreshAccountContext, refreshGroups);
        }}
        onDismiss={() => setErr(null)}
      />

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Separation of concerns</div>
          <div className="summaryCardValue">Directory only</div>
          <div className="summaryCardText">
            The groups hub should let people scan what exists, not force creation and membership state into the same scroll surface.
          </div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Next step</div>
          <div className="summaryCardValue">Open a group detail</div>
          <div className="summaryCardText">
            Each row links to a dedicated group detail page where membership actions and scoped activity can happen without crowding the hub.
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Directory</div>
              <h2 className="cardTitle">Available groups</h2>
              <div className="cardDesc">Open a group to inspect its charter, membership state, and scoped activity.</div>
            </div>
            <div className="buttonRow buttonRowWide statusSummary">
              <button className="btn btnPrimary" onClick={() => nav("/groups/create")} type="button">
                Create group
              </button>
              <button className="btn" onClick={() => void refreshMutationSlices(loadAccountState, refreshAccountContext, refreshGroups)} disabled={loading}>
                {loading ? "Refreshing…" : "Refresh"}
              </button>
            </div>
          </div>

          {groups.length === 0 ? (
            <div className="cardDesc">No groups returned yet.</div>
          ) : (
            <div className="pageStack">
              {groups.map((g) => (
                <button
                  key={g.id}
                  className="quickCard"
                  onClick={() => nav(`/groups/${encodeURIComponent(g.id)}`)}
                >
                  <span>
                    <strong>{g.name}</strong>
                    <small>
                      {g.id} · {g.isPrivate ? "private" : "public"}
                      {g.memberCountHint != null ? ` · ${g.memberCountHint} member(s)` : ""}
                    </small>
                    {g.description ? <small>{g.description.slice(0, 180)}</small> : null}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
