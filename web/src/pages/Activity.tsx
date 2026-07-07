import React, { useEffect, useMemo, useState } from "react";

import { getAuthHeaders, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";

type ActivityItem = {
  id: string;
  type: string;
  title: string;
  body: string;
  href?: string;
  priority?: "normal" | "high";
};

function asObject(value: any): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function accountCandidates(account: string): Set<string> {
  const acct = normalizeAccount(account || "");
  const raw = String(account || "").trim();
  return new Set([acct, raw].filter(Boolean));
}

function textIncludesAccount(value: any, candidates: Set<string>): boolean {
  const text = JSON.stringify(value || {}).toLowerCase();
  for (const candidate of candidates) {
    if (candidate && text.includes(candidate.toLowerCase())) return true;
  }
  return false;
}

function collectPublicActivity(snapshot: any, account: string): ActivityItem[] {
  const accountSet = accountCandidates(account);
  const items: ActivityItem[] = [];
  const state = asObject(snapshot?.state || snapshot);

  const postsRoot = asObject(state.content || state.posts || {});
  const posts = asObject(postsRoot.posts_by_id || postsRoot.by_id || state.posts_by_id || {});
  const comments = asObject(postsRoot.comments_by_id || state.comments_by_id || {});
  for (const [id, post] of Object.entries(posts)) {
    if (!textIncludesAccount(post, accountSet)) continue;
    const postId = String((post as any)?.post_id || id);
    items.push({
      id: `mention:${postId}`,
      type: "mention",
      title: "Public mention",
      body: `A public post references ${account}.`,
      href: `/content/${encodeURIComponent(postId)}`,
    });
  }
  for (const [id, comment] of Object.entries(comments)) {
    if (!textIncludesAccount(comment, accountSet)) continue;
    const parent = String((comment as any)?.post_id || (comment as any)?.parent_post_id || "").trim();
    items.push({
      id: `reply:${String(id)}`,
      type: "reply",
      title: "Public reply or mention",
      body: `A public comment references ${account}.`,
      href: parent ? `/thread/${encodeURIComponent(parent)}` : "/feed",
    });
  }

  const disputesRoot = asObject(state.disputes || {});
  const disputes = asObject(disputesRoot.disputes_by_id || state.disputes_by_id || {});
  for (const [id, dispute] of Object.entries(disputes)) {
    if (!textIncludesAccount(dispute, accountSet)) continue;
    const disputeId = String((dispute as any)?.dispute_id || id);
    items.push({
      id: `dispute:${disputeId}`,
      type: "dispute_assignment",
      title: "Public review or report notice",
      body: "A public dispute/review record references your account or role.",
      href: `/reports/${encodeURIComponent(disputeId)}`,
      priority: "high",
    });
  }

  const proposalsRoot = asObject(state.governance || state.gov || {});
  const proposals = asObject(proposalsRoot.proposals_by_id || state.proposals_by_id || {});
  for (const [id, proposal] of Object.entries(proposals)) {
    if (!textIncludesAccount(proposal, accountSet)) continue;
    const proposalId = String((proposal as any)?.proposal_id || id);
    items.push({
      id: `governance:${proposalId}`,
      type: "governance_notice",
      title: "Public governance notice",
      body: "A public decision record references your account or responsibilities.",
      href: `/decisions/${encodeURIComponent(proposalId)}`,
    });
  }

  const groups = asObject(state.groups_by_id || asObject(state.groups).groups_by_id || {});
  for (const [id, group] of Object.entries(groups)) {
    if (!textIncludesAccount(group, accountSet)) continue;
    const groupId = String((group as any)?.group_id || id);
    items.push({
      id: `group:${groupId}`,
      type: "group_invitation",
      title: "Public group activity",
      body: "A public group membership, invitation, or role event references your account.",
      href: `/groups/${encodeURIComponent(groupId)}`,
    });
  }

  const validators = asObject(state.validators || state.validator_set || state.operator_status || {});
  if (textIncludesAccount(validators, accountSet)) {
    items.push({
      id: "operator:account",
      type: "validator_operator_alert",
      title: "Public node/operator alert",
      body: "Public validator/operator state references your account.",
      href: "/node",
      priority: "high",
    });
  }

  const dedup = new Map<string, ActivityItem>();
  for (const item of items) dedup.set(item.id, item);
  return Array.from(dedup.values()).slice(0, 100);
}

export default function Activity(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = normalizeAccount(session?.account || "");
  const headers = useMemo(() => (account ? getAuthHeaders(account) : undefined), [account]);
  const [items, setItems] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  async function load(): Promise<void> {
    if (!account) return;
    setLoading(true);
    setErr(null);
    try {
      const snapshot = await weall.stateSnapshot(base, headers);
      setItems(collectPublicActivity(snapshot, account));
    } catch (e: any) {
      setErr({ msg: e?.message || "Unable to load public activity notices.", details: e?.payload || e?.body || e });
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, [account, base]);

  return (
    <section className="pageStack">
      <div className="pageHeader">
        <div>
          <div className="eyebrow">Public activity</div>
          <h1>Activity notices</h1>
          <p>
            Notices here are derived from publicly inspectable protocol events: mentions, replies, group invitations,
            moderation notices, dispute assignments, governance notices, and validator/operator alerts.
          </p>
        </div>
        <button className="btn" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button>
      </div>

      <section className="card">
        <div className="cardBody formStack">
          <div className="eyebrow">Protocol rule</div>
          <h2 className="cardTitle">Participation can be gated; visibility cannot</h2>
          <p className="cardDesc">
            WeAll does not provide protocol-native private user-to-user communication. Group content and moderation activity remain public;
            group membership may restrict posting, commenting, voting, moderation, or administration.
          </p>
        </div>
      </section>

      {err ? <ErrorBanner message={err.msg} details={err.details} onRetry={() => void load()} onDismiss={() => setErr(null)} /> : null}

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionTitleRow">
            <div>
              <div className="eyebrow">Public event notices</div>
              <h2 className="cardTitle">{items.length ? `${items.length} relevant public notice${items.length === 1 ? "" : "s"}` : "No public notices found"}</h2>
            </div>
          </div>

          {items.length ? (
            <div className="listStack">
              {items.map((item) => (
                <article key={item.id} className="listItem">
                  <div>
                    <div className="eyebrow">{item.type.replace(/_/g, " ")}{item.priority === "high" ? " · high" : ""}</div>
                    <h3>{item.title}</h3>
                    <p>{item.body}</p>
                  </div>
                  {item.href ? <button className="btn btnSmall" onClick={() => nav(item.href || "/activity")}>Open</button> : null}
                </article>
              ))}
            </div>
          ) : (
            <p className="cardDesc">
              There are no currently indexed public notices for {account || "this account"}. The absence of a notice does not hide protocol data; it only means this derived view found no relevant public event.
            </p>
          )}
        </div>
      </section>
    </section>
  );
}
