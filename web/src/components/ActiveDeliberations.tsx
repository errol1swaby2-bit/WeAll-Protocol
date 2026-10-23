import React, { useCallback, useEffect, useMemo, useState } from "react";

import { useMutationRefresh } from "../hooks/useMutationRefresh";
import {
  governanceProposalIdOf,
  governanceProposalStageOf,
  governanceProposalTitleOf,
  loadGovernanceProposalSurface,
  type GovernanceProposal,
} from "../lib/governance";
import { nav } from "../lib/router";

const COMMENT_STAGES = new Set(["draft", "poll", "revision", "validation"]);
const ACTIVE_STAGES = new Set(["draft", "poll", "revision", "validation", "voting", "vote"]);

type PublicComment = {
  comment_id?: string;
  by?: string;
  body?: string;
  height?: number;
};

type Props = {
  base: string;
  proposals?: GovernanceProposal[];
  maxItems?: number;
  title?: string;
};

function commentsOf(proposal: GovernanceProposal): PublicComment[] {
  const raw = proposal.raw && typeof proposal.raw === "object" ? proposal.raw : {};
  const comments = Array.isArray(raw.comments) ? raw.comments : [];
  return comments
    .filter((item: unknown): item is PublicComment => !!item && typeof item === "object" && !Array.isArray(item))
    .slice()
    .sort((a, b) =>
      Number(a.height || 0) - Number(b.height || 0) ||
      String(a.comment_id || "").localeCompare(String(b.comment_id || "")),
    );
}

export function activeDeliberationProposals(proposals: GovernanceProposal[]): GovernanceProposal[] {
  return proposals
    .filter((proposal) => !!governanceProposalIdOf(proposal) && ACTIVE_STAGES.has(governanceProposalStageOf(proposal)))
    .slice()
    .sort((a, b) => {
      const aComments = commentsOf(a);
      const bComments = commentsOf(b);
      const aHeight = Math.max(Number(a.updated_at_height || 0), Number(aComments.at(-1)?.height || 0));
      const bHeight = Math.max(Number(b.updated_at_height || 0), Number(bComments.at(-1)?.height || 0));
      return bHeight - aHeight || governanceProposalIdOf(a).localeCompare(governanceProposalIdOf(b));
    });
}

/**
 * A read-only cross-surface preview of protocol-native governance comments.
 * This does not transform signed deliberation transactions into social posts.
 * The proposal detail page remains the only place to submit a comment.
 */
export default function ActiveDeliberations({
  base,
  proposals,
  maxItems = 3,
  title = "Active deliberations",
}: Props): JSX.Element {
  const externalItems = proposals !== undefined;
  const [loaded, setLoaded] = useState<GovernanceProposal[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");

  const load = useCallback(async (): Promise<void> => {
    if (externalItems) return;
    setLoading(true);
    setLoadError("");
    try {
      const result = await loadGovernanceProposalSurface(base, { limit: 200, activeOnly: true });
      setLoaded(result.items);
    } catch (e: unknown) {
      setLoadError(e instanceof Error ? e.message : "Unable to load public governance discussions.");
    } finally {
      setLoading(false);
    }
  }, [base, externalItems]);

  useEffect(() => {
    if (!externalItems) void load();
  }, [externalItems, load]);

  useMutationRefresh({
    entityTypes: ["proposal"],
    onRefresh: async () => {
      if (!externalItems) await load();
    },
  });

  const activeItems = useMemo(
    () => activeDeliberationProposals(externalItems ? proposals || [] : loaded).slice(0, Math.max(1, maxItems)),
    [externalItems, proposals, loaded, maxItems],
  );

  return (
    <section className="card" aria-label="Active proposal deliberations">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Decision discussions</div>
            <h2 className="cardTitle">{title}</h2>
            <div className="cardDesc">
              Explore signed public comments on open decisions. Deliberation stays bound to the decision record;
              this preview is not an instant-message channel.
            </div>
          </div>
          <div className="statusSummary">
            {!externalItems ? <button className="btn" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button> : null}
            <button className="btn" onClick={() => nav("/decisions")}>All decisions</button>
          </div>
        </div>

        {loadError && !externalItems ? (
          <div className="calloutInfo" role="alert">
            Discussion activity could not be refreshed: {loadError}. Existing previews may be stale.
          </div>
        ) : null}

        {activeItems.length === 0 ? (
          <div className="cardDesc">
            {loading && !externalItems
              ? "Loading public deliberations…"
              : loadError && !externalItems
                ? "Discussion activity is unavailable right now."
                : "No active decision discussions or voting-stage conversations were returned."}
          </div>
        ) : (
          <div className="pageStack">
            {activeItems.map((proposal) => {
              const id = governanceProposalIdOf(proposal);
              const stage = governanceProposalStageOf(proposal);
              const openForComments = COMMENT_STAGES.has(stage);
              const comments = commentsOf(proposal);
              const latest = comments.slice(-2);
              const groupId = String(proposal.raw?.group_id || "").trim();
              return (
                <article key={id} className="summaryCard">
                  <div className="sectionHead">
                    <div>
                      <div className="summaryCardLabel">Community decision{groupId ? " · " + groupId : ""}</div>
                      <h3 className="cardTitle">{governanceProposalTitleOf(proposal)}</h3>
                    </div>
                    <div className="statusSummary">
                      <span className="statusPill">{stage}</span>
                      <span className={"statusPill " + (openForComments ? "ok" : "warn")}>
                        {openForComments ? "Comments open" : "Deliberation closed"}
                      </span>
                    </div>
                  </div>
                  <div className="cardDesc">
                    {comments.length} public deliberation comment{comments.length === 1 ? "" : "s"}
                    {comments.length ? " · Latest at block " + Number(comments.at(-1)?.height || 0) : ""}
                  </div>
                  {latest.length ? (
                    <div className="pageStack" aria-label="Recent deliberation comments">
                      {latest.map((comment, index) => (
                        <div className="infoCard" key={String(comment.comment_id || index)}>
                          <div className="summaryCardLabel">
                            {String(comment.by || "Unknown participant")} · block {Number(comment.height || 0) || "—"}
                          </div>
                          <div className="feedBodyText">
                            {String(comment.body || "").slice(0, 240)}
                            {String(comment.body || "").length > 240 ? "…" : ""}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="cardDesc">
                      {openForComments ? "No comments yet. Open the discussion to contribute." : "No public comments recorded before voting."}
                    </div>
                  )}
                  <div className="buttonRow">
                    <button className="btn btnPrimary" onClick={() => nav("/decisions/" + encodeURIComponent(id))}>
                      {openForComments ? "Join deliberation" : "Review discussion and vote"}
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        )}
        <div className="cardDesc">
          Read visibility is public. Eligibility, stage windows, signatures, and transaction inclusion are enforced by the protocol.
        </div>
      </div>
    </section>
  );
}
