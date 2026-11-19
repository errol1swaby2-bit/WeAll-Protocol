import React, { useEffect, useState } from "react";
import type { GroupElectionRecord } from "../api/weall";
import {
  localBallotPlanningGate,
  moveRankedCandidate,
  rankCandidate,
  unrankCandidate,
} from "../lib/groupBallotPlanning";

type Props = { election: GroupElectionRecord; groupId: string };

/**
 * Deliberately NO network, no signed submission, no browser storage.
 * The draft exists only in React component memory and dies on unmount.
 */
export default function GroupBallotPlanner({ election, groupId }: Props): JSX.Element {
  const [ranking, setRanking] = useState<string[]>([]);
  const gate = localBallotPlanningGate(election, groupId);
  const candidates = gate.canPrepare ? election.candidates || [] : [];
  const rosterKey = JSON.stringify([groupId, election.election_id, election.candidates, election.observed_height]);

  useEffect(() => {
    setRanking([]);
  }, [rosterKey]);

  const unranked = candidates.filter(candidate => !ranking.includes(candidate));

  return (
    <section className="card" aria-label="Non-submitting election ranking practice">
      <div className="cardBody formStack">
        <div className="eyebrow">Ballot design rehearsal · no submission</div>
        <h3 className="cardTitle">Arrange your preferences locally</h3>
        <div className="calloutDanger" role="alert">
          Secret-ballot protection is not verified. The current signed group-ballot
          transaction exposes both the voter account and plaintext ranking, even if
          the resulting chain state aggregates ballots. No vote will be signed, sent, saved or counted here.
        </div>
        {!gate.canPrepare ? (
          <div className="calloutInfo">{gate.explanation} Ranking practice is unavailable for this snapshot.</div>
        ) : (
          <>
            <p className="cardDesc">
              Select candidates in order of preference, then adjust their position.
              Partial rankings are for on-screen practice only. Your draft is cleared when
              the election or observed record changes, or when you leave this page.
              Anyone viewing your screen can see it.
            </p>
            <div className="formStack" aria-label="Ranked candidate preview">
              <h4 className="cardTitle">Current order</h4>
              {!ranking.length ? <p className="cardDesc">No candidates ranked yet.</p> : null}
              {ranking.map((candidate, index) => (
                <div className="quickCard quickCardSplit" key={candidate}>
                  <div className="quickCardMain">
                    <strong>{index + 1}. {candidate}</strong>
                    <small>Local preview · never submitted</small>
                  </div>
                  <div className="buttonRow">
                    <button type="button" className="btn"
                      aria-label={`Move ${candidate} higher`}
                      disabled={index === 0}
                      onClick={() => setRanking(previous => moveRankedCandidate(previous, candidate, -1))}>
                      Higher
                    </button>
                    <button type="button" className="btn"
                      aria-label={`Move ${candidate} lower`}
                      disabled={index === ranking.length - 1}
                      onClick={() => setRanking(previous => moveRankedCandidate(previous, candidate, 1))}>
                      Lower
                    </button>
                    <button type="button" className="btn"
                      aria-label={`Remove ${candidate} from practice ranking`}
                      onClick={() => setRanking(previous => unrankCandidate(previous, candidate))}>
                      Remove
                    </button>
                  </div>
                </div>
              ))}
            </div>
            <div className="formStack" aria-label="Unranked canonical candidates">
              <h4 className="cardTitle">Remaining candidates</h4>
              {unranked.map(candidate => (
                <button key={candidate} type="button" className="btn"
                  onClick={() => setRanking(previous => rankCandidate(previous, candidate, candidates))}>
                  Add {candidate} to practice ranking
                </button>
              ))}
              {!unranked.length ? <p className="cardDesc">All returned candidates have been ranked.</p> : null}
            </div>
            <button type="button" className="btn" disabled={!ranking.length}
              onClick={() => setRanking([])}>Clear local ranking</button>
          </>
        )}
        <div className="calloutInfo">
          Submission status: blocked. The election API is read-only and the signed-envelope
          confidentiality problem must be resolved before this becomes a voting interface.
        </div>
      </div>
    </section>
  );
}
