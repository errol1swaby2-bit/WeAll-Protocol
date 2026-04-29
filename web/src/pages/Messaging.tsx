import React from "react";

import { nav } from "../lib/router";

export default function Messaging(): JSX.Element {
  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody formStack">
          <div className="eyebrow">Messaging</div>
          <h1 className="heroTitle heroTitleSm">Direct messages stay on their own surface</h1>
          <p className="heroText">
            This route completes the primary navigation contract without leaking communication flows into the content feed, governance queue, or disputes workspace.
            As the messaging surface expands, it should remain conversation-first and separate from the other coordination domains.
          </p>
          <section className="surfaceBoundaryBar" aria-label="Messaging route contract">
            <div className="surfaceBoundaryHeader">
              <div>
                <h2 className="surfaceBoundaryTitle">Dedicated communication domain</h2>
                <p className="surfaceBoundaryText">
                  Messaging is connected to the rest of the product by account identity and notifications, not by merging conversations into feed, governance, or adjudication views.
                </p>
              </div>
              <span className="statusPill">Hub surface</span>
            </div>
            <div className="surfaceBoundaryList">
              <span className="surfaceBoundaryTag">Center: conversations only</span>
              <span className="surfaceBoundaryTag">No governance voting</span>
              <span className="surfaceBoundaryTag">No dispute review</span>
              <span className="surfaceBoundaryTag">No feed mixing</span>
            </div>
          </section>
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Current status</div>
              <h2 className="cardTitle">Messaging shell route is now present</h2>
              <div className="cardDesc">
                The dedicated route exists so the primary navigation contract is complete. Conversation threading, inbox hydration, and direct-message creation can continue here in later implementation passes.
              </div>
            </div>
          </div>
          <div className="buttonRow">
            <button className="btn btnPrimary" onClick={() => nav("/home")}>Open home</button>
            <button className="btn" onClick={() => nav("/profile")}>Open profile</button>
          </div>
        </div>
      </section>
    </div>
  );
}
