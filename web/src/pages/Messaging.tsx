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
            Messages stay separate from the feed, decisions, and review work so conversations remain easy to find.
            As the messaging surface expands, it should remain conversation-first and simple for ordinary users.
          </p>
          <section className="surfaceBoundaryBar" aria-label="Messaging page boundaries">
            <div className="surfaceBoundaryHeader">
              <div>
                <h2 className="surfaceBoundaryTitle">Dedicated communication domain</h2>
                <p className="surfaceBoundaryText">
                  Messaging is connected to the rest of the product by account identity and notifications, not by mixing private conversations into feed, decisions, or review pages.
                </p>
              </div>
              <span className="statusPill">Messages</span>
            </div>
            <div className="surfaceBoundaryList">
              <span className="surfaceBoundaryTag">Center: conversations only</span>
              <span className="surfaceBoundaryTag">No decision voting</span>
              <span className="surfaceBoundaryTag">No report review</span>
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
                The dedicated Messages page exists so direct conversations have a clear home. Conversation threading, inbox loading, and direct-message creation can continue here in later implementation passes.
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
