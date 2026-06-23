import React from "react";

import { nav } from "../lib/router";

const UNSUPPORTED_CODE = "PRIVATE_MESSAGING_UNSUPPORTED";

export default function Messaging(): JSX.Element {
  return (
    <section className="pageStack">
      <div className="pageHeader">
        <div>
          <div className="eyebrow">Unsupported route</div>
          <h1>Use public activity</h1>
          <p>
            Protocol-native private user-to-user communication is not part of WeAll. Notices are derived from public protocol events. Code: {UNSUPPORTED_CODE}.
          </p>
        </div>
        <button className="btn btnPrimary" onClick={() => nav("/activity")}>Open activity</button>
      </div>
    </section>
  );
}
