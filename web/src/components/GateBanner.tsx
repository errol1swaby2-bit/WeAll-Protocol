import React from "react";
import { GateResult } from "../lib/gates";

type Props = {
  gate: GateResult;
  prefix?: string;
};

export default function GateBanner({ gate, prefix }: Props) {
  if (gate.ok) return null;
  return (
    <div
      style={{
        background: "#fff5f5",
        border: "1px solid #f5c2c2",
        color: "#8b0000",
        padding: 10,
        borderRadius: 10,
        fontSize: 13,
        marginTop: 8,
      }}
    >
      {prefix ? <b>{prefix}: </b> : null}
      {gate.reason || "Action disabled."}
    </div>
  );
}
