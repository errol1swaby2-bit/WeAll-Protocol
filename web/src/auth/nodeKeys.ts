import { generateKeypair, normalizeAccount } from "./keys";

export type NodeKeyFile = {
  type: "weall_node_key";
  version: 1;
  account: string;
  nodeId: string;
  deviceId: string;
  label: string;
  publicKeyB64: string;
  secretKeyB64: string;
  createdAt: string;
  warning: string;
};

export function safeNodeKeyFilename(account: string): string {
  const safe = normalizeAccount(account).replace(/^@/, "").replace(/[^a-z0-9_-]/g, "_") || "account";
  return `weall-node-key-${safe}.json`;
}

export function createNodeKeyFile(args: {
  account: string;
  nodeId: string;
  deviceId: string;
  label?: string;
}): NodeKeyFile {
  const account = normalizeAccount(args.account);
  if (!account) throw new Error("account_required");

  const nodeId = String(args.nodeId || `node:${account}`).trim() || `node:${account}`;
  const deviceId = String(args.deviceId || nodeId).trim() || nodeId;
  const label = String(args.label || "Primary node").trim() || "Primary node";
  const kp = generateKeypair();

  return {
    type: "weall_node_key",
    version: 1,
    account,
    nodeId,
    deviceId,
    label,
    publicKeyB64: kp.pubkeyB64,
    secretKeyB64: kp.secretKeyB64,
    createdAt: new Date().toISOString(),
    warning:
      "This is a separate node operation key, not your WeAll account recovery key. Store it on the node host securely. Anyone with this file may operate this registered node identity until it is revoked.",
  };
}

export function serializeNodeKeyFile(file: NodeKeyFile): string {
  return JSON.stringify(
    {
      type: file.type,
      version: file.version,
      account: normalizeAccount(file.account),
      nodeId: String(file.nodeId || ""),
      deviceId: String(file.deviceId || ""),
      label: String(file.label || ""),
      publicKeyB64: String(file.publicKeyB64 || ""),
      secretKeyB64: String(file.secretKeyB64 || ""),
      createdAt: String(file.createdAt || ""),
      warning: String(file.warning || ""),
    },
    null,
    2,
  );
}

export function downloadNodeKeyFile(file: NodeKeyFile): void {
  const blob = new Blob([serializeNodeKeyFile(file)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = safeNodeKeyFilename(file.account);
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
