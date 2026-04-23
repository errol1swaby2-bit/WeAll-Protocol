import { normalizeAccount } from "../auth/keys";

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

export function accountVariants(value: string): string[] {
  const raw = String(value || "").trim();
  if (!raw) return [];
  const normalized = normalizeAccount(raw);
  const base = normalized.startsWith("@") ? normalized.slice(1) : normalized;
  const out = [normalized, base ? `@${base}` : "", base, raw].filter(Boolean);
  return Array.from(new Set(out));
}

export function recordForAccount(mapping: unknown, account: string): Record<string, any> | null {
  const recs = asRecord(mapping);
  for (const variant of accountVariants(account)) {
    const rec = recs[variant];
    if (rec && typeof rec === "object" && !Array.isArray(rec)) return rec as Record<string, any>;
  }
  return null;
}

export function voteForAccount(mapping: unknown, account: string): { vote?: string; height?: number } | null {
  const record = recordForAccount(mapping, account);
  if (!record) return null;
  return record as { vote?: string; height?: number };
}
