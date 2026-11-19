/**
 * Verification is one journey with focused views. Selection is presentation
 * only; signed requests, reviewer authority and canonical status stay backend-enforced.
 */
export const VERIFICATION_SECTIONS = [
  { id: "overview", label: "Overview" },
  { id: "async", label: "Record evidence" },
  { id: "live", label: "Live verification" },
  { id: "responsibilities", label: "Responsibilities" },
  { id: "history", label: "Case history" },
  { id: "technical", label: "Technical records" },
] as const;

export type VerificationSection = (typeof VERIFICATION_SECTIONS)[number]["id"];

export function verificationSectionFromHash(hash: string): VerificationSection {
  const raw = String(hash || "");
  const path = raw.startsWith("#") ? raw.slice(1).split("?")[0] : raw.split("?")[0];
  if (path === "/verification/async") return "async";
  if (path === "/verification/live/request") return "live";
  if (path === "/verification/history") return "history";

  const offset = raw.indexOf("?");
  const fromQuery = new URLSearchParams(offset >= 0 ? raw.slice(offset + 1) : "").get("tab") || "overview";
  return VERIFICATION_SECTIONS.find((entry) => entry.id === fromQuery)?.id || "overview";
}
