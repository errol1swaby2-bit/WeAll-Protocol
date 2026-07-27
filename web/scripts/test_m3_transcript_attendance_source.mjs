import { readFileSync } from "node:fs";

const source = readFileSync(
  new URL("../tests/e2e/m3_civic_governance_real_stack.spec.ts", import.meta.url),
  "utf8",
);

function assertIncludes(needle, label) {
  if (!source.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

function assertNotIncludes(needle, label) {
  if (source.includes(needle)) {
    throw new Error(`${label}: forbidden ${needle}`);
  }
}

assertIncludes(
  'evidence_kind?: string;',
  "M3 action contract must expose embedded evidence kind",
);

assertIncludes(
  'const EMBEDDED_ATTENDANCE_EVIDENCE_KIND = "acceptance_embedded_attendance";',
  "M3 real-stack gate must use the canonical attendance evidence kind",
);

assertIncludes(
  'function isEmbeddedAttendancePair(first: M3Action, second: M3Action): boolean',
  "M3 real-stack gate must validate acceptance/attendance pairs",
);

assertIncludes(
  'const seen = new Map<string, M3Action[]>();',
  "M3 real-stack gate must count records per transaction",
);

assertIncludes(
  'priorRecords.length',
  "M3 real-stack gate must reject transaction IDs used more than twice",
);

assertIncludes(
  'attendance.tx_id === acceptance.tx_id',
  "M3 real-stack gate must require a shared committed transaction",
);

assertIncludes(
  'attendance.role === acceptance.role',
  "M3 real-stack gate must bind attendance to the accepting role",
);

assertIncludes(
  'attendance.account === acceptance.account',
  "M3 real-stack gate must bind attendance to the accepting account",
);

assertIncludes(
  'attendance.subject_id === acceptance.subject_id',
  "M3 real-stack gate must bind attendance to the same dispute",
);

assertNotIncludes(
  'const seen = new Set<string>();',
  "M3 real-stack gate must not reject every repeated transaction ID",
);

assertNotIncludes(
  'duplicate transaction id in transcript:',
  "M3 real-stack gate must not retain the blanket duplicate assertion",
);

console.log(
  "M3 embedded attendance transcript source checks passed",
);
