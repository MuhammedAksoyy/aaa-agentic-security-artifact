// B0-B4 comparison over the D1 corpus (paper Section VI-B).
//
// Usage: place this file (and the sibling corpus-*.jsonl files) inside a checked-out
// copy of the target system's repository root, at benchmark/, then run:
//   node --import tsx benchmark/run-b0-b4.mjs
//
// Requires: src/security/security-hitl.ts (this artifact's copy or the target
// system's own, if the retrofit patch has been applied), and the target system's
// own src/infra/exec-approvals-allowlist.ts + src/infra/exec-approvals.ts (B1).
//
// B0: no protection (baseline)
// B1: the target system's own allowlist analyzer, security=allowlist / ask=on-miss,
//     empty allowlist (represents a freshly installed system with no project-specific
//     allowlist configured yet)
// B2: naive substring rule (command.includes("rm "))
// B3: the detector in this artifact (analyzeCommandRisk)
// B4: B1 OR B3 (layered)
import { analyzeCommandRisk } from "../src/security/security-hitl.js";
// The artifact lives beside the pinned target checkout in this reproduction
// workspace.  Keep the detector local to the artifact, but import B1 from the
// pinned OpenClaw source rather than a machine-specific absolute path.
import { evaluateShellAllowlist } from "../../openclaw-upstream/src/infra/exec-approvals-allowlist.js";
import { requiresExecApproval } from "../../openclaw-upstream/src/infra/exec-approvals.js";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

function load(f) {
  return readFileSync(join(__dirname, f), "utf8")
    .trim()
    .split("\n")
    .map(JSON.parse);
}

const benign = load("corpus-benign.jsonl");
const malicious = load("corpus-malicious.jsonl");
const evasion = load("corpus-evasion.jsonl");
const all = [...benign, ...malicious, ...evasion];

function b1Blocked(command) {
  const { analysisOk, allowlistSatisfied } = evaluateShellAllowlist({
    command,
    allowlist: [],
    safeBins: new Set(),
    platform: "linux",
  });
  return requiresExecApproval({
    ask: "on-miss",
    security: "allowlist",
    analysisOk,
    allowlistSatisfied,
  });
}

function b2Blocked(command) {
  return command.includes("rm ");
}

function b3Blocked(command) {
  return analyzeCommandRisk(command).isRisky;
}

const rows = all.map((r) => {
  let b1;
  try {
    b1 = b1Blocked(r.command);
  } catch (e) {
    b1 = true; // analysis failure -> allowlist mode treats as not-ok -> blocked
  }
  const b2 = b2Blocked(r.command);
  const b3 = b3Blocked(r.command);
  const b4 = b1 || b3;
  return { ...r, b0: false, b1, b2, b3, b4 };
});

function metrics(rows, key) {
  const ben = rows.filter((r) => r.label === "benign");
  const mal = rows.filter((r) => r.label === "malicious");
  const fp = ben.filter((r) => r[key]).length;
  const tp = mal.filter((r) => r[key]).length;
  const fpr = fp / ben.length;
  const tpr = tp / mal.length;
  const precision = tp + fp === 0 ? null : tp / (tp + fp);
  const f1 = precision === null || tpr === 0 ? 0 : (2 * precision * tpr) / (precision + tpr);
  return { fp, tp, fpr, tpr, precision, f1 };
}

console.log("=== Overall (100 benign + 100 malicious + 50 evasion-as-malicious) ===");
for (const key of ["b0", "b1", "b2", "b3", "b4"]) {
  const m = metrics(rows, key);
  console.log(
    `${key.toUpperCase()}  FPR=${(m.fpr * 100).toFixed(1)}%  TPR=${(m.tpr * 100).toFixed(1)}%  ` +
      `Precision=${m.precision === null ? "n/a" : (m.precision * 100).toFixed(1) + "%"}  F1=${m.f1.toFixed(3)}`,
  );
}

console.log("\n=== Malicious-only (M-*, non-evasion, 100 rows) ===");
const nonEvasionRows = rows.filter((r) => r.label === "benign" || r.id.startsWith("M-"));
for (const key of ["b0", "b1", "b2", "b3", "b4"]) {
  const m = metrics(nonEvasionRows, key);
  console.log(
    `${key.toUpperCase()}  FPR=${(m.fpr * 100).toFixed(1)}%  TPR=${(m.tpr * 100).toFixed(1)}%  ` +
      `Precision=${m.precision === null ? "n/a" : (m.precision * 100).toFixed(1) + "%"}`,
  );
}

console.log("\n=== Evasion-only (E-*, 50 rows) -- catch rate per config ===");
const evRows = rows.filter((r) => r.id.startsWith("E-"));
for (const key of ["b0", "b1", "b2", "b3", "b4"]) {
  const caught = evRows.filter((r) => r[key]).length;
  console.log(`${key.toUpperCase()}  caught=${caught}/${evRows.length} (${(100 * caught / evRows.length).toFixed(1)}%)`);
}

writeFileSync(
  join(__dirname, "results-b0-b4.csv"),
  "id,label,family,obfuscation,b0,b1,b2,b3,b4\n" +
    rows.map((r) => `${r.id},${r.label},${r.family},${r.obfuscation},${r.b0},${r.b1},${r.b2},${r.b3},${r.b4}`).join("\n") +
    "\n",
);
console.log("\nWrote results-b0-b4.csv");
