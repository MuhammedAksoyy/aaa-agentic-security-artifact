// D2 -- latency cost of the retrofit, three configurations, N=1000 each (paper
// Section VI-D).
//
// Usage: place this file inside a checked-out copy of the target system's repository
// root, at benchmark/, with the retrofit patch applied (patches/retrofit-integration-
// point.diff) and a validating sidecar listening on :8081 (see mock-validator.mjs in
// this directory for a minimal example), then run:
//   node --import tsx benchmark/run-d2-latency.mjs
import { analyzeCommandRisk, getSecurityOrchestrator } from "../src/security/security-hitl.js";
import { SecurityInterceptor } from "../src/node-host/SecurityInterceptor.js";

const N = 1000;
const CMD = "git status";

function percentile(sorted, p) {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}
function report(label, samplesMs) {
  const sorted = [...samplesMs].sort((a, b) => a - b);
  console.log(
    `${label.padEnd(28)} p50=${percentile(sorted, 50).toFixed(3)}ms  p95=${percentile(sorted, 95).toFixed(3)}ms  p99=${percentile(sorted, 99).toFixed(3)}ms  mean=${(sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(3)}ms`,
  );
}

async function measureLocal() {
  const samples = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    analyzeCommandRisk(CMD);
    samples.push(performance.now() - t0);
  }
  return samples;
}

async function measureSidecar() {
  const samples = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    await SecurityInterceptor.interceptCommand({
      runId: `d2-${i}`,
      cmdText: CMD,
      argv: ["git", "status"],
    });
    samples.push(performance.now() - t0);
  }
  return samples;
}

async function measureHitl() {
  const orch = getSecurityOrchestrator();
  const samples = [];
  const N_HITL = 100; // fewer: each requires an event-loop round trip to auto-resolve
  for (let i = 0; i < N_HITL; i++) {
    const t0 = performance.now();
    const promise = orch.requestApproval({
      command: CMD,
      workdir: process.cwd(),
      riskAnalysis: { isRisky: true, category: "system_command", reason: "d2 test", targets: [] },
    });
    // Simulate an operator who resolves instantly (best case -- isolates
    // orchestration overhead from human reaction time, which cannot be
    // benchmarked meaningfully).
    queueMicrotask(() => {
      const [action] = orch.getPendingActions();
      if (action) orch.resolveApproval(action.actionId, true, "synthetic-operator");
    });
    await promise;
    samples.push(performance.now() - t0);
  }
  return samples;
}

const local = await measureLocal();
report(`(a) local analysis (N=${N})`, local);

let sidecar;
try {
  sidecar = await measureSidecar();
  report(`(b) HTTP sidecar round trip (N=${N})`, sidecar);
} catch (e) {
  console.log(`(b) HTTP sidecar round trip: FAILED (${e.message}) -- is a validator running on :8081?`);
}

const hitl = await measureHitl();
report(`(c) HITL orchestration (N=100, instant-resolve)`, hitl);

console.log("\nNote: (c) isolates SecurityOrchestrator/Promise overhead from human reaction");
console.log("time, which cannot be benchmarked. Real HITL latency = this overhead + however");
console.log("long the human takes to respond (seconds, up to the configured timeout).");
