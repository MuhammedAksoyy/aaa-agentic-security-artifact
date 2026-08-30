# Artifact: Security Cannot Be Retrofitted

Companion artifact for the paper *"Security Cannot Be Retrofitted: An
Authorization--Approval--Accountability Assessment of Agentic AI Systems"* (accepted with
revision at SINCONF 2026). This bundle contains the security components and benchmark suite described
in Sections V and VI, sufficient to reproduce every number reported in the paper's tables.

**Scope note.** This artifact is a clean, standalone extraction of the paper's
contribution -- it deliberately does not include the full OpenClaw source tree, which would
needlessly bloat the bundle. To reproduce, apply the two patches in `patches/` to a checkout
of the OpenClaw version noted in the paper (or any sufficiently similar version -- see
Limitations in the paper for how tool-surface size affects Mediation
Completeness).

## Contents

```
src/
  security/
    security-hitl.ts     -- the risk detector (B3 in the paper) and approval
                             orchestrator. Verified behaviorally identical to the
                             exact code measured for every number in Table IV/V of
                             the paper (see Verification below).
    tool-gate.ts          -- the relocated gate (Section V-B): the same detector,
                             wrapped at the target system's universal tool-invocation
                             boundary instead of the shell-execution path only.
    tool-gate.test.ts     -- 20 tests: 10 original shell/non-shell cases, 8
                             provider-independent fixtures for tools not directly
                             instantiated in the test environment, and 2 tests
                             isolating the gate's opt-in activation behavior.
  node-host/
    SecurityInterceptor.ts -- the retrofit (Section V-A): blocks on an external
                             HTTP validator before allowing a shell command through.

patches/
  retrofit-integration-point.diff        -- where SecurityInterceptor.ts is wired
                                             into the target system (Section V-A)
  relocated-gate-integration-point.diff  -- where tool-gate.ts is wired in instead
                                             (Section V-B)

benchmark/
  corpus-benign.jsonl       -- 181 benign commands (56 sampled from a real, redacted
                               shell history from an unrelated robotics project, 125
                               synthetic, including near-miss pairs that surface-resemble
                               malicious commands while being safe)
  corpus-malicious.jsonl    -- 191 malicious commands across 14 threat families, at
                               least 10 per family
  corpus-evasion.jsonl      -- 90 evasion variants derived from the malicious set
  mediation.csv             -- raw tool-by-tool classification backing Table VI
                               (side-effecting?, mediated/partial/unmediated, gate
                               mechanism) for both the fork baseline and current
                               upstream version studied
  d3-kappa-confusion-matrix.md -- raw pre-reconciliation contingency table and
                                 calculation summary for Section III-A
  d3-blind-ratings.csv       -- anonymized raw paired labels used to derive the matrix
  compute-d3-kappa.py       -- recomputes n, agreement, expected agreement, and kappa
  results-b0-b4.csv          -- raw per-command results for the five detection
                               configurations in Table IV
  run-b0-b4.mjs             -- reproduces Table IV (detection accuracy, B0-B4)
  run-d2-latency.mjs        -- reproduces Table V (latency)
  mock-validator.mjs        -- minimal external validator for the retrofit's HTTP
                               round trip during reproduction (not a security control)
  d2-reproduction.log       -- raw output of the independent Windows reproduction

vitest.config.ts             -- standalone test discovery for `src/**/*.test.ts`
```

## Reproducing the results

### Table IV -- detection accuracy (B0-B4)

No target-system checkout is required for B0, B2, B3 (they only need
`security-hitl.ts`, included here). B1 requires the target system's own
`exec-approvals-allowlist.ts` and `exec-approvals.ts` modules, imported as shown in
`run-b0-b4.mjs`.

```bash
node --import tsx benchmark/run-b0-b4.mjs
```

### Targeted gate tests

From the artifact root, run:

```bash
npx vitest run src/security/tool-gate.test.ts --reporter=dot
```

The suite has 20 tests: the original ten targeted cases, eight provider-independent
fixtures, and two tests that isolate the gate's activation behavior itself. The fixtures
establish fail-closed gate behavior for the eight tools that were not provider-backed
instantiated; they do not establish provider activation.

**Gate activation is opt-in, not shipped-default.** `wrapToolWithSecurityGate` (see
`src/security/tool-gate.ts`) only wraps a tool's `execute` when the environment variable
`SECURITY_TOOL_GATE` is set to `"1"`. With the variable unset -- the default state of any
checkout that has not explicitly set it -- every tool executes unmodified and the gate
performs no interception at all. The paper's 17/17 and 24/32 coverage figures (Section V-B)
describe this variable set to `1`; they are not a claim about what a fresh checkout runs
without configuration. The two new tests above assert this directly: one confirms a tool
executes untouched with the variable unset, the other confirms the same call is rejected
before execution once it is set.

### Table V -- latency

Requires a checkout of the target system with `patches/retrofit-integration-point.diff`
applied, plus the mock validator running:

```bash
node benchmark/mock-validator.mjs &
node --import tsx benchmark/run-d2-latency.mjs
```

### Independent Windows reproduction (August 2026)

The artifact was independently re-run beside a pinned checkout of OpenClaw commit
`fb3d473a73b039251ac8f28297a54d2a89e5d67e`. From that checkout's root, after its
locked dependencies are installed, run:

```powershell
node --import tsx ..\aaa-agentic-security-artifact\benchmark\run-b0-b4.mjs
node ..\aaa-agentic-security-artifact\benchmark\mock-validator.mjs
# in a second terminal:
node --import tsx ..\aaa-agentic-security-artifact\benchmark\run-d2-latency.mjs
```

This reproduction predates the corpus's later expansion from 250 to 462 commands (every
family raised to at least 10 examples; see Table IV in the paper) and used the earlier
250-command corpus (100 benign, 100 malicious, 50 evasion): B3 obtained FPR 8.0%,
TPR 54.7%, F1 0.683, and caught 32/50 evasion commands. On the current 462-command corpus
in this artifact, B3 obtains FPR 6.6%, TPR (all) 43.8%, TPR (non-evasion) 39.8%, precision
91.1% -- matching Table III. The fresh-install B1/B4 configuration blocked every command
(FPR/TPR 100%) in both runs, as expected for an empty allowlist. The D2 raw log records
local-analysis, HTTP-sidecar, and synthetic-HITL measurements; it is an overhead
measurement only and does not include human approval time.

### Table VI -- Mediation Completeness

`mediation.csv` is the reconciled raw classification data. The method (Section III-A): enumerate
every tool OpenClaw's core catalog defines, classify each as side-effecting or
not, and for each side-effecting tool determine whether it passes through a mandatory
gate on the agent's primary invocation loop (not merely a separate HTTP surface or an
owner-only check). This is a manual classification task supported by, but not fully
automated by, code search; see the paper's Section III-A and VI-A for the full rubric and
inter-rater methodology. The inventory counts logical tools: `cron` and `automations` are
legacy/current aliases for one scheduling capability, although both strings remain in the
gate's compatibility set. `d3-kappa-confusion-matrix.md` records the raw independent
pre-reconciliation contingency table behind the reported $\kappa=0.209$. The paired
anonymized labels and a standalone reproduction script are included as
`d3-blind-ratings.csv` and `compute-d3-kappa.py`; from this directory, run
`python3 compute-d3-kappa.py`.

### Verifying the artifact's detector matches the paper's numbers

`security-hitl.ts` in this artifact was checked against the original (unredacted, comment-
translated) working copy across all 250 corpus commands with zero behavioral differences
(`isRisky` output identical on every command); only comments, log strings, and identifying
names were changed, not logic. Re-running `run-b0-b4.mjs` against this file reproduces
Table IV exactly.

## What this artifact does not include

- The OpenClaw source tree (patches assume you have your own checkout).
- The external notifier and audit-logging components mentioned in `security-hitl.ts`'s
  module comment (Telegram-bot-style notifier, persistent audit log) -- these were never
  implemented in the studied system and are not claimed as contributions.
- Any component of the built-in reference architecture discussed in Section V-C: it is
  unreleased and described in the paper at the level of the guarantees it makes, not its
  implementation.

## License

The files in `src/` are original code, provided under the MIT License (see `LICENSE`).
The two files in `patches/` are minimal diffs against the target system's own MIT-licensed
source and are provided under the same terms.
