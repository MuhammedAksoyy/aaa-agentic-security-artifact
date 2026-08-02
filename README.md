# Artifact: Security Cannot Be Retrofitted

Companion artifact for the paper *"Security Cannot Be Retrofitted: An
Authorization--Approval--Accountability Assessment of Agentic AI Systems"* (submitted to
SINCONF 2026). This bundle contains the security components and benchmark suite described
in Sections V and VI, sufficient to reproduce every number reported in the paper's tables.

**Anonymity note.** This artifact is a clean, standalone extraction of the paper's
contribution -- it deliberately does not include the target system's full source tree
(the target is a large, publicly available open-source agent gateway; including it here
would both bloat this artifact and risk pointing reviewers at a specific fork whose commit
history could reveal author identity). To reproduce, apply the two patches in `patches/`
to a checkout of the target system version noted in the paper (or any sufficiently similar
version -- see Limitations in the paper for how tool-surface size affects Mediation
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
    tool-gate.test.ts     -- 10 tests exercising both shell and non-shell tools,
                             including the message-tool case that has no shell syntax
                             at all but is held for approval because it is classified
                             as irreversible.
  node-host/
    SecurityInterceptor.ts -- the retrofit (Section V-A): blocks on an external
                             HTTP validator before allowing a shell command through.

patches/
  retrofit-integration-point.diff        -- where SecurityInterceptor.ts is wired
                                             into the target system (Section V-A)
  relocated-gate-integration-point.diff  -- where tool-gate.ts is wired in instead
                                             (Section V-B)

benchmark/
  corpus-benign.jsonl       -- 100 benign commands (56 sampled from a real, redacted
                               shell history from an unrelated robotics project, 44
                               synthetic for family coverage)
  corpus-malicious.jsonl    -- 100 malicious commands across 14 threat families
  corpus-evasion.jsonl      -- 50 evasion variants derived from the malicious set
  mediation.csv             -- raw tool-by-tool classification backing Table VI
                               (side-effecting?, mediated/partial/unmediated, gate
                               mechanism) for both the fork baseline and current
                               upstream version studied
  results-b0-b4.csv          -- raw per-command results for the five detection
                               configurations in Table IV
  run-b0-b4.mjs             -- reproduces Table IV (detection accuracy, B0-B4)
  run-d2-latency.mjs        -- reproduces Table V (latency)
  mock-validator.mjs        -- minimal external validator for the retrofit's HTTP
                               round trip during reproduction (not a security control)
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

### Table V -- latency

Requires a checkout of the target system with `patches/retrofit-integration-point.diff`
applied, plus the mock validator running:

```bash
node benchmark/mock-validator.mjs &
node --import tsx benchmark/run-d2-latency.mjs
```

### Table VI -- Mediation Completeness

`mediation.csv` is the raw classification data. The method (Section III-A): enumerate
every tool the target system's core catalog defines, classify each as side-effecting or
not, and for each side-effecting tool determine whether it passes through a mandatory
gate on the agent's primary invocation loop (not merely a separate HTTP surface or an
owner-only check). This is a manual classification task supported by, but not fully
automated by, code search; see the paper's Section III-A and VI-A for the full rubric and
inter-rater methodology.

### Verifying the artifact's detector matches the paper's numbers

`security-hitl.ts` in this artifact was checked against the original (unredacted, comment-
translated) working copy across all 250 corpus commands with zero behavioral differences
(`isRisky` output identical on every command); only comments, log strings, and identifying
names were changed, not logic. Re-running `run-b0-b4.mjs` against this file reproduces
Table IV exactly.

## What this artifact does not include

- The target system's own source tree (patches assume you have your own checkout).
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
