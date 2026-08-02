/**
 * Human-in-the-Loop (HITL) command risk detector and approval orchestrator.
 *
 * This module analyzes a shell command for risky operations and, when one is detected,
 * pauses the calling flow (via async/await) until a human approves, denies, or a timeout
 * elapses. This is the detector referred to as B3 in the paper's evaluation (Section VI),
 * and the component wrapped by the retrofit in Section V-A (SecurityInterceptor.ts) and
 * relocated in Section V-B (tool-gate.ts).
 *
 * Architecture:
 *   1. analyzeCommandRisk()  — pattern-based risk detector (33 patterns, five analysis
 *      stages: base64 decoding, command substitution, pipe/chain splitting, direct
 *      pattern match, protected-path targeting)
 *   2. SecurityOrchestrator  — singleton state machine: IDLE -> WAITING -> APPROVED/DENIED
 *   3. Event-based hooks     — an external notifier (e.g. a chat bot) and an audit logger
 *      subscribe to the orchestrator's events; neither is included in this artifact
 *
 * `requestApproval()` returns a `Promise<SecurityDecision>`. The calling code simply
 * `await`s this promise, which pauses the agent's execution without any thread
 * manipulation -- the Node.js event loop handles it.
 */

import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";

// --- Types -------------------------------------------------------------------

/** Possible states of a pending security action */
export type SecurityState = "idle" | "waiting_approval" | "approved" | "denied" | "timed_out";

/** The result returned after a human makes a decision */
export interface SecurityDecision {
  actionId: string;
  approved: boolean;
  decidedBy: string; // e.g. "operator:123456" or "console" or "timeout"
  decidedAt: Date;
  reason?: string;
}

/** Metadata about a risky command awaiting approval */
export interface PendingAction {
  actionId: string;
  command: string;
  workdir: string;
  riskCategory: RiskCategory;
  riskReason: string;
  detectedAt: Date;
  state: SecurityState;
  /** Resolved when a human responds or the timeout fires */
  resolve: (decision: SecurityDecision) => void;
  timeoutHandle?: ReturnType<typeof setTimeout>;
}

/** Risk categories for detected commands */
export type RiskCategory =
  | "file_delete"
  | "file_modify"
  | "file_permission"
  | "system_command"
  | "network"
  | "unknown";

/** Result of risk analysis on a command */
export interface RiskAnalysis {
  isRisky: boolean;
  category: RiskCategory;
  reason: string;
  /** Specific file/path targets extracted from the command, if any */
  targets: string[];
}

/** Events emitted by the SecurityOrchestrator */
export interface SecurityEvents {
  "approval-requested": (action: Omit<PendingAction, "resolve" | "timeoutHandle">) => void;
  "approval-resolved": (decision: SecurityDecision) => void;
  "approval-timeout": (actionId: string) => void;
}

// --- Risky Command Detector ---------------------------------------------------
//
// 33 patterns across six categories: Unix/Windows file deletion, file/permission
// modification, low-level system danger, network-borne remote code execution,
// Node.js and Python filesystem/process APIs, and elevated-privilege commands.
// See the paper's Section VI-C for a family-by-family recall breakdown against a
// 250-command corpus, including the categories this pattern set does not cover
// (credential access, exfiltration, supply-chain, destructive VCS/cloud operations).

/** Patterns that indicate a destructive or risky OS operation */
const RISKY_PATTERNS: Array<{ pattern: RegExp; category: RiskCategory; reason: string }> = [
  // -- File Deletion --
  {
    pattern: /\brm\s+(-[a-zA-Z]*\s+)*[^\s|&;]+/i,
    category: "file_delete",
    reason: "Unix file deletion command (rm) detected",
  },
  {
    pattern: /\brmdir\b/i,
    category: "file_delete",
    reason: "Directory removal command (rmdir) detected",
  },
  {
    pattern: /\bdel\s+\/[fFqQsS]/i,
    category: "file_delete",
    reason: "Windows forced file deletion (del /f or /q) detected",
  },
  {
    pattern: /\brd\s+\/[sS]/i,
    category: "file_delete",
    reason: "Windows recursive directory removal (rd /s) detected",
  },
  {
    pattern: /\bshutil\.rmtree\b/,
    category: "file_delete",
    reason: "Python shutil.rmtree (recursive delete) detected",
  },
  {
    pattern: /\bos\.remove\b/,
    category: "file_delete",
    reason: "Python os.remove detected",
  },
  {
    pattern: /\bos\.unlink\b/,
    category: "file_delete",
    reason: "Python os.unlink detected",
  },
  {
    pattern: /\bunlink\s+/i,
    category: "file_delete",
    reason: "Unix unlink command detected",
  },

  // -- File/Directory Modification --
  {
    pattern: /\bmv\s+/i,
    category: "file_modify",
    reason: "File move/rename (mv) detected -- may overwrite existing files",
  },
  {
    pattern: /\bchmod\s+[0-7]{3,4}\b/i,
    category: "file_permission",
    reason: "File permission change (chmod) detected",
  },
  {
    pattern: /\bchown\b/i,
    category: "file_permission",
    reason: "File ownership change (chown) detected",
  },

  // -- System-level Danger --
  {
    pattern: /\bmkfs\b/i,
    category: "system_command",
    reason: "Filesystem format command (mkfs) detected",
  },
  {
    pattern: /\bdd\s+if=/i,
    category: "system_command",
    reason: "Low-level disk write (dd) detected",
  },
  {
    pattern: />\s*\/dev\/[sh]d[a-z]/i,
    category: "system_command",
    reason: "Direct write to block device detected",
  },
  {
    pattern: /\bformat\s+[a-zA-Z]:/i,
    category: "system_command",
    reason: "Windows disk format command detected",
  },

  // -- Network --
  {
    pattern: /\bcurl\s+.*-[xX]\s+DELETE\b/i,
    category: "network",
    reason: "HTTP DELETE request via curl detected",
  },
  // Remote script download + pipe-execute (RCE)
  {
    pattern: /\bcurl\s+[^|]+\|\s*(?:ba)?sh/i,
    category: "network",
    reason: "Remote code execution via curl|sh pipe detected",
  },
  {
    pattern: /\bwget\s+.*-O\s+-\s*\|\s*(?:ba)?sh/i,
    category: "network",
    reason: "Remote code execution via wget|sh pipe detected",
  },

  // -- Node.js File Operations --
  {
    pattern: /\bfs\.unlinkSync\b/,
    category: "file_delete",
    reason: "Node.js fs.unlinkSync detected",
  },
  { pattern: /\bfs\.rmSync\b/, category: "file_delete", reason: "Node.js fs.rmSync detected" },
  {
    pattern: /\bfs\.rmdirSync\b/,
    category: "file_delete",
    reason: "Node.js fs.rmdirSync (directory removal) detected",
  },
  {
    pattern: /\bfs\.unlink\b/,
    category: "file_delete",
    reason: "Node.js fs.unlink (async delete) detected",
  },
  { pattern: /\bfs\.rm\b/, category: "file_delete", reason: "Node.js fs.rm detected" },

  // -- Python Additional --
  { pattern: /\bos\.rmdir\b/, category: "file_delete", reason: "Python os.rmdir detected" },
  {
    pattern: /\bpathlib\.Path[^)]*\.unlink\b/,
    category: "file_delete",
    reason: "Python pathlib unlink detected",
  },
  {
    pattern: /\bsubprocess\.(?:run|call|Popen)\b/,
    category: "system_command",
    reason: "Python subprocess execution detected",
  },

  // -- Elevated / System Danger --
  {
    pattern: /\bsudo\s+rm\b/i,
    category: "system_command",
    reason: "Elevated privilege file deletion (sudo rm) detected",
  },
  {
    pattern: /\bkill\s+-9\b/,
    category: "system_command",
    reason: "Force kill signal (kill -9) detected",
  },
  {
    pattern: /\bshutdown\b/i,
    category: "system_command",
    reason: "System shutdown command detected",
  },
  { pattern: /\breboot\b/i, category: "system_command", reason: "System reboot command detected" },
];

// --- Protected Paths -----------------------------------------------------------
//
// Commands targeting these directories are treated as risky regardless of which
// (if any) RISKY_PATTERNS entry matches -- see the paper's Section VI-C for the
// path-traversal evasion this prefix check does not catch (`startsWith`, no
// normalization).

const PROTECTED_PATHS = [
  "/etc",
  "/usr",
  "/bin",
  "/sbin",
  "/var",
  "/root",
  "/boot",
  "/sys",
  "/proc",
  "C:\\Windows",
  "C:\\Program Files",
];

/**
 * Checks if any extracted target path falls under a critical system directory.
 * Even an otherwise "safe" command (like `cat`) becomes risky if it targets /etc/passwd.
 */
function isTargetingProtectedPath(targets: string[]): boolean {
  return targets.some((target) =>
    PROTECTED_PATHS.some(
      (protectedPath) => target.startsWith(protectedPath) || target === protectedPath,
    ),
  );
}

// --- Helper Parsers ------------------------------------------------------------

/**
 * Splits a shell command string by pipe (|) and chaining operators (&&, ||, ;).
 * Note: this is a naive split, not quote-aware -- see the paper's Section VI-C for
 * the evasion this enables (an operator inside a quoted string is still split on).
 *   "echo hello && rm -rf /tmp" -> ["echo hello", "rm -rf /tmp"]
 */
function splitCommandChain(command: string): string[] {
  // Split on ||, &&, ;, | -- order matters: || before |
  return command.split(/\s*(?:\|\||&&|;|\|)\s*/);
}

/**
 * Extracts subcommands from $(...) or `...` command substitutions.
 * Note: the $(...) regex is not nesting-aware -- see the paper's Section VI-C for
 * the nested-substitution evasion this enables.
 *   "echo $(rm file.txt)" -> ["rm file.txt"]
 */
function extractCommandSubstitutions(command: string): string[] {
  const subs: string[] = [];

  // $(...) form
  const dollarParenRegex = /\$\(([^)]+)\)/g;
  let match;
  while ((match = dollarParenRegex.exec(command)) !== null) {
    subs.push(match[1]);
  }

  // Backtick form: `...`
  const backtickRegex = /`([^`]+)`/g;
  while ((match = backtickRegex.exec(command)) !== null) {
    subs.push(match[1]);
  }

  return subs;
}

/**
 * Detects base64-encoded commands piped through a decoder.
 * Example attack: `echo "cm0gLXJmIC8=" | base64 -d | sh` (encodes "rm -rf /").
 * Decodes and recursively analyzes; a decode failure is itself treated as risky.
 *
 * Note: only this single `echo X | base64 -d` form is recognized -- see the paper's
 * Section VI-C for the base64 variants (herestring, openssl enc, xxd, in-language
 * decode) this misses entirely.
 */
function detectBase64EncodedCommands(command: string): RiskAnalysis | null {
  const base64PipePattern = /echo\s+["']?([A-Za-z0-9+/=]+)["']?\s*\|\s*base64\s+-d/;
  const match = base64PipePattern.exec(command);
  if (!match) {
    return null;
  }

  try {
    const decoded = Buffer.from(match[1], "base64").toString("utf-8");
    const innerAnalysis = analyzeCommandRisk(decoded);
    if (innerAnalysis.isRisky) {
      return {
        ...innerAnalysis,
        reason: `${innerAnalysis.reason} (detected inside base64-encoded command: "${decoded}")`,
      };
    }
  } catch {
    // Decode failed -- unknown binary payload, treat as risky.
    // Note: Node's base64 decoder rarely throws on invalid input in practice, so
    // this branch is close to dead code -- see the paper's Section VI-C.
    return {
      isRisky: true,
      category: "unknown",
      reason: "Undecodable base64-encoded command detected",
      targets: [],
    };
  }

  return null;
}

/**
 * Analyzes a shell command for risky operations, in five stages:
 *   1. Base64-encoded payload detection
 *   2. Command substitution ($(...) / backtick) -- recursive analysis
 *   3. Pipe / chain analysis -- each sub-command checked independently
 *   4. Direct pattern check against RISKY_PATTERNS
 *   5. Protected-path targeting check (independent of pattern match)
 */
export function analyzeCommandRisk(command: string): RiskAnalysis {
  const trimmed = command.trim();

  // Stage 1: base64-encoded command detection (before direct pattern match)
  const base64Result = detectBase64EncodedCommands(trimmed);
  if (base64Result) {
    return base64Result;
  }

  // Stage 2: recursively analyze commands inside command substitutions
  // (done before direct pattern match so the reason message is accurate)
  const substitutions = extractCommandSubstitutions(trimmed);
  for (const sub of substitutions) {
    const result = analyzeCommandRisk(sub);
    if (result.isRisky) {
      return {
        ...result,
        reason: `${result.reason} (detected inside command substitution)`,
      };
    }
  }

  // Stage 3: pipe/chain analysis -- surfaces commands hidden after an operator
  const subCommands = splitCommandChain(trimmed);
  if (subCommands.length > 1) {
    for (const subCmd of subCommands) {
      for (const { pattern, category, reason } of RISKY_PATTERNS) {
        if (pattern.test(subCmd.trim())) {
          const targets = extractTargets(subCmd.trim());
          return {
            isRisky: true,
            category,
            reason: `${reason} (detected inside pipe/chain)`,
            targets,
          };
        }
      }
    }
  }

  // Stage 4: direct single-command check
  for (const { pattern, category, reason } of RISKY_PATTERNS) {
    if (pattern.test(trimmed)) {
      const targets = extractTargets(trimmed);
      const protectedHit = isTargetingProtectedPath(targets);
      return {
        isRisky: true,
        category,
        reason: protectedHit ? `${reason} (targets a protected system directory)` : reason,
        targets,
      };
    }
  }

  // Stage 5: protected-path targeting -- even if no pattern matched
  const targets = extractTargets(trimmed);
  if (isTargetingProtectedPath(targets)) {
    return {
      isRisky: true,
      category: "file_modify",
      reason: "Targets a protected system directory",
      targets,
    };
  }

  return { isRisky: false, category: "unknown", reason: "", targets: [] };
}

/**
 * Best-effort extraction of file/path targets from a command string.
 * Returns tokens that look like file arguments (not flags).
 *
 * Note: any token containing "." is treated as a target -- see the paper's
 * Section VI-C for the false-positive this causes on ordinary tokens like
 * `node.js` or version strings.
 */
function extractTargets(command: string): string[] {
  const tokens = command.split(/\s+/);
  const targets: string[] = [];
  for (const token of tokens) {
    // Skip flags and operators
    if (token.startsWith("-") || ["&&", "||", "|", ";", ">", "<", ">>"].includes(token)) {
      continue;
    }
    // Look for path-like tokens (contains / \ or .)
    if (token.includes("/") || token.includes("\\") || token.includes(".")) {
      targets.push(token);
    }
  }
  return targets;
}

// --- Security Orchestrator ----------------------------------------------------

/** Default timeout for awaiting human approval (milliseconds) */
const DEFAULT_APPROVAL_TIMEOUT_MS = 120_000; // 2 minutes

/**
 * Singleton orchestrator that manages the lifecycle of risky-command approvals.
 *
 * Usage flow:
 *   1. A gate (SecurityInterceptor.ts or tool-gate.ts) detects a risky call and
 *      calls `requestApproval()`.
 *   2. The orchestrator creates a PendingAction and emits `"approval-requested"`.
 *   3. An external notifier (not included in this artifact) listens for the event
 *      and surfaces it to a human operator.
 *   4. The operator approves or denies -> caller invokes
 *      `resolveApproval(actionId, approved)`.
 *   5. The `await requestApproval()` promise resolves; the gate continues or denies.
 *   6. An external audit logger (not included in this artifact) records the decision.
 */
class SecurityOrchestrator extends EventEmitter {
  private pendingActions: Map<string, PendingAction> = new Map();
  private approvalTimeoutMs: number = DEFAULT_APPROVAL_TIMEOUT_MS;

  // -- Singleton --
  private static _instance: SecurityOrchestrator | null = null;
  static getInstance(): SecurityOrchestrator {
    if (!SecurityOrchestrator._instance) {
      SecurityOrchestrator._instance = new SecurityOrchestrator();
    }
    return SecurityOrchestrator._instance;
  }

  /** Override default timeout (useful for tests or config) */
  setApprovalTimeout(ms: number): void {
    this.approvalTimeoutMs = ms;
  }

  /**
   * Called by a gate when a risky command is detected.
   * Returns a Promise that resolves only when a human approves or denies (or the
   * timeout fires).
   *
   * This is the function that pauses the agent loop:
   *   - Node.js `await` suspends the async function
   *   - the event loop continues processing other work
   *   - when `resolveApproval()` is called, the awaited promise resolves
   *   - the caller resumes with the decision
   */
  async requestApproval(params: {
    command: string;
    workdir: string;
    riskAnalysis: RiskAnalysis;
  }): Promise<SecurityDecision> {
    const actionId = randomUUID();

    return new Promise<SecurityDecision>((resolve) => {
      // Set up auto-deny timeout
      const timeoutHandle = setTimeout(() => {
        const action = this.pendingActions.get(actionId);
        if (action && action.state === "waiting_approval") {
          action.state = "timed_out";
          const decision: SecurityDecision = {
            actionId,
            approved: false,
            decidedBy: "timeout",
            decidedAt: new Date(),
            reason: `Auto-denied: no response within ${this.approvalTimeoutMs / 1000}s`,
          };
          this.pendingActions.delete(actionId);
          this.emit("approval-timeout", actionId);
          this.emit("approval-resolved", decision);
          resolve(decision);
        }
      }, this.approvalTimeoutMs);

      const action: PendingAction = {
        actionId,
        command: params.command,
        workdir: params.workdir,
        riskCategory: params.riskAnalysis.category,
        riskReason: params.riskAnalysis.reason,
        detectedAt: new Date(),
        state: "waiting_approval",
        resolve,
        timeoutHandle,
      };

      this.pendingActions.set(actionId, action);

      // Emit event for an external notifier / audit logger to pick up
      const publicAction: Omit<PendingAction, "resolve" | "timeoutHandle"> = {
        actionId: action.actionId,
        command: action.command,
        workdir: action.workdir,
        riskCategory: action.riskCategory,
        riskReason: action.riskReason,
        detectedAt: action.detectedAt,
        state: action.state,
      };
      this.emit("approval-requested", publicAction);

      // Console fallback for local testing / no external notifier configured
      console.log(`\n${"=".repeat(60)}`);
      console.log("SECURITY WARNING -- RISKY COMMAND DETECTED");
      console.log("=".repeat(60));
      console.log(`Command   : ${params.command}`);
      console.log(`Directory : ${params.workdir}`);
      console.log(`Category  : ${params.riskAnalysis.category}`);
      console.log(`Reason    : ${params.riskAnalysis.reason}`);
      console.log(`Action ID : ${actionId}`);
      console.log(`Timeout   : ${this.approvalTimeoutMs / 1000}s`);
      console.log("=".repeat(60));
      console.log("Waiting for approval via an external notifier...");
      console.log(
        "(Or, for testing: call SecurityOrchestrator.getInstance().resolveApproval(...))\n",
      );
    });
  }

  /**
   * Called by an external notifier (or test harness) to approve/deny a pending
   * action, e.g.:
   *   const orchestrator = SecurityOrchestrator.getInstance();
   *   orchestrator.resolveApproval(actionId, true, "operator:some-id");
   */
  resolveApproval(
    actionId: string,
    approved: boolean,
    decidedBy: string = "unknown",
    reason?: string,
  ): boolean {
    const action = this.pendingActions.get(actionId);
    if (!action || action.state !== "waiting_approval") {
      return false; // Action not found or already resolved
    }

    // Clear the timeout
    if (action.timeoutHandle) {
      clearTimeout(action.timeoutHandle);
    }

    // Update state
    action.state = approved ? "approved" : "denied";

    const decision: SecurityDecision = {
      actionId,
      approved,
      decidedBy,
      decidedAt: new Date(),
      reason,
    };

    // Clean up
    this.pendingActions.delete(actionId);

    // Emit for audit logging
    this.emit("approval-resolved", decision);

    // This resolves the promise the gate is awaiting -- how the agent "resumes".
    action.resolve(decision);

    return true;
  }

  /** List all currently pending actions (for a notifier to display) */
  getPendingActions(): Array<Omit<PendingAction, "resolve" | "timeoutHandle">> {
    return Array.from(this.pendingActions.values()).map((action) => ({
      actionId: action.actionId,
      command: action.command,
      workdir: action.workdir,
      riskCategory: action.riskCategory,
      riskReason: action.riskReason,
      detectedAt: action.detectedAt,
      state: action.state,
    }));
  }

  /** Get a specific pending action's state */
  getActionState(actionId: string): SecurityState {
    const action = this.pendingActions.get(actionId);
    return action?.state ?? "idle";
  }

  /** How many actions are currently awaiting approval */
  get pendingCount(): number {
    return this.pendingActions.size;
  }

  /** Reset for testing */
  _resetForTesting(): void {
    for (const action of this.pendingActions.values()) {
      if (action.timeoutHandle) {
        clearTimeout(action.timeoutHandle);
      }
    }
    this.pendingActions.clear();
    this.removeAllListeners();
  }
}

// --- Exports -------------------------------------------------------------------

/** Get the singleton security orchestrator */
export function getSecurityOrchestrator(): SecurityOrchestrator {
  return SecurityOrchestrator.getInstance();
}

export { SecurityOrchestrator };
