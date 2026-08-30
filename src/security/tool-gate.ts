/**
 * Universal tool gate — complete-mediation enforcement at the tool-invocation boundary.
 *
 * Motivation: the original interceptor (SecurityInterceptor.ts) was wired into a single
 * execution path (`system.run`), which left every other side-effecting tool ungated.
 * Measured mediation completeness of that placement was MC = 2/17 on OpenClaw's own
 * tool surface (paper Section V-A) -- unchanged from baseline, since the shell-
 * execution tool was already mediated by OpenClaw's own, independent exec-
 * approval mechanism. This module moves the same risk analysis to the boundary that
 * *every* tool already passes through (see `wrapToolWithBeforeToolCallHook` in
 * `src/agents/pi-tools.ts`), so a newly added tool is gated by construction rather than
 * by remembering to wire it. With SECURITY_TOOL_GATE=1, this relocation provides configured
 * boundary coverage of 17/17 on the same tool surface (paper Section V-B); the shipped
 * default leaves the opt-in wrapper disabled.
 *
 * Differs from the plugin `before_tool_call` hook in one decisive respect: that hook is
 * fail-open (a throwing hook lets the call through). A security gate must be fail-closed.
 */

import type { AnyAgentTool } from "../agents/tools/common.js";
import { analyzeCommandRisk, getSecurityOrchestrator, type RiskAnalysis } from "./security-hitl.js";

/** Tools that change state outside the agent's own session. Derived from the D3 inventory. */
const SIDE_EFFECTING_TOOLS = new Set<string>([
  // filesystem
  "write",
  "edit",
  "apply_patch",
  // execution
  "exec",
  "process",
  "code_execution",
  "terminal",
  // network egress
  "web_fetch",
  "web_search",
  "x_search",
  // agent orchestration
  "sessions_send",
  "sessions_spawn",
  "subagents",
  "spawn_task",
  // external conversations / messaging
  "message",
  "conversations_list",
  "conversations_send",
  "conversations_turn",
  // UI / device control
  "browser",
  "canvas",
  "screen",
  "show_widget",
  "nodes",
  "computer",
  "mobile_ui",
  // control plane + persistence
  "gateway",
  "cron",
  "automations",
  "skill_workshop",
  // media generation (external API + file write)
  "image_generate",
  "music_generate",
  "video_generate",
  "tts",
]);

/**
 * Side-effecting tools whose effect cannot be undone once it leaves the host.
 * These require approval regardless of what the risk analyzer reports, because
 * pattern matching cannot recognize "this message reaches a third party".
 */
const IRREVERSIBLE_TOOLS = new Set<string>([
  "message",
  "conversations_send",
  "conversations_turn",
  "gateway",
  "nodes",
  "computer",
  "mobile_ui",
  "skill_workshop",
  "cron",
  "automations",
]);

export type ToolGateDecision =
  | { allowed: true }
  | { allowed: false; reason: string };

export function isSideEffectingTool(toolName: string): boolean {
  return SIDE_EFFECTING_TOOLS.has(toolName);
}

/**
 * Flatten tool parameters into a single string for risk analysis.
 *
 * The existing analyzer is written for shell command text. For non-shell tools we
 * concatenate string-valued parameters so that the same pattern set still sees paths and
 * targets. This is deliberately a coarse adapter: its limits are part of what the
 * evaluation measures (see the evasion results in the paper).
 */
export function extractRiskSurface(params: unknown): string {
  if (typeof params === "string") {
    return params;
  }
  if (!params || typeof params !== "object") {
    return "";
  }
  const parts: string[] = [];
  for (const value of Object.values(params as Record<string, unknown>)) {
    if (typeof value === "string") {
      parts.push(value);
    } else if (Array.isArray(value)) {
      parts.push(...value.filter((v): v is string => typeof v === "string"));
    }
  }
  return parts.join(" ");
}

/**
 * Gate a single tool invocation. Fail-closed: any unexpected failure denies the call.
 */
export async function gateToolCall(args: {
  toolName: string;
  params: unknown;
  workdir?: string;
}): Promise<ToolGateDecision> {
  const { toolName, params, workdir } = args;

  try {
    if (!isSideEffectingTool(toolName)) {
      return { allowed: true };
    }

    const surface = extractRiskSurface(params);
    const analysis: RiskAnalysis = analyzeCommandRisk(surface);
    const irreversible = IRREVERSIBLE_TOOLS.has(toolName);

    if (!analysis.isRisky && !irreversible) {
      return { allowed: true };
    }

    const reasonPrefix = irreversible && !analysis.isRisky ? "irreversible action" : analysis.reason;

    const decision = await getSecurityOrchestrator().requestApproval({
      command: `${toolName}: ${surface}`.trim(),
      workdir: workdir ?? process.cwd(),
      riskAnalysis: {
        ...analysis,
        isRisky: true,
        reason: reasonPrefix,
      },
    });

    if (decision.approved) {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: `security gate: denied by ${decision.decidedBy} (${reasonPrefix})`,
    };
  } catch (err) {
    // Fail-closed. A gate that cannot decide must not permit.
    return {
      allowed: false,
      reason: `security gate: fail-closed (${String(err)})`,
    };
  }
}

/**
 * Wrap a tool so that every invocation passes the gate before executing.
 *
 * Applied to the same tool list as `wrapToolWithBeforeToolCallHook`, which is the single
 * point every core tool already flows through. This is the placement change that raises
 * mediation completeness from 1/31 to the full side-effecting set.
 */
export function isToolGateEnabled(): boolean {
  return process.env.SECURITY_TOOL_GATE === "1";
}

export function wrapToolWithSecurityGate(tool: AnyAgentTool): AnyAgentTool {
  const execute = tool.execute;
  if (!execute || !isToolGateEnabled()) {
    return tool;
  }
  const toolName = tool.name || "tool";
  return {
    ...tool,
    execute: async (toolCallId, params, signal, onUpdate) => {
      const decision = await gateToolCall({ toolName, params });
      if (!decision.allowed) {
        throw new Error(decision.reason);
      }
      return await execute(toolCallId, params, signal, onUpdate);
    },
  };
}
