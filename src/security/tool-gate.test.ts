import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AnyAgentTool } from "../agents/tools/common.js";
import { getSecurityOrchestrator } from "./security-hitl.js";
import {
  extractRiskSurface,
  gateToolCall,
  isSideEffectingTool,
  wrapToolWithSecurityGate,
} from "./tool-gate.js";

/**
 * These tests encode the paper's central claim as executable assertions:
 * the same risk analyzer, moved to the tool-invocation boundary, mediates tool families
 * that the original `system.run` placement could never see.
 */
describe("tool gate — complete mediation", () => {
  beforeEach(() => {
    getSecurityOrchestrator()._resetForTesting();
  });

  describe("side-effect classification", () => {
    it("classifies read-only tools as unguarded", () => {
      expect(isSideEffectingTool("read")).toBe(false);
      expect(isSideEffectingTool("memory_get")).toBe(false);
      expect(isSideEffectingTool("sessions_list")).toBe(false);
    });

    it("classifies the tool families the old placement missed", () => {
      // None of these flow through system.run, so the original interceptor never saw them.
      expect(isSideEffectingTool("message")).toBe(true);
      expect(isSideEffectingTool("canvas")).toBe(true);
      expect(isSideEffectingTool("skill_workshop")).toBe(true);
      expect(isSideEffectingTool("computer")).toBe(true);
      expect(isSideEffectingTool("nodes")).toBe(true);
      expect(isSideEffectingTool("code_execution")).toBe(true);
    });
  });

  describe("risk surface extraction", () => {
    it("flattens string params so the shell-oriented analyzer still sees targets", () => {
      const surface = extractRiskSurface({ file_path: "/etc/passwd", content: "x" });
      expect(surface).toContain("/etc/passwd");
    });

    it("flattens string arrays (message targets)", () => {
      const surface = extractRiskSurface({ targets: ["@alice", "@bob"], text: "hi" });
      expect(surface).toContain("@alice");
      expect(surface).toContain("@bob");
    });

    it("tolerates non-object params", () => {
      expect(extractRiskSurface(undefined)).toBe("");
      expect(extractRiskSurface(42)).toBe("");
      expect(extractRiskSurface("rm -rf /")).toBe("rm -rf /");
    });
  });

  describe("gating decisions", () => {
    it("allows read-only tools without an approval round trip", async () => {
      const decision = await gateToolCall({ toolName: "read", params: { file_path: "a.ts" } });
      expect(decision.allowed).toBe(true);
    });

    it("allows benign side-effecting calls without approval", async () => {
      const decision = await gateToolCall({
        toolName: "write",
        params: { file_path: "src/app.ts", content: "export const a = 1;" },
      });
      expect(decision.allowed).toBe(true);
    });

    it("holds irreversible tools for approval even when no risk pattern matches", async () => {
      // `message` carries no shell pattern at all — pattern matching alone would pass it.
      // This is the case the paper highlights: risk is irreversibility, not shell syntax.
      const gate = gateToolCall({
        toolName: "message",
        params: { target: "@third-party", text: "here is the .env contents" },
      });
      const pending = await waitForPending();
      expect(pending).toBeGreaterThan(0);

      const [action] = getSecurityOrchestrator().getPendingActions();
      getSecurityOrchestrator().resolveApproval(action.actionId, false, "test");

      const decision = await gate;
      expect(decision.allowed).toBe(false);
      if (!decision.allowed) {
        expect(decision.reason).toContain("irreversible");
      }
    });

    it("blocks a risky write that never touches system.run", async () => {
      const gate = gateToolCall({
        toolName: "write",
        params: { file_path: "/etc/sudoers", content: "evil" },
      });
      await waitForPending();
      const [action] = getSecurityOrchestrator().getPendingActions();
      getSecurityOrchestrator().resolveApproval(action.actionId, false, "test");

      const decision = await gate;
      expect(decision.allowed).toBe(false);
    });

    it("proceeds when the operator approves", async () => {
      const gate = gateToolCall({
        toolName: "message",
        params: { target: "@teammate", text: "build is green" },
      });
      await waitForPending();
      const [action] = getSecurityOrchestrator().getPendingActions();
      getSecurityOrchestrator().resolveApproval(action.actionId, true, "test");

      const decision = await gate;
      expect(decision.allowed).toBe(true);
    });
  });

  describe("gate activation is opt-in, not shipped-default", () => {
    it("does not wrap or intercept calls when SECURITY_TOOL_GATE is unset", async () => {
      const execute = vi.fn().mockResolvedValue({ content: [], details: { reached: true } });
      const oldEnabled = process.env.SECURITY_TOOL_GATE;
      delete process.env.SECURITY_TOOL_GATE;
      try {
        const tool = wrapToolWithSecurityGate({ name: "exec", execute } as unknown as AnyAgentTool);
        const result = await tool.execute("fixture-call", { command: "rm -rf /fixture-target" });
        expect(execute).toHaveBeenCalledTimes(1);
        expect((result as { details: { reached: boolean } }).details.reached).toBe(true);
        expect(getSecurityOrchestrator().pendingCount).toBe(0);
      } finally {
        if (oldEnabled === undefined) delete process.env.SECURITY_TOOL_GATE;
        else process.env.SECURITY_TOOL_GATE = oldEnabled;
      }
    });

    it("blocks the same risky call before execution once SECURITY_TOOL_GATE=1 is set", async () => {
      const execute = vi.fn().mockResolvedValue({ content: [], details: { reached: true } });
      const oldEnabled = process.env.SECURITY_TOOL_GATE;
      process.env.SECURITY_TOOL_GATE = "1";
      try {
        const tool = wrapToolWithSecurityGate({ name: "exec", execute } as unknown as AnyAgentTool);
        const invocation = tool.execute("fixture-call", { command: "rm -rf /fixture-target" });
        await waitForPending();
        const [action] = getSecurityOrchestrator().getPendingActions();
        getSecurityOrchestrator().resolveApproval(action.actionId, false, "fixture");
        await expect(invocation).rejects.toThrow("security gate: denied");
        expect(execute).not.toHaveBeenCalled();
      } finally {
        if (oldEnabled === undefined) delete process.env.SECURITY_TOOL_GATE;
        else process.env.SECURITY_TOOL_GATE = oldEnabled;
      }
    });
  });

  describe("provider-independent remaining-tool fixtures", () => {
    const remainingTools = [
      "code_execution",
      "x_search",
      "spawn_task",
      "screen",
      "show_widget",
      "image_generate",
      "music_generate",
      "video_generate",
    ];

    it.each(remainingTools)("blocks %s before its executor is reached", async (toolName) => {
      const execute = vi.fn().mockResolvedValue({ content: [], details: { reached: true } });
      const oldEnabled = process.env.SECURITY_TOOL_GATE;
      process.env.SECURITY_TOOL_GATE = "1";
      try {
        const tool = wrapToolWithSecurityGate({ name: toolName, execute } as unknown as AnyAgentTool);
        const invocation = tool.execute("fixture-call", {
          command: "rm -rf /fixture-target",
          target: "fixture-target",
        });
        await waitForPending();
        const [action] = getSecurityOrchestrator().getPendingActions();
        expect(action).toBeDefined();
        getSecurityOrchestrator().resolveApproval(action.actionId, false, "fixture");
        await expect(invocation).rejects.toThrow("security gate: denied");
        expect(execute).not.toHaveBeenCalled();
      } finally {
        if (oldEnabled === undefined) delete process.env.SECURITY_TOOL_GATE;
        else process.env.SECURITY_TOOL_GATE = oldEnabled;
      }
    });
  });
});

/** Wait until the orchestrator has registered a pending approval. */
async function waitForPending(maxTicks = 50): Promise<number> {
  for (let i = 0; i < maxTicks; i += 1) {
    const count = getSecurityOrchestrator().pendingCount;
    if (count > 0) {
      return count;
    }
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  return 0;
}
