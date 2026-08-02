import { beforeEach, describe, expect, it } from "vitest";
import { getSecurityOrchestrator } from "./security-hitl.js";
import { extractRiskSurface, gateToolCall, isSideEffectingTool } from "./tool-gate.js";

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
