import { logWarn, logInfo } from "../logger.js";

/**
 * SecurityInterceptor: intercepts system commands on the shell-execution path and
 * blocks on an external approval decision before allowing the call to proceed.
 *
 * This is the retrofit described in the paper's Section V-A: it is wired into a single
 * execution path (system.run) rather than the tool-invocation boundary every core tool
 * passes through. See tool-gate.ts for the relocated version.
 */
export class SecurityInterceptor {
  private static readonly API_URL = "http://127.0.0.1:8081/validate";
  private static readonly TIMEOUT_MS = 45000; // 45s approval wait

  /**
   * Intercepts a command and blocks the calling flow until the external API responds
   * (or times out). Fail-closed: any failure to reach a definitive APPROVED denies.
   */
  static async interceptCommand(payload: {
    runId: string;
    cmdText: string;
    argv: string[];
    cwd?: string;
    env?: Record<string, string>;
  }): Promise<{ approved: boolean; reason?: string }> {
    try {
      logInfo(`[SecurityInterceptor] Command captured: ${payload.cmdText} (RunID: ${payload.runId})`);
      logInfo(`[SecurityInterceptor] Waiting for approval (${this.TIMEOUT_MS / 1000}s)...`);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

      const response = await fetch(this.API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const data = (await response.json()) as { status: string; reason?: string };
        if (data.status === "APPROVED") {
          logInfo(`[SecurityInterceptor] Command APPROVED.`);
          return { approved: true };
        }
      }

      const reason = "External security policy decision or invalid response.";
      logWarn(`[SecurityInterceptor] Command DENIED. Reason: ${reason}`);
      return { approved: false, reason };
    } catch (error: any) {
      // Fail-closed: a transport failure or timeout denies rather than allows.
      let errorMessage = "Security layer unreachable.";

      if (error.name === "AbortError") {
        errorMessage = "Approval timed out (45s).";
      } else {
        errorMessage = error.message;
      }

      logWarn(`[SecurityInterceptor] Critical error: ${errorMessage}`);
      return {
        approved: false,
        reason: `Execution blocked due to security-layer error: ${errorMessage}`,
      };
    }
  }
}
