/** Minimal artifact-local logging shim used by the benchmark interceptor. */
export function logInfo(message: string): void {
  console.info(message);
}

export function logWarn(message: string): void {
  console.warn(message);
}
