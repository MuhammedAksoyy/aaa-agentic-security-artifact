import { defineConfig } from "vitest/config";

/** Keep the standalone artifact independent of the host project's test filters. */
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
  },
});
