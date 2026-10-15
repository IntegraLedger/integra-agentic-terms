import { defineConfig } from "vitest/config";

// No test asserts a time the machine takes: the waits a test asserts run on vitest's fake clock. A timeout only stops a
// test that hangs, so it is wide enough that no test fails because the machine running it is busy.
export default defineConfig({ test: { testTimeout: 120_000, hookTimeout: 120_000 } });
