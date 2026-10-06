import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Every test in this package is pure - no chain, no clock, no network. A test that
    // needs any of those belongs in the Foundry suite, which already exercises the real
    // contracts. Keeping this package pure is what makes it cheap enough to run on every
    // save.
    include: ["test/**/*.test.ts"],
    environment: "node",
  },
});
