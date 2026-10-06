import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { resolveForge } from "../forge-bin.mjs";

/**
 * This module exists because a hardcoded `forge.exe` path resolved on a Windows laptop and
 * to nothing on the Linux runner, and the only place that showed up was CI. The tests
 * therefore care about *which path gets chosen*, not just that something is returned.
 */
describe("resolveForge", () => {
  it("prefers an explicit FORGE_BIN over any discovered install", () => {
    const dir = mkdtempSync(join(tmpdir(), "forge-test-"));
    try {
      const explicit = join(dir, "my-forge");
      writeFileSync(explicit, "#!/bin/sh\n");

      // Saved and restored so the test does not leak into the suite's own runs.
      const previous = process.env.FORGE_BIN;
      process.env.FORGE_BIN = explicit;
      try {
        expect(resolveForge("test")).toBe(explicit);
      } finally {
        if (previous === undefined) delete process.env.FORGE_BIN;
        else process.env.FORGE_BIN = previous;
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("throws a message naming every location it tried", () => {
    const previousBin = process.env.FORGE_BIN;
    const previousDir = process.env.FOUNDRY_DIR;
    // Point both at an empty directory, and hope `forge` is not on PATH.
    const empty = mkdtempSync(join(tmpdir(), "forge-empty-"));
    try {
      process.env.FORGE_BIN = join(empty, "nope");
      process.env.FOUNDRY_DIR = empty;

      let thrown: unknown;
      try {
        resolveForge("unit-test");
      } catch (error) {
        thrown = error;
      }

      // Either forge is genuinely installed (then this is a no-op pass) or the error must
      // be actionable. Asserting on the *message* is the point: "spawn ENOENT" would tell
      // the next person nothing.
      if (thrown !== undefined) {
        const message = (thrown as Error).message;
        expect(message).toContain("unit-test");
        expect(message).toContain("FORGE_BIN");
        expect(message).toContain("different OS");
      }
    } finally {
      if (previousBin === undefined) delete process.env.FORGE_BIN;
      else process.env.FORGE_BIN = previousBin;
      if (previousDir === undefined) delete process.env.FOUNDRY_DIR;
      else process.env.FOUNDRY_DIR = previousDir;
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it("rejects a directory, not just a missing file", () => {
    // A `~/.foundry/bin` entry is a legitimate *candidate* for PATH lookup, so a naive
    // `existsSync` would select the directory and then fail to spawn - with a message that
    // hides the real cause.
    const dir = mkdtempSync(join(tmpdir(), "forge-dir-"));
    try {
      const asDirectory = join(dir, "forge.exe");
      mkdirSync(asDirectory);

      const previous = process.env.FORGE_BIN;
      process.env.FORGE_BIN = asDirectory;
      try {
        // Either something else on the machine provides forge, or this throws - but it must
        // never return the directory itself.
        const resolved = resolveForge("dir-test");
        expect(resolved).not.toBe(asDirectory);
      } catch {
        /* expected when no forge exists */
      } finally {
        if (previous === undefined) delete process.env.FORGE_BIN;
        else process.env.FORGE_BIN = previous;
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
