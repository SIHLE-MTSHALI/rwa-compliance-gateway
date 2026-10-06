// Locate the `forge` binary.
//
// ## Why this is a module
//
// Both the mutation harness and the CCID vector generator shell out to `forge`. Each
// originally hardcoded a Windows path, `$USERPROFILE/.foundry/bin/forge.exe`, which
// resolves to nothing on the Linux CI runner - and because that is a *different machine*,
// every local run passed. The failure only appeared once the code reached CI, which is the
// worst place to discover it: two green local suites, a red pipeline.
//
// So the lookup is platform-aware, and it **fails loudly with a list of where it looked**
// instead of falling through to an opaque spawn error.
//
// ## Why `PATH` is checked last
//
// A bare `forge` on `PATH` can be a different Foundry version from the pinned toolchain,
// and a harness that mutates contracts with an unexpected compiler produces results nobody
// can reproduce. Prefer the explicit install directory.

import { statSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const IS_WINDOWS = process.platform === "win32";

function isExecutableFile(p) {
  try {
    // `existsSync` accepts a directory, and a `~/.foundry/bin` entry is legitimately on the
    // candidate list for `PATH` resolution - so the type has to be checked, or the
    // directory gets selected and then fails to spawn with a message that hides the cause.
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function candidates() {
  const list = [];
  if (process.env.FORGE_BIN) list.push(process.env.FORGE_BIN);

  // Foundry's own install directory, if the caller set it explicitly.
  if (process.env.FOUNDRY_DIR) {
    list.push(join(process.env.FOUNDRY_DIR, "bin", IS_WINDOWS ? "forge.exe" : "forge"));
  }

  // The default: `%USERPROFILE%\.foundry` on Windows, `$HOME/.foundry` elsewhere.
  const home = IS_WINDOWS ? process.env.USERPROFILE : process.env.HOME;
  if (home) list.push(join(home, ".foundry", "bin", IS_WINDOWS ? "forge.exe" : "forge"));

  // Where foundry-toolchain installs on the Linux CI runner.
  if (!IS_WINDOWS) {
    list.push("/usr/local/bin/forge", "/usr/bin/forge", "/home/runner/.foundry/bin/forge");
  }

  return list;
}

/**
 * Resolve a runnable `forge` path, or explain why it cannot.
 *
 * @param {string} caller - Included in the error so the message names the failing script.
 * @returns {string} A path to a `forge` executable.
 */
export function resolveForge(caller) {
  for (const candidate of candidates()) {
    if (isExecutableFile(candidate)) return candidate;
  }

  // Last resort: resolve through the shell's own search path.
  const lookup = spawnSync(IS_WINDOWS ? "where" : "which", ["forge"], { encoding: "utf8" });
  const resolved = (lookup.stdout ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.length > 0);
  if (resolved !== undefined && isExecutableFile(resolved)) return resolved;

  throw new Error(
    `${caller}: could not find a forge binary.\n` +
      `Looked in:\n${candidates().map((c) => `  ${c}`).join("\n")}\n` +
      `  <PATH>\n\n` +
      `Install Foundry (https://book.getfoundry.sh/getting-started/installation) or set\n` +
      `FORGE_BIN to an explicit path.\n\n` +
      `If this worked locally and fails here, the cause is almost always a hardcoded\n` +
      `platform-specific path: CI runs a different OS from your machine, so a path that\n` +
      `resolved at your desk resolves to nothing on the runner.`,
  );
}
