// Mutation harness: proves the test suite is not vacuous.
//
// Each mutation introduces one real defect, the suite is expected to FAIL, and the
// source is restored. A mutation that still passes is a hole in the suite.
//
// Run from the repository root:  node scripts/mutation-check.mjs
//
// ## Why the full suite, not just the invariant tests
//
// Each mutation declares the scope it needs. That is not a convenience: several
// properties here are genuinely unobservable from one chain. `setStatus` stopping to
// bump the nonce, for instance, leaves the source chain completely correct - the
// credential *is* `Revoked` there. The damage only appears on a destination, which
// discards the message as stale. No single-chain invariant can see it, and an earlier
// version of this harness reported that mutation as surviving for exactly that reason.

import { readFileSync, writeFileSync, copyFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolveForge } from "./forge-bin.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
// Platform-aware, and fails loudly with a list of where it looked. This previously pointed
// at a Windows path, which resolved fine locally and to nothing on the CI runner.
const forge = resolveForge("mutation-check");

/** All mutations, applied one at a time, each reverted before the next. */
const mutations = [
  {
    id: "M1-pending-allows",
    why: "`Pending` reported as an allow",
    scope: "full",
    edits: [
      {
        file: "contracts/src/PoolComplianceModule.sol",
        from: "if (status == ComplianceTypes.CredentialStatus.Pending) return ComplianceTypes.REASON_PENDING;",
        to: "if (status == ComplianceTypes.CredentialStatus.Pending) return ComplianceTypes.REASON_OK;",
      },
    ],
  },
  {
    id: "M1b-pending-allows-no-provider-backstop",
    why: "`Pending` allowed AND no provider backstop - both defences removed at once",
    scope: "full",
    note:
      "M1 is caught only because PolicyEvaluation.t.sol asserts the provider backstop " +
      "explicitly rather than leaving it to chance. M1b removes both, which is the " +
      "realistic version of the failure.",
    edits: [
      {
        file: "contracts/src/PoolComplianceModule.sol",
        from: "if (status == ComplianceTypes.CredentialStatus.Pending) return ComplianceTypes.REASON_PENDING;",
        to: "if (status == ComplianceTypes.CredentialStatus.Pending) return ComplianceTypes.REASON_OK;",
      },
      {
        file: "contracts/src/ProviderRegistry.sol",
        from: "return p.status == uint8(ProviderStatus.Active) || p.status == uint8(ProviderStatus.Deprecated);",
        to: "return p.registered; // mutation: any registered provider is trusted",
      },
    ],
  },
  {
    id: "M2-revoked-resurrects",
    why: "`Revoked` is no longer terminal - a revoked credential can return to `Valid`",
    scope: "full",
    edits: [
      {
        file: "contracts/src/ComplianceRegistry.sol",
        from: "if (from == ComplianceTypes.CredentialStatus.Revoked) return false;",
        to: "if (from == ComplianceTypes.CredentialStatus.Revoked) return to == ComplianceTypes.CredentialStatus.Valid;",
      },
    ],
  },
  {
    id: "M3-stale-nonce-renewal",
    why: "renewal accepts a nonce that does not increase - the replay guard is gone",
    scope: "full",
    edits: [
      {
        file: "contracts/src/ComplianceRegistry.sol",
        from: "if (newNonce <= r.nonce) revert NonceNotIncreasing(ccid, r.nonce, newNonce);",
        to: "// mutation: renewal nonce monotonicity removed",
      },
    ],
  },
  {
    id: "M4-policy-version-overwritable",
    why: "a policy version can be overwritten in place - an integrator's pinned version becomes meaningless",
    scope: "full",
    edits: [
      {
        file: "contracts/src/PoolPolicyManager.sol",
        from: "uint32 version = latestVersion[poolId] + 1;",
        to: "uint32 version = 1; // mutation: every registration overwrites version 1",
      },
    ],
  },
  {
    id: "M5-untrusted-provider-allows",
    why: "a revoked provider's existing credentials still pass policy",
    scope: "full",
    edits: [
      {
        file: "contracts/src/ProviderRegistry.sol",
        from: "return p.status == uint8(ProviderStatus.Active) || p.status == uint8(ProviderStatus.Deprecated);",
        to: "return true; // mutation: every provider is trusted",
      },
    ],
  },
  {
    id: "M6-status-change-does-not-bump-nonce",
    why: "`setStatus` stops bumping the nonce, so every destination discards a revocation as stale",
    scope: "full",
    note: "Undetectable on one chain - needs the propagation suite.",
    edits: [
      {
        file: "contracts/src/ComplianceRegistry.sol",
        from: "r.nonce += 1;",
        to: "// mutation: nonce not advanced on a status change",
      },
    ],
  },
  {
    id: "M7-replica-overwrites-local-authority",
    why: "a remote replica may overwrite a credential this chain is the issuer for",
    scope: "full",
    edits: [
      {
        file: "contracts/src/CrossChainComplianceReceiver.sol",
        from: "if (REGISTRY.exists(m.ccid) && !REGISTRY.getPropagationState(m.ccid).isReplica) {",
        to: "if (false) {",
      },
    ],
  },
  {
    id: "M8-binding-hash-unverified",
    why: "a payload edited after the sender signed it is accepted",
    scope: "full",
    edits: [
      {
        file: "contracts/src/CrossChainComplianceReceiver.sol",
        from: "if (recomputed != m.bindingHash) {",
        to: "if (false) {",
      },
    ],
  },
  {
    id: "M9-deprecated-provider-invalidates",
    why: "a deprecated provider invalidates credentials it already signed",
    scope: "full",
    note: "The opposite error to M5, and the one the docs warn about most.",
    edits: [
      {
        file: "contracts/src/ProviderRegistry.sol",
        from: "return p.status == uint8(ProviderStatus.Active) || p.status == uint8(ProviderStatus.Deprecated);",
        to: "return p.status == uint8(ProviderStatus.Active); // mutation: deprecation is treated as distrust",
      },
    ],
  },
  {
    id: "M10-allocation-cap-ignores-current-holding",
    why: "the per-investor cap is checked against the increment instead of the total",
    scope: "full",
    note: "Lets a holder already at the cap add another full cap's worth.",
    edits: [
      {
        file: "contracts/src/PoolComplianceModule.sol",
        from: "uint256 total = request.currentAllocation + request.requestedAmount;",
        to: "uint256 total = request.requestedAmount; // mutation: the existing holding is ignored",
      },
    ],
  },
  {
    id: "M11-activation-delay-removed",
    why: "a policy can be activated immediately, with no notice window",
    scope: "full",
    edits: [
      {
        file: "contracts/src/PoolPolicyManager.sol",
        from:
          "if (uint64(block.timestamp) < activateAfter) " +
          "{ revert ActivationDelayNotElapsed(activateAfter, uint64(block.timestamp)); }",
        to: "// mutation: activation delay removed",
      },
    ],
  },
  {
    id: "M12-unpause-immediately-executable",
    why: "a scheduled unpause can be executed before its delay elapses",
    scope: "full",
    edits: [
      {
        file: "contracts/src/EmergencyControls.sol",
        from: "if (uint64(block.timestamp) < unpauseExecutableAt) {",
        to: "if (false) {",
      },
    ],
  },
  {
    id: "M13-reason-missing-from-all-reasons",
    why: "a reason code has a label but is absent from `allReasons()`, so `describeReason` reports `UNRECOGNIZED` for a live reason",
    scope: "full",
    note:
      "The regression that actually shipped once. `REASON_POOL_NOT_REGISTERED` existed " +
      "as a constant and had a label, but was missing from the array - so `reasonToString` " +
      "walked past it and returned `UNRECOGNIZED` for a denial the gateway really " +
      "returned. The `string[15]` type cannot catch it, because the label array was " +
      "correct; the two lists were simply out of step in the one direction that matters.",
    edits: [
      {
        file: "contracts/src/libraries/ComplianceTypes.sol",
        from: "out[11] = REASON_POOL_NOT_REGISTERED;",
        to: "out[11] = bytes32(uint256(0)); // mutation: a live reason code is absent from allReasons()",
      },
    ],
  },
];

function runForge(args) {
  // No `shell: true`: the forge path and every argument are already safe to pass
  // directly, and going through `cmd.exe` adds both an escaping hazard and an exit-code
  // that does not reliably reflect forge's own.
  const result = spawnSync(forge, args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
  });
  return { code: result.status, out: `${result.stdout ?? ""}${result.stderr ?? ""}` };
}

// ---------------------------------------------------------------------------
// Anchor matching
// ---------------------------------------------------------------------------

/**
 * Collapse every run of whitespace to a single space, recording where each normalised
 * character came from.
 *
 * ## Why
 *
 * `forge fmt` decides where braces go, so an anchor written as a single-line
 * `if (...) { ... }` stops matching the moment the file is reformatted. The failure mode
 * is nasty: the harness exits non-zero with "the source moved", which reads like a broken
 * build rather than a broken anchor, and the obvious response is to delete the mutation.
 * A harness that breaks on formatting gets abandoned.
 *
 * So anchors are matched against a whitespace-collapsed view and the span is mapped back
 * to real indices. The mutation is spliced into the *original* text, so the file's own
 * formatting survives the round trip untouched.
 */
function collapseWhitespace(text) {
  let normalised = "";
  const origins = [];
  let i = 0;

  while (i < text.length) {
    if (/\s/.test(text[i])) {
      while (i < text.length && /\s/.test(text[i])) i += 1;
      // No leading space: a leading whitespace run is indentation, and emitting one
      // would make every anchor need a phantom character before it.
      if (normalised.length > 0 && i < text.length) {
        normalised += " ";
        origins.push(i);
      }
      continue;
    }
    normalised += text[i];
    origins.push(i);
    i += 1;
  }

  return { normalised, origins };
}

function collapse(text) {
  return collapseWhitespace(text).normalised;
}

/**
 * Locate `anchor` inside `source`, ignoring whitespace differences.
 *
 * ## Ambiguity is an error, not a detail
 *
 * An anchor that matches more than once means the mutation may be applied to a site
 * nobody intended - and it can then be *caught* for entirely the wrong reason, which is
 * worse than going unnoticed: the report claims the suite has coverage it does not have.
 * Requiring a unique match forces the author to lengthen the anchor until it names one
 * statement.
 */
function locate(source, anchor) {
  const { normalised, origins } = collapseWhitespace(source);
  const needle = collapse(anchor);

  const first = normalised.indexOf(needle);
  if (first === -1) return { status: "absent" };

  if (normalised.indexOf(needle, first + 1) !== -1) {
    return { status: "ambiguous", count: normalised.split(needle).length - 1 };
  }

  return { status: "found", start: origins[first], end: origins[first + needle.length - 1] + 1 };
}

/** Apply one edit, or report precisely why it could not be applied. Returns null on failure. */
function applyEdit(source, edit) {
  const found = locate(source, edit.from);

  if (found.status === "absent") {
    console.error(`\n  anchor not found in ${edit.file}. The source moved; update this script.`);
    console.error(`  looking for: ${edit.from.slice(0, 110)}`);
    console.error("  lines with the most token overlap:");
    const tokens = edit.from.split(/[^A-Za-z0-9_]+/).filter((t) => t.length > 3);
    const scored = source
      .split("\n")
      .map((line) => {
        const collapsed = collapse(line);
        return { line, hits: tokens.filter((t) => collapsed.includes(t)).length };
      })
      .filter((candidate) => candidate.hits >= Math.max(2, Math.floor(tokens.length / 2)))
      .slice(0, 5);
    for (const candidate of scored) {
      console.error(`    ${candidate.line.trim().slice(0, 110)}`);
    }
    return null;
  }

  if (found.status === "ambiguous") {
    console.error(
      `\n  anchor is ambiguous in ${edit.file}: matches ${found.count} sites. A mutation ` +
        `applied to the wrong statement can be caught for the wrong reason, so lengthen ` +
        `the anchor until it names exactly one.`,
    );
    console.error(`  looking for: ${edit.from.slice(0, 110)}`);
    return null;
  }

  return source.slice(0, found.start) + edit.to + source.slice(found.end);
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// Snapshot every file we will touch, so a crash mid-run cannot leave a mutation in the
// repository. Snapshots go to a temp directory outside the repo on purpose.
const backupDir = mkdtempSync(join(tmpdir(), "mutation-"));
const backups = new Map();
let restored = false;

function basename(p) {
  const parts = p.split("/");
  return parts[parts.length - 1];
}

function restore() {
  if (restored) return;
  restored = true;
  for (const m of mutations) {
    for (const edit of m.edits) {
      const src = join(backupDir, `${m.id}__${basename(edit.file)}`);
      if (existsSync(src)) copyFileSync(src, join(root, edit.file));
    }
  }
}

for (const m of mutations) {
  for (const edit of m.edits) {
    copyFileSync(join(root, edit.file), join(backupDir, `${m.id}__${basename(edit.file)}`));
    // Two mutations may touch the same file; back up the pristine original under a
    // per-mutation name so a restore cannot cascade one mutation into the next.
    backups.set(`${m.id}__${basename(edit.file)}`, edit.file);
  }
}

process.on("exit", restore);
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    restore();
    process.exit(130);
  });
}

function cleanup() {
  restore();
  rmSync(backupDir, { recursive: true, force: true });
}

// Baseline: nothing below means anything unless the suite is green first.
process.stdout.write("baseline (expect pass) ... ");
const baseline = runForge(["test", "--no-match-test", "invariant"]);
if (baseline.code !== 0) {
  console.error("FAILED - fix the suite before mutation testing.");
  console.error(baseline.out.slice(-4000));
  cleanup();
  process.exit(1);
}
console.log("pass\n");

const survivors = [];
let applied = 0;

for (const m of mutations) {
  let failed = false;

  for (const edit of m.edits) {
    const src = join(root, edit.file);
    const original = readFileSync(src, "utf8");
    const mutated = applyEdit(original, edit);

    if (mutated === null) {
      failed = true;
      break;
    }
    if (mutated === original) {
      // applyEdit is total: a "found" span always differs. Treat equality as a bug in the
      // harness rather than silently mutating nothing and reporting a survivor.
      console.error(`\n${m.id}: mutation produced no change; the anchor matched itself.`);
      failed = true;
      break;
    }
    writeFileSync(src, mutated);
  }

  if (failed) {
    console.error(`\n${m.id}: could not apply. Aborting rather than reporting a false result.`);
    cleanup();
    process.exit(1);
  }

  applied += 1;
  const { code, out } = runForge(["test"]);

  // Detect failure from the output, not the exit code.
  //
  // `spawnSync` with `shell: true` goes through `cmd.exe`, and the status it reports
  // does not reliably reflect `forge`'s own. An earlier version of this harness trusted
  // `status !== 0` and reported ten mutations as "survived" while the very next line
  // printed the test that had failed for each one. The summary line is authoritative.
  const summary = out.match(/Ran \d+ test suites?[^\n]*?: (\d+) tests? passed, (\d+) failed/);
  const failingCount = summary ? Number(summary[2]) : (out.match(/\[FAIL:/g) ?? []).length;
  const caught = failingCount > 0 || code !== 0;
  const failing = [...out.matchAll(/\[FAIL: ([^\n]{0,110})/g)].map((x) => x[1].trim());
  const suite = (out.match(/Encountered \d+ failing tests? in ([^\n:]+)/) ?? [, "?"])[1];

  if (caught) {
    console.log(`caught    ${m.id}`);
    console.log(`         ${m.why}`);
    console.log(`         ${failingCount} failing: ${suite} ${failing[0] ?? ""}`);
  } else {
    console.log(`SURVIVED  ${m.id}`);
    console.log(`         ${m.why}`);
    if (m.note) console.log(`         note: ${m.note}`);
    survivors.push(m);
  }

  restore();
  restored = false;
}

cleanup();

console.log("");
const unexpected = survivors.filter((m) => !m.expect);
if (unexpected.length > 0) {
  console.error(`${unexpected.length} mutation(s) survived. The suite is missing coverage:`);
  for (const m of unexpected) console.error(`  - ${m.id}: ${m.why}`);
  process.exit(1);
}

// Every mutation in this file is expected to be caught. A mutation that is allowed to
// survive would need an `expect:` field *and* a comment explaining why the gap is
// deliberate - which is a much better outcome than silently accepting a survivor.
console.log(`${applied} of ${mutations.length} mutations caught`);
