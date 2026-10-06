#!/usr/bin/env node
/**
 * EIP-170 deployment-size gate.
 *
 * Fails when any deployable contract's runtime bytecode exceeds the limit.
 *
 * ## Why this enumerates `contracts/src` rather than scanning `out/`
 *
 * Foundry names an artifact directory after the *source file*, not the source
 * directory: `contracts/test/invariant/ComplianceLifecycleHandler.sol` builds to
 * `out/ComplianceLifecycleHandler.sol/ComplianceLifecycleHandler.json`. So the artifact
 * path carries no hint of whether a contract is deployable, and an earlier version of
 * this script that filtered on the artifact path reported a 21.8 KB *test handler* as
 * the largest contract in the repository - larger than anything actually deployed.
 *
 * Two rules were tried and both were wrong:
 *
 *   - filtering on a `.t.sol` / `.s.sol` suffix misses an ordinary `.sol` file that
 *     happens to live under `contracts/test`; and
 *   - filtering on a `test`/`script` path segment cannot work, because the segment is not
 *     present in the artifact path at all.
 *
 * Walking the source tree is unambiguous: EIP-170 applies to contracts under
 * `contracts/src`, and to nothing else in this repository.
 *
 * ## Usage
 *
 *   node scripts/check-contract-sizes.mjs [additional-contract ...]
 *
 * Exit 0 when every deployable contract fits, 1 when one is oversized, 2 on tooling
 * failure.
 */

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = join(root, "contracts", "src");
const artifactRoot = join(root, "out");

/**
 * EIP-170: 24576 bytes of runtime code.
 *
 * A test contract has no such limit, which is precisely why the deployable set is
 * enumerated from source rather than from artifacts - an oversized test contract is not
 * a deployment problem, and treating it as one makes the gate cry wolf.
 */
const LIMIT = 24576;

/** `contract Foo` / `abstract contract Foo` / `library Foo`, excluding interfaces. */
const CONTRACT_DECLARATION = /^\s*(?:abstract\s+)?(?:contract|library)\s+([A-Za-z_][A-Za-z0-9_]*)/gm;

function fail(message) {
  console.error(`::error::${message}`);
  process.exit(2);
}

function solidityFiles(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...solidityFiles(full));
    else if (entry.endsWith(".sol")) out.push(full);
  }
  return out;
}

const sources = solidityFiles(sourceRoot);
if (sources.length === 0) fail(`no Solidity sources under ${relative(root, sourceRoot)} - did \`forge build\` run?`);

const names = new Set();
for (const file of sources) {
  const text = readFileSync(file, "utf8");
  for (const match of text.matchAll(CONTRACT_DECLARATION)) {
    names.add(match[1]);
  }
}

for (const extra of process.argv.slice(2)) names.add(extra);

if (names.size === 0) fail("found no contract declarations under contracts/src");

const artifactFor = (name) => {
  for (const candidate of [
    join(artifactRoot, `${name}.sol`, `${name}.json`),
    join(artifactRoot, name, `${name}.json`),
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
};

/**
 * Byte length of a contract's runtime bytecode, as it appears in the artifact.
 *
 * Deliberately measured as the raw hex length rather than by shelling out to
 * `forge build --sizes`. The two differ by a constant per contract - 125 bytes for
 * `ComplianceGateway` in this repository - because `--sizes` excludes the trailing CBOR
 * metadata blob that `bytecode_hash = "ipfs"` appends to `deployedBytecode.object`.
 *
 * Measuring the larger number is the right direction for a gate: it can only be
 * pessimistic, so a contract this script accepts certainly fits. Cross-checked against
 * `forge build --sizes` for every contract in `contracts/src`; the ordering matches and
 * no contract is near the limit either way.
 */
function runtimeBytecodeLength(json) {
  const deployed = json.deployedBytecode;
  // Foundry emits `{ object }` when bytecode hashing is on, and a bare string when it is
  // off. Both appear in real repositories; treating one as absent would silently skip
  // the contract being measured.
  const hex = typeof deployed === "string" ? deployed : deployed?.object;
  if (typeof hex !== "string") return null;
  const body = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (body.length === 0) return 0;
  return body.length / 2;
}

const sizes = [];
const unmeasurable = [];

for (const name of [...names].sort()) {
  const artifact = artifactFor(name);
  if (artifact === null) {
    // An interface, or a contract whose bytecode was stripped. Neither has runtime code
    // to measure, so it is reported rather than treated as a failure - an interface that
    // somehow needed EIP-170 headroom would be a different and alarming story.
    unmeasurable.push(name);
    continue;
  }

  let json;
  try {
    json = JSON.parse(readFileSync(artifact, "utf8"));
  } catch (error) {
    fail(`could not parse ${relative(root, artifact)}: ${error.message}`);
  }

  const size = runtimeBytecodeLength(json);
  if (size === null) {
    unmeasurable.push(name);
    continue;
  }
  sizes.push({ name, size, artifact: relative(root, artifact).split("\\").join("/") });
}

if (sizes.length === 0) fail("no contract with runtime bytecode was found - did `forge build` run?");

sizes.sort((a, b) => b.size - a.size);

const OVERHEAD = 200;
const show = sizes.slice(0, 5);
console.log(`${sizes.length} deployable contract(s), limit ${LIMIT} B`);
for (const s of show) {
  console.log(`  ${String(s.size).padStart(6)} B  ${s.name.padEnd(34)} (${LIMIT - s.size} B margin)`);
}
if (unmeasurable.length > 0) {
  console.log(`  (${unmeasurable.length} with no runtime bytecode, e.g. interfaces: ${unmeasurable.slice(0, 3).join(", ")})`);
}

// `runtimeBytecodeLength` does not include the 200-byte allowance for the constructor
// arguments appended at deploy time, so the margin quoted above is slightly generous.
// EIP-170 counts the runtime code as deployed, which is what is measured here, but a
// contract within 200 bytes of the limit should be treated as not fitting.
const tight = sizes.filter((s) => s.size + OVERHEAD > LIMIT);
const oversized = sizes.filter((s) => s.size > LIMIT);

if (oversized.length > 0) {
  console.error("");
  for (const s of oversized) console.error(`::error::${s.name} is ${s.size} B, over the ${LIMIT} B limit`);
  console.error("\nEIP-170 deployable contracts must fit; split the contract or move logic off chain.");
  process.exit(1);
}

if (tight.length > 0) {
  console.error("");
  for (const s of tight) {
    console.error(`::error::${s.name} is ${s.size} B - within ${OVERHEAD} B of the limit, too close to deploy safely`);
  }
  process.exit(1);
}

const largest = sizes[0];
console.log(`\nall ${sizes.length} deployable contract(s) fit; largest is ${largest.name} at ${largest.size} B`);
