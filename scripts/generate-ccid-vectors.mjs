// Regenerates the CCID test vectors from the contract's own resolver.
//
//   node scripts/generate-ccid-vectors.mjs
//
// Writes `packages/sdk/test/vectors/ccid.json`, where `ccid.test.ts` asserts the
// TypeScript derivation reproduces these bytes exactly.
//
// ## Why these are generated rather than hand-written
//
// The CCID derivation is protocol. A pasted-in vector computed by hand would keep
// "passing" after a reordered field or a changed domain separator, while the gateway -
// which re-derives every CCID on submission - would reject every real credential. The
// failure would appear in production, on the first issuance, with no failing test
// pointing at the cause.
//
// Generating from the contract makes the vectors a witness of the implementation: a
// protocol change surfaces as a failing TypeScript test instead.
//
// ## Why the intermediate format is a token stream
//
// Two facts about `console.log` shaped this parser, and both cost a rewrite to discover:
//
//   1. it pads every argument to a fixed column, so padding lands inside values; and
//   2. it wraps long output at roughly 78 columns, so one logical row arrives as two
//      physical lines.
//
// Rather than strip padding or join wrapped lines - both of which produced subtly
// malformed values instead of errors - this reads the payload as a whitespace-separated
// token stream and consumes the markers positionally. Wrapping and padding then become
// irrelevant, and a truncated payload still fails loudly at the point where the fields
// run out.
//
// The Solidity side emits the fixed inputs (`credentialType`, `schemaVersion`,
// `providerId`) too, so nothing here recomputes a hash. A second keccak implementation
// in JavaScript is another thing that can quietly disagree with the chain, and a vectors
// file that disagrees is precisely the failure this mechanism exists to prevent.

import { spawnSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const forge = process.env.FORGE_BIN ?? join(process.env.USERPROFILE ?? "", ".foundry", "bin", "forge.exe");
const outPath = join(root, "packages", "sdk", "test", "vectors", "ccid.json");

const BEGIN = "RWA_CCID_VECTORS_V1";
const END = "RWA_CCID_VECTORS_END";

/** Must match `ComplianceTypes.InvestorClass`. An unlisted value is an error, not a default. */
const INVESTOR_CLASSES = new Set(["Unknown", "USAccredited", "NonUSProfessional", "Blocked"]);

const HEX64 = /^[0-9a-f]{64}$/;

function fail(message) {
  console.error(`generate-ccid-vectors: ${message}`);
  process.exit(1);
}

const result = spawnSync(forge, ["script", "contracts/script/GenerateCcidVectors.s.sol:GenerateCcidVectors"], {
  cwd: root,
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024,
});

if (result.status !== 0) {
  console.error(result.stdout ?? "");
  console.error(result.stderr ?? "");
  process.exit(result.status ?? 1);
}

const raw = `${result.stdout ?? ""}`;
const beginIndex = raw.indexOf(BEGIN);
const endIndex = raw.indexOf(END);
if (beginIndex === -1) fail(`missing the ${BEGIN} marker in the script output`);
if (endIndex === -1 || endIndex < beginIndex) fail(`missing the ${END} marker in the script output`);

const tokens = raw
  .slice(beginIndex + BEGIN.length, endIndex)
  .split(/\s+/)
  .filter((token) => token.length > 0);

let cursor = 0;
function take(what) {
  if (cursor >= tokens.length) fail(`output ended while reading ${what}`);
  const token = tokens[cursor];
  cursor += 1;
  return token;
}
function expect(token, what) {
  const actual = take(what);
  if (actual !== token) fail(`expected "${token}" for ${what}, found "${actual}"`);
}
function hex(value, what) {
  if (!HEX64.test(value)) fail(`${what} is not 64 lowercase hex characters: "${value}"`);
  return value;
}
function uintInRange(raw_, what, max) {
  const value = Number(raw_);
  if (!Number.isInteger(value) || value < 0 || value > max) {
    fail(`${what} "${raw_}" is not an integer in [0, ${max}]`);
  }
  return value;
}

expect("DOMAIN", "the domain marker");
const domain = hex(take("the domain hash"), "domain");

expect("INPUTS", "the fixed-inputs marker");
const credentialType = hex(take("credentialType"), "credentialType");
const schemaVersion = uintInRange(take("schemaVersion"), "schemaVersion", 0xffffffff);
const providerId = hex(take("providerId"), "providerId");

const vectors = [];
while (cursor < tokens.length) {
  expect("VECTOR", "a vector marker");
  const subjectCommitment = hex(take("subjectCommitment"), "subjectCommitment");
  // Jurisdiction 0 is rejected by the gateway, so a vector carrying it would test a
  // state issuance cannot produce.
  const jurisdictionCode = uintInRange(take("jurisdictionCode"), "jurisdictionCode", 0xffff);
  if (jurisdictionCode === 0) fail("a vector has jurisdictionCode 0, which the gateway rejects at issuance");
  const investorClass = take("investorClass");
  if (!INVESTOR_CLASSES.has(investorClass)) {
    fail(`unrecognised investor class "${investorClass}"; add it to INVESTOR_CLASSES if the enum grew`);
  }
  const ccid = hex(take("ccid"), "ccid");

  vectors.push({ subjectCommitment, jurisdictionCode, investorClass, ccid });
}

if (vectors.length === 0) fail("no vectors were emitted");

const seenCcids = new Set();
const seenSubjects = new Set();
for (const v of vectors) {
  if (seenCcids.has(v.ccid)) fail(`duplicate CCID in the vectors: ${v.ccid}`);
  if (seenSubjects.has(v.subjectCommitment)) fail(`duplicate subject commitment: ${v.subjectCommitment}`);
  seenCcids.add(v.ccid);
  seenSubjects.add(v.subjectCommitment);
}

// Every jurisdiction and every class the chain can represent should appear, or a field
// swap in the TypeScript derivation could pass on the uncovered combination.
const jurisdictionsCovered = new Set(vectors.map((v) => v.jurisdictionCode));
const classesCovered = new Set(vectors.map((v) => v.investorClass));
if (jurisdictionsCovered.size < 2) fail("vectors cover fewer than two jurisdictions");
if (classesCovered.size < 3) fail("vectors cover fewer than three investor classes");

const parsed = {
  _comment:
    "GENERATED by scripts/generate-ccid-vectors.mjs from CCIDResolver.compute(). " +
    "Do not edit by hand - ccid.test.ts asserts the TypeScript derivation reproduces these bytes.",
  // `0x`-prefixed for viem, which rejects unprefixed hex outright. The prefix is added
  // here rather than at every read site: a value that silently needs fixing at the point
  // of use is a value that will be used unfixed somewhere.
  domain: asHex(domain),
  credentialType: asHex(credentialType),
  schemaVersion,
  providerId: asHex(providerId),
  vectors: vectors.map((v) => ({
    subjectCommitment: asHex(v.subjectCommitment),
    jurisdictionCode: v.jurisdictionCode,
    investorClass: v.investorClass,
    ccid: asHex(v.ccid),
  })),
};

/** Prefixed hex, for the JSON the SDK and workflow tests read. */
function asHex(bare) {
  return `0x${bare}`;
}

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(parsed, null, 2)}\n`);

console.log(`wrote ${vectors.length} vectors to packages/sdk/test/vectors/ccid.json`);
console.log(`domain:         ${domain}`);
console.log(`credentialType: ${credentialType}`);
console.log(`schemaVersion:  ${schemaVersion}`);
console.log(`providerId:     ${providerId}`);
console.log(`coverage:       ${jurisdictionsCovered.size} jurisdictions x ${classesCovered.size} classes`);
