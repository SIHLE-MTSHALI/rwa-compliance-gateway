#!/usr/bin/env node
/**
 * Structural PII check for contract storage layout.
 *
 * Verifies that privacy-sensitive contracts declare no free-form (`string` / `bytes`)
 * storage members.
 *
 * ## Why this exists
 *
 * `contracts/test/NoPiiStorage.t.sol` scans storage at runtime and catches personal data
 * that was *actually written*. It cannot catch a `string` field that has been added but
 * never populated: an unset short string occupies no slots, so the runtime scan passes
 * vacuously. That is not hypothetical - a `legalName` field survived review in a sibling
 * repository of this one for exactly that reason.
 *
 * Reading the compiled storage layout closes the gap, because it checks the *shape* of
 * the state rather than the values in it.
 *
 * ## Why the type graph is walked, not just `storage`
 *
 * `forge inspect <c> storage-layout --json` exposes a `storage` array of top-level
 * entries and a separate `types` graph keyed by type id. A struct nested inside a
 * mapping - which is exactly how a credential record is stored - is reachable from
 * `storage` only as an opaque type id, so its members are invisible unless the graph is
 * traversed. A `string` added to `ComplianceCredential` would not appear in a naive
 * scan of `storage` at all.
 *
 * This walk is validated rather than assumed: injecting a `string` into
 * `ComplianceTypes.PoolPolicy` makes it report
 * `_policies{value}{value}.injectedPiiField` - two mapping hops deep, where the
 * `storage` array alone shows only an opaque type id.
 *
 * ## Usage
 *
 *   node scripts/check-no-dynamic-storage.mjs [contract ...]
 *
 * Exit 0 when clean, 1 when a free-form member is found, 2 on tooling failure.
 */

import { execFileSync } from "node:child_process";

/**
 * Contracts whose storage must contain no free-form members.
 *
 * `ComplianceRegistry` holds the only investor-linked state in the system, and
 * `AuditTrail` holds the history an auditor reads - so a `string` in either is a place
 * personal data could be written and never removed, since the trail is append-only by
 * construction.
 *
 * `PoolPolicyManager` is included for a different reason: it is the one contract whose
 * storage legitimately contains dynamic arrays, and this check is what keeps them
 * fixed-width.
 */
const STRICT_CONTRACTS = [
  "ComplianceRegistry",
  "PoolComplianceModule",
  "ComplianceGateway",
  "PoolPolicyManager",
  "CCIDResolver",
  "EmergencyControls",
  "AuditTrail",
  "CrossChainComplianceSender",
  "CrossChainComplianceReceiver",
];

/**
 * Contracts allowed exactly these free-form members, and nothing more.
 *
 * `ProviderRegistry` stores exactly one `string`: a documentation pointer chosen by
 * governance, not by an investor. Naming it here rather than exempting the contract
 * means a *second* `string` field added to the same contract still fails - which is the
 * property an allowlist gives you and a comment does not.
 */
const ALLOWED_DYNAMIC = {
  ProviderRegistry: ["metadataURI"],
};

/** True when a type label denotes free-form, arbitrarily sized data. */
function isFreeFormLabel(label) {
  if (typeof label !== "string") return false;
  // "string", "bytes", "string[]", "string[3]", "bytes[2][]", ...
  return /\b(string|bytes)\b/.test(label);
}

function layoutFor(contract) {
  const forge = process.env.FORGE_BIN ?? "forge";
  const out = execFileSync(forge, ["inspect", contract, "storage-layout", "--json"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const parsed = JSON.parse(out);
  if (!parsed || !Array.isArray(parsed.storage) || typeof parsed.types !== "object") {
    throw new Error("unexpected storage-layout shape");
  }
  return parsed;
}

/**
 * Depth-first walk of the type graph.
 *
 * `members` covers structs, `value` covers mappings, and `base` covers arrays and
 * inherited types. All three are followed, because a free-form field can hide in a
 * struct inside a mapping inside an array.
 */
function walk(types, typeId, path, seen, freeForm, dynamicArrays) {
  if (!typeId || seen.has(typeId)) return;
  seen.add(typeId);

  const node = types[typeId];
  if (!node) return;

  if (isFreeFormLabel(node.label)) {
    freeForm.push({ path, type: typeId, label: node.label });
    // Still descend: `string[]` is itself free-form and its elements matter too.
  }

  if (typeof node.base === "string") walk(types, node.base, `${path}[]`, seen, freeForm, dynamicArrays);
  if (typeof node.value === "string") walk(types, node.value, `${path}{value}`, seen, freeForm, dynamicArrays);

  if (Array.isArray(node.members)) {
    for (const member of node.members) {
      const childPath = path ? `${path}.${member.label}` : member.label;
      const childLabel = types[member.type]?.label;

      // Dynamic arrays are identified from `numberOfBytes`, not from the label:
      // solc's type label does not distinguish `uint16[]` from `uint16[3]`, but a
      // fixed-size array is exactly as wide as its contents while a dynamic array is a
      // single length word plus a pointer.
      //
      // Recorded for visibility rather than treated as a failure.
      // `PoolPolicyManager` legitimately holds `uint16[]` and `InvestorClass[]`; neither
      // can carry personal data, and printing the element type makes that judgement
      // auditable instead of implicit.
      if (
        member.numberOfBytes === 32 &&
        typeof childLabel === "string" &&
        childLabel.startsWith("t_array(") &&
        !isFreeFormLabel(childLabel)
      ) {
        dynamicArrays.push({
          path: childPath,
          label: childLabel,
          element: types[types[member.type].base]?.label ?? "unknown",
        });
      }

      walk(types, member.type, childPath, seen, freeForm, dynamicArrays);
    }
  }
}

const requested = process.argv.slice(2);
const contracts = requested.length > 0 ? requested : STRICT_CONTRACTS;

let failures = 0;
let freeFormTotal = 0;

for (const contract of contracts) {
  let layout;
  try {
    layout = layoutFor(contract);
  } catch (err) {
    console.error(`FAIL  ${contract}: could not read storage layout (${String(err.message).split("\n")[0]})`);
    failures += 1;
    continue;
  }

  const allowed = new Set(ALLOWED_DYNAMIC[contract] ?? []);
  const freeForm = [];
  const dynamicArrays = [];
  for (const entry of layout.storage) {
    walk(layout.types, entry.type, entry.label, new Set(), freeForm, dynamicArrays);
  }

  const unexpected = freeForm.filter((f) => !allowed.has(f.path.split(".").pop()));

  if (unexpected.length > 0) {
    console.error(`FAIL  ${contract}: free-form storage member(s) found`);
    for (const f of unexpected) console.error(`        ${f.path}  (${f.label})`);
    failures += 1;
    continue;
  }

  const notes = [];
  if (freeForm.length > 0) notes.push(`allowed free-form: ${freeForm.map((f) => f.path).join(", ")}`);
  if (dynamicArrays.length > 0) {
    notes.push(
      `fixed-width dynamic arrays: ${dynamicArrays.map((d) => `${d.path} [${d.element}]`).join(", ")}`,
    );
  }

  console.log(
    `ok    ${contract}: no unexpected free-form storage${notes.length > 0 ? `  [${notes.join("; ")}]` : ""}`,
  );
  freeFormTotal += freeForm.length;
}

if (failures > 0) {
  console.error(`\n${failures} contract(s) declare storage capable of holding free-form data.`);
  console.error("Credential state must be hashes, enums, and timestamps only. See docs/privacy-model.md.");
  process.exit(1);
}

console.log(
  `\nAll ${contracts.length} contract(s) checked. Free-form members found: ${freeFormTotal}` +
    (freeFormTotal > 0 ? " (all explicitly allowlisted above)." : "."),
);
