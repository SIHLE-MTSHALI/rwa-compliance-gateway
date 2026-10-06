# Privacy model

This document describes what the system stores, what it deliberately does not, and how that is
enforced mechanically rather than by convention.

Nothing here establishes legal or regulatory compliance. See
[`audit-readiness.md`](./audit-readiness.md) for what is missing before a pilot.

## 1. The claim

A class, not an identity.

The only investor-shaped values on chain are `jurisdictionCode` and `investorClass`. Both are
coarse buckets selected by issuer policy. No name, address, tax ID, date of birth, passport number,
email, document, accreditation certificate number, or provider case reference is stored, emitted, or
loggable anywhere in this repository.

This is possible because the access decision does not need the investor. It needs to know "this
credential, presented by this holder, represents a US-accredited investor under jurisdiction 840".
That is two small integers. Everything else stays in the off-chain workflow.

## 2. What is stored, field by field

### 2.1 `ComplianceTypes.ComplianceCredential` — the only investor-linked record

| Field | Type | Bytes | What it tells you |
| --- | --- | --- | --- |
| `ccid` | `bytes32` | 32 | Nothing directly. A one-way content identifier. |
| `credentialType` | `bytes32` | 32 | Which policy family, e.g. `keccak256("kyc.basic")`. |
| `providerId` | `bytes32` | 32 | Which verifier. |
| `evidenceHash` | `bytes32` | 32 | A commitment to evidence. **Not** the evidence. |
| `schemaVersion` | `uint32` | 4 | Which version of the schema was applied. |
| `jurisdictionCode` | `uint16` | 2 | **Investor-shaped.** ISO 3166-1 numeric. 840 is the United States. |
| `investorClass` | `enum` (1 byte) | 1 | **Investor-shaped.** Four values. |
| `status` | `enum` (1 byte) | 1 | Lifecycle state. |
| `issuedAt` | `uint64` | 8 | Timestamp. |
| `expiresAt` | `uint64` | 8 | Timestamp. |
| `updatedAt` | `uint64` | 8 | Timestamp. |
| `nonce` | `uint64` | 8 | Monotonic replay guard. |

Packed into 6 storage slots (192 bytes). Two investor-shaped fields occupy 3 bytes of that.

`subjectCommitment` is **not** a field. It exists only on `CredentialResult`, the transient calldata
struct the gateway validates and then discards. See §4.

### 2.2 `ComplianceTypes.PropagationState`

| Field | What it is |
| --- | --- |
| `isReplica` | Whether this record came from another chain. |
| `sourceChainSelector` | Which chain. |
| `lastUpdatedAt` | When it arrived. |
| `lastSourceNonce` | The nonce it carried. |

One storage slot. No investor data.

### 2.3 `ComplianceTypes.PoolPolicy`

`poolId`, `version`, `active`, `registered`, `requiresManualReview`, `requiresFreshReplica`,
`acceptedJurisdictions` (`uint16[]`), `acceptedInvestorClasses` (`InvestorClass[]`),
`maxReplicaAge`, `maxAllocationPerInvestor`, `revocationMode`, `effectiveAt`, `createdAt`.

Issuer configuration, not investor data. The two dynamic arrays have fixed-width elements.

### 2.4 `AuditTrail.Entry`

| Field | Why it is not PII |
| --- | --- |
| `ccid` | A content identifier, never an identity. |
| `poolId` | Issuer's own pool. |
| `actor` | A contract address, already public on chain. For `recordCredentialEvent` it holds the resulting status, packed to keep the entry a fixed shape. |
| `reasonCode` | One of 14 fixed codes. **Never free text** — that is what stops an operator smuggling a name in through a reason string. |
| `amount` | A quantity in the pool's accounting token. Needed to reconstruct whether a cap was applied correctly. Not an investor attribute. |
| `timestamp` | Timestamp. |
| `kind` | `EntryKind` enum. |

`AuditTrail.t.sol::test_NoInvestorShapedFieldIsStored` asserts every one of these, field by field.

### 2.5 `ProviderRegistry.Provider`

`providerId`, `metadataURI`, `lastHeartbeat`, `failureCount`, `registeredAt`, `updatedAt`,
`status`, `registered`.

`metadataURI` is the only free-form string in the system. It is a governance-chosen documentation
pointer, bounded at 512 bytes, written by `PROVIDER_ADMIN` only. Not investor-supplied.

### 2.6 `EmergencyControls`

`paused` (bool), `unpauseExecutableAt` (uint64). Plus roles. Nothing else.

### 2.7 `CrossChainComplianceSender` / `CrossChainComplianceReceiver`

Sender: `bridge`, `bridgeInitialized`, `lastSentNonce`, `sentTo`. Receiver: `ALLOWED_SOURCE_SENDERS`,
`ALLOWED_SOURCE_CHAINS`, `consumedOrderIds`, `lastAcceptedNonce`, `wired`. All infrastructure
bookkeeping.

## 3. Why two coarse buckets are not identity

### 3.1 `jurisdictionCode` — a country, not a person

`uint16`, ISO 3166-1 numeric. 840 is the United States; 826 is the United Kingdom; 392 is Japan.

It answers "which securities regime applies to this investor's attestation", which is what pool
policy genuinely needs. It is a country-level attribute that the holder's own jurisdiction
determines, not a property of a person's identity. Two people in the same country share the value,
and the value alone does not narrow a population below "everyone subject to that regime".

It is a preimage component of the CCID, so changing it changes the credential's identity. A
US-accredited attestation cannot be presented as a UK professional one — `test_JurisdictionSwapRejected`.

It is validated as `!= 0` at issuance (`JurisdictionUnset`). A credential asserting jurisdiction 0
would otherwise be evaluated against policy as though it were real data.

### 3.2 `investorClass` — four values, and no more

```solidity
enum InvestorClass { Unknown, USAccredited, NonUSProfessional, Blocked }
```

Deliberately limited to four. Every additional class is another axis on which holders can be
correlated from public chain state, so the set is kept as small as real policy permits.

`Blocked` is a first-class value rather than an absent credential, so a denial is explainable to the
holder it affects. An absent credential cannot be distinguished from "never verified".

A policy's empty `acceptedInvestorClasses` means *all except `Blocked`*. Serving a blocked investor
requires an explicit opt-in — see [`policy-schema.md`](./policy-schema.md).

### 3.3 What the buckets do not permit

Neither value, alone or combined, identifies a person. There is no address, no name, no document
reference, and no jurisdiction sub-national code. An observer with full access to chain state learns
that *some* credential exists for jurisdiction 840 / class `USAccredited` — which is precisely the
fact the access decision requires, and no more.

The remaining correlation risk is the `ccid` itself, which is a function of these fields plus a
subject commitment the observer cannot invert. Two credentials sharing a jurisdiction and class still
have different CCIDs because the subject commitment differs.

## 4. `subjectCommitment` never reaches storage

`CredentialResult` carries `subjectCommitment` because the gateway needs it to verify the CCID
binding:

```solidity
bytes32 expected = CCID_RESOLVER.compute(
    r.credentialType, r.schemaVersion, r.providerId, r.jurisdictionCode, r.investorClass, r.subjectCommitment
);
if (r.ccid != expected) revert InvalidCCID(r.ccid, expected);
```

That is the only use. `ComplianceRegistry.issue` and `resolvePending` take explicit parameters and
`subjectCommitment` is not among them, so it is not written. It is also **not** in the cross-chain
payload — the destination needs "does a valid credential exist for this CCID", and the CCID already
binds it. Shipping the commitment would publish a second, correlatable per-holder value on every
destination chain for no functional gain.

Consequence worth stating plainly: because the commitment is absent, the destination **cannot
re-derive the CCID**. Integrity there rests on `bindingHash`, `ALLOWED_SOURCE_SENDERS`, and the
nonce. That is a real trade, made in exchange for not spreading a correlatable identifier.

## 5. `evidenceHash` is a commitment, never the evidence

`evidenceHash` is a `bytes32` the provider workflow computes over its own evidence artifact — a
document, a screening result, a case file. Only the hash reaches the chain. The gateway requires it
to be non-zero (`ZeroEvidenceHash`), so an issuance cannot claim "no evidence commitment".

It is a commitment, not a reference: the chain cannot open it, an auditor needs the provider's own
systems to resolve it, and an observer learns nothing from it. The trade is that on-chain
verification of the evidence is impossible by construction — stated as a gap in
[`audit-readiness.md`](./audit-readiness.md).

## 6. The salt never leaves the off-chain workflow

`subjectCommitment` is computed **off-chain** as a salted commitment — conceptually
`keccak256(salt || verifiedAttribute)`. The salt stays inside the workflow's secret store and never
reaches the chain, so the commitment is:

- not reversible, and
- not correlatable across issuers that choose different salts.

The sensitive boundary is off-chain **by construction**, not by policy: there is deliberately no
function in `CCIDResolver`, in the gateway, or in the payload library that accepts a name, email, or
document. `CCIDResolver.validateParts` requires `credentialType`, `providerId`, and
`subjectCommitment` all non-zero — a zero commitment would leave the credential unbound to anybody,
which is worse than not issuing it.

### 6.1 The SDK helper is a demonstration, not a construction

`packages/sdk/src/ccid.ts` exports `saltedSubjectCommitment(salt, attribute)`. Its own doc comment
says not to use it in production: a salt of that kind is not a secret. If the attribute is guessable
— and a passport number is not — then an attacker with the salt and the commitment can confirm a
guess. The real workflow must use a proper HMAC over the verified attribute, or a keyed commitment
whose key never leaves the workflow's secret store.

It exists so the SDK's call sites and tests have a working example, and so the "never send the
salt" property has something concrete to attach to.

## 7. Where a `string` could still hide: the storage-layout check

### 7.1 The blind spot

`contracts/test/` contains runtime storage assertions, and `AuditTrail.t.sol` walks a stored entry
field by field. Those catch personal data that was **actually written**.

They cannot catch a `string` field that has been added but never populated: an unset short string
occupies no slots, so a runtime scan passes vacuously.

This is not hypothetical. **A `legalName` field survived review in a sibling repository for exactly
that reason.** It compiled, it was never written, every test passed, and nothing in the test suite
was capable of noticing.

### 7.2 `scripts/check-no-dynamic-storage.mjs`

Reads the **compiled** storage layout, which checks the *shape* of the state rather than the values
in it.

```bash
node scripts/check-no-dynamic-storage.mjs          # the 9 strict contracts
node scripts/check-no-dynamic-storage.mjs ProviderRegistry
FORGE_BIN=/path/to/forge node scripts/check-no-dynamic-storage.mjs
```

Exit codes: `0` clean, `1` a free-form member was found, `2` tooling failure. It runs as its own CI
job (`privacy (storage layout)`).

**Strict contracts** — `ComplianceRegistry`, `PoolComplianceModule`, `ComplianceGateway`,
`PoolPolicyManager`, `CCIDResolver`, `EmergencyControls`, `AuditTrail`,
`CrossChainComplianceSender`, `CrossChainComplianceReceiver`.

`ComplianceRegistry` holds the only investor-linked state and `AuditTrail` holds the history an
auditor reads — a `string` in either is a place personal data could be written and never removed,
since the trail is append-only by construction. `PoolPolicyManager` is included for a different
reason: it is the one contract whose storage legitimately contains dynamic arrays, and this check is
what keeps them fixed-width.

### 7.3 Why the `types` graph is walked, not just `storage`

`forge inspect <contract> storage-layout --json` exposes a `storage` array of top-level entries and
a **separate `types` graph** keyed by type id.

A struct nested inside a mapping — which is exactly how a credential record is stored — is reachable
from `storage` only as an opaque type id. `ComplianceRegistry._records` appears as
`t_mapping(t_bytes32,t_struct(ComplianceCredential)1548_storage)`; a naive scan of `storage` sees
only that string and no members. A `string` added to `ComplianceCredential` would not appear at all.

The walk therefore follows three edges:

| Edge | What it covers |
| --- | --- |
| `members` | Struct fields |
| `value` | Mappings |
| `base` | Arrays and inherited types |

All three, because a free-form field can hide in a struct inside a mapping inside an array. Cycles
are guarded by a `seen` set. When a node's label matches `/\b(string|bytes)\b/` the path is recorded
and the walk **still descends** — `string[]` is itself free-form and its elements matter.

The reported path is built from the traversal, so a finding names its exact location rather than
just the contract.

### 7.4 Dynamic arrays are reported, not failed

A dynamic array is identified from `numberOfBytes == 32` plus a `t_array(...)` label, not from the
label alone — solc's type label does not distinguish `uint16[]` from `uint16[3]`, while a fixed-size
array is exactly as wide as its contents and a dynamic array is a length word plus a pointer.

Non-free-form dynamic arrays are printed with their element type for visibility:

```
ok    PoolPolicyManager: no unexpected free-form storage  [fixed-width dynamic arrays:
      _policies{value}{value}.acceptedJurisdictions [uint16],
      _policies{value}{value}.acceptedInvestorClasses [enum ComplianceTypes.InvestorClass]]
```

Neither element type can carry personal data, and printing them makes that judgement auditable
instead of implicit.

### 7.5 The allowlist is a list, not an exemption

```js
const ALLOWED_DYNAMIC = {
  ProviderRegistry: ["metadataURI"],
};
```

Naming the single permitted field — rather than exempting the whole contract — means a **second**
`string` added to `ProviderRegistry` still fails. That is the property an allowlist gives you and a
comment does not.

### 7.6 Proving the check works: the mutation procedure

A check that has never been observed to fail is not known to work. The procedure:

1. Add a `string` member to `ComplianceTypes.PoolPolicy`:

```solidity
struct PoolPolicy {
    // ...
    uint64 effectiveAt;
    uint64 createdAt;
    string injectedPiiField;   // mutation
}
```

2. Run the check against `PoolPolicyManager`:

```bash
node scripts/check-no-dynamic-storage.mjs PoolPolicyManager
```

3. Required output — exit code `1`, naming the field two mapping hops deep:

```
FAIL  PoolPolicyManager: free-form storage member(s) found
        _policies{value}{value}.injectedPiiField  (string)
1 contract(s) declare storage capable of holding free-form data.
```

4. Revert the mutation and confirm the run is clean again (exit `0`, no findings).

**Why this specific target.** `PoolPolicy` lives at `_policies[poolId][version]`, so the path is
`_policies{value}{value}.injectedPiiField`. A `storage`-array-only scan sees `_policies` as an opaque
mapping-to-struct type id and reports nothing — so this target simultaneously proves the check fires
*and* proves the `types`-graph walk is what makes it visible.

**Verified during development.** The procedure above was executed against this repository: the check
reported `_policies{value}{value}.injectedPiiField  (string)` and exited `1`; the mutation was then
reverted and all 9 strict contracts reported clean.

### 7.7 Related backstops

| Layer | What it catches | Limit |
| --- | --- | --- |
| `check-no-dynamic-storage.mjs` | Authoritative. Any free-form storage member in a strict contract, written or not. | Only storage — does not inspect event parameters |
| `git grep` in CI hygiene job | Identity-bearing *field names* (`legalName`, `fullName`, `dateOfBirth`, `passportNumber`, `taxId`, `ssn`) in `contracts/src/**` | Backstop, not authority. Scoped to `contracts/src` deliberately: `contracts/test/**` names these fields in comments, and a `workflows/src/privacy.ts`-style blocklist names them in order to forbid them |
| `AuditTrail.t.sol` runtime assertions | Values actually written | Cannot see an unset `string` — see §7.1 |
| `scripts/mutation-check.mjs` | Behaviours removed from contracts | Does not touch storage shape |

## 8. What is emitted

Events carry the same discipline. `ComplianceRegistry` events: `ccid`, `credentialType`,
`providerId`, `schemaVersion`, `jurisdictionCode`, `investorClass`, `expiresAt`, `nonce`. No
`subjectCommitment`, no evidence, no free text.

`ProviderRegistry.ProviderStatusChanged` and friends use `providerId` as the subject rather than an
address — providers are identified by hash, and logging an address that stands in for a provider
invites the reader to treat it as a person.

### 8.1 Denials are not emitted

`PoolComplianceModule` emits `AccessAllowed` and `AccessReviewRequired` and nothing for `Deny`. An
emitted denial would let anyone inflate a holder's public denial history by probing repeatedly, and
the view function already returns the reason to the caller.

`AuditTrail.recordDecision` supports `EntryKind.AccessDenied` for a permissioned compliance officer
recording denials they resolve. The path exists; the module does not use it.

### 8.2 Reason strings are codes, not text

`revoke(ccid, poolId, reason, destinations)` takes `reason` as `bytes32`. An issuer can pass any
`bytes32` they like, and it is not validated against `ComplianceTypes.allReasons()`. The practical
effect is that an arbitrary hash can be written into the audit entry's `reasonCode` — it cannot carry
a readable name, because 32 bytes of arbitrary content is not a name, and `reasonToString` will
report `UNRECOGNIZED` for anything not in the list. Storing a hash rather than free text is what
prevents personal data being injected into an append-only log that cannot be scrubbed. Constraining
`reason` to the known set would be tighter; noted as a minor gap.

`EmergencyControls.pause(string reason)` and `scheduleUnpause(string reason)` do take a short string,
bounded at `MAX_REASON_LENGTH = 256`. It is operator-authored during an incident, bound to a bounded
length, and the doc comment states it must not contain investor data because it is public chain
state.

## 9. Residual privacy risks

| Risk | Assessment |
| --- | --- |
| `jurisdictionCode` + `investorClass` are linkable per credential | Accepted. They are the minimum the decision requires. They do not identify a person. |
| `ccid` is a stable per-holder identifier | By design — it is what integrators store and what propagates. It is a function of coarse buckets plus a commitment that cannot be inverted. |
| `evidenceHash` is correlatable across credentials from one provider | If the provider commits deterministically to the same evidence, two credentials share a hash. The provider workflow should salt. |
| `metadataURI` is free-form | Governance-controlled, 512-byte bound, and the only allowlisted string. |
| `pause` / `scheduleUnpause` reason strings are free-form | Bounded at 256 bytes, operator-authored, public. |
| The workflow boundary holds all sensitive data | This is the load-bearing assumption. A leak in the off-chain workflow is outside these contracts' reach, which is also why confidential compute is the right answer and why this system does not claim to solve it. |

## 10. What this document does not claim

- It does not claim the system is compliant with any regulation. Whether a jurisdiction's rules are
  satisfied by this design is a question for qualified counsel.
- It does not claim the off-chain workflow handles sensitive data correctly. This system verifies
  that an attestation is *coherent*; it does not verify that it is *true*.
- It does not claim `saltedSubjectCommitment` is a production construction. See §6.1.
- It does not claim the absence of a `string` field proves the absence of a privacy leak. It proves a
  specific, mechanical property of storage shape, which is narrower and checkable.