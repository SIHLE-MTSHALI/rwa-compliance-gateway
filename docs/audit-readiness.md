# Audit readiness

**This repository is not audited.** No external security review has been performed. No bug bounty is
active. Nothing here establishes legal or regulatory compliance, and nothing here should be
represented as doing so.

What follows is an honest, ranked list of what is missing before a pilot, and what would close each
item. It is written for someone deciding whether to commission an audit, and for whoever reads that
audit's report later.

## 1. Summary

| # | Gap | Severity | Effort to close |
| --- | --- | --- | --- |
| G1 | No bulk revocation | **Critical at scale** | Medium |
| G2 | No per-credential proof of off-chain verification | High | High |
| G3 | Audit trail is on-chain only, no off-chain anchoring | High | Medium |
| G4 | The CCIP router is trusted and only mocked in tests | High | Medium |
| G5 | `currentAllocation` is a caller-supplied argument | High | Medium |
| G6 | No formal verification | Medium | High |
| G7 | No gas benchmarks | Medium | Low |
| G8 | No formal spec-to-code traceability | Medium | Medium |
| G9 | Invariant suite is sampled over sequences | Medium | Medium |
| G10 | The invariant handler cannot reach two system states | Medium | Medium |
| G11 | `reason` on lifecycle calls is unvalidated | Low | Low |
| G12 | `receiveMessage` is a second entry point to `_accept` | Low | Low |
| G13 | No secrets or incident-response rehearsal | Low | Low |
| G14 | No legal or regulatory review | **Blocker** | External |

Two of these — G1 and G6 — are the ones an auditor will ask about first.

## 2. Ranked gaps

### G1 — No bulk revocation

**Severity: critical at scale.** This is the top gap.

`ComplianceGateway.revoke` is per credential. There is no `revokeBatch`, no provider-scoped
revocation, and no way to withdraw a set of credentials in one transaction.

`ComplianceRegistry.expireDue` accepts a batch, bounded at `MAX_SWEEP_BATCH = 100` — so the pattern
exists for expiry and is absent for the far more consequential operation.

**Why it is the top gap.** Consider a provider compromise affecting 10,000 holders:

1. `setProviderStatus(providerId, Revoked)` — one transaction, and access stops immediately
   everywhere the provider is registered. This is the effective mitigation.
2. But every credential in the audit trail still reads `Valid` with a live provider, and the reason a
   holder is refused is `PROVIDER_PAUSED`, not `Revoked`.
3. Sweeping to `Revoked` for a clean record means 10,000 transactions, each with its own propagation.
   At any realistic gas price and block limit, that is many hours of work during an incident.

So the practical state is: the incident is contained by one call, and the evidence is not. An
investigator reconstructing what happened finds credentials that appear valid, a provider that was
revoked, and no per-credential record of why. That is a worse position than it needs to be, and it is
a position an auditor will probe.

**What would close it:**

```solidity
function revokeBatch(
    bytes32[] calldata ccids,
    bytes32 poolId,
    bytes32 reason,
    uint64[] calldata destinations
) external onlyIssuerAdmin returns (uint256 revokedCount);
```

with `BatchTooLarge` bounding, the same `_requireRevocationAuthority` per element, a single
`_propagate` call carrying the highest nonce, and one `CredentialLifecycleAction` per credential.
Estimated 30–60 lines. Alternatively — and better, for this specific scenario — a
`revokeProviderAndCascade(providerId, reason)` on `ComplianceGateway` that revokes every credential
backed by a provider in one sweep.

**Residual after closing:** the per-credential audit entries still cost storage. Mitigate by
recording one provider-scoped entry plus an off-chain index.

### G2 — No per-credential proof that the off-chain verification happened

**Severity: high.** This is the deepest gap and the one most likely to be misunderstood.

`evidenceHash` is a `bytes32` commitment to provider evidence the chain cannot open. The gateway's
only check is that it is non-zero (`ZeroEvidenceHash`).

There is no on-chain evidence that:
- a verification actually occurred,
- it was performed by the claimed provider,
- the provider applied its stated methodology,
- the holder actually presented the documents the evidence attests to,
- the result has not been fabricated by a compromised workflow.

**The chain verifies that an attestation is coherent, not that it is true.** A compromised
`WORKFLOW_SUBMITTER` cannot forge a *false* credential that passes policy — the CCID binds the
fields and the provider must be `Active` — but it can submit an attestation for a holder who was
never verified, as long as the fields are internally consistent and the provider supports the schema.
The chain has no way to tell.

This is partly inherent: a blockchain cannot verify a document. But the gap as it stands is that
**there is no verifiable claim at all**, rather than a cryptographic claim an auditor could check.

**What would close it, in increasing order of ambition:**

1. **Off-chain anchoring.** The workflow publishes a signed attestation over
   `(ccid, evidenceHash, providerId, timestamp)` to an independent, append-only medium — a
   transparency log, a notary, a second chain. Low effort. Turns "we say so" into "a third party can
   check", though the trust moves rather than disappears.
2. **A signed provider attestation on chain.** The provider signs the result directly with a key whose
   on-chain address is registered in `ProviderRegistry`. The workflow then cannot fabricate anything —
   it can only relay. This is the highest-value change and the most invasive: it inverts the trust
   model from "trust the workflow" to "trust the provider's key", which is the correct shape for a
   system whose whole premise is that the workflow is off-chain and untrusted.
3. **ZK proof of verification.** A proof that a verification circuit over specific attributes was
   executed correctly, with the provider's parameters committed. Highest assurance, highest cost, and
   a substantial engineering effort. Note that confidential compute is the complementary technology:
   it addresses the *processing* boundary rather than the *verification* boundary, and the two are
   frequently confused.

**Residual after closing:** none of these proves the provider itself is honest. Option 2 moves the
trust from the workflow operator to the provider, which is a genuine improvement but not elimination.

### G3 — The audit trail is on-chain only, with no off-chain anchoring

**Severity: high.**

`AuditTrail` is append-only by construction — no update, no delete — and `nextEntryId` is strictly
increasing. That is a real property: an entry cannot change because an id cannot be reused
(`test_EarliestEntrySurvivesLaterWrites`, `invariant_auditEntriesAreNeverRewritten`).

But append-only on one chain means integrity rests entirely on that chain's integrity. There is no
periodic publication of a Merkle root to an independent medium, no off-chain copy, and no independent
timestamping. An adversary who can rewrite chain history rewrites the audit trail.

Two smaller problems compound it:

- **Coverage is partial.** `evaluateAndRecord` records allows and review-required outcomes, plus
  credential lifecycle events via `recordCredentialEvent`. Denials are deliberately not emitted — a
  sound privacy decision, but it means the trail cannot answer "who was refused and when". A
  permissioned `recordDecision` path exists for a compliance officer and is not called by the module.
- **The typed entry methods are not wired.** `recordIssuance`, `recordPolicyChange`,
  `recordProviderChange`, and `recordEmergencyAction` exist and are tested, but **no production
  contract calls them.** Policy changes, provider status changes, and emergency actions are emitted
  as events but are not recorded in the trail. `_recordAudit` in the gateway always uses
  `recordCredentialEvent`, including at issuance — so an issuance is recorded with kind
  `CredentialStatusChanged`, never `CredentialIssuance`.

**What would close it:**

1. **Anchor a root.** After each entry, or on a schedule, publish `keccak256(entryId, ccid, poolId,
   reasonCode, timestamp)` — or a rolling Merkle root — to an independent medium. Cheap, and it is
   the difference between "the chain says so" and "we published it before the incident".
2. **Wire the existing methods.** `PoolPolicyManager` and `ProviderRegistry` and
   `EmergencyControls` each hold no `AuditTrail` reference, so they cannot record. Add one, or accept
   that their events are the record and index off-chain. The latter is defensible; the point is that it
   must be a decision rather than an accident.
3. **Record issuance as issuance.** `_recordAudit` at the issuance path uses
   `recordCredentialEvent`; `recordIssuance` exists and is unused.
4. **Decide the denial policy explicitly.** Either record denials from a permissioned path, or state
   in the auditor-facing documentation that denials are deliberately not on chain and that the
   off-chain log is the record.

### G4 — The CCIP router is trusted, and only mocked in tests

**Severity: high.**

`msg.sender == ROUTER` is the receiver's primary gate. `MockCCIPRouter` preserves the two properties
the receiver depends on — `send` returns a message id with `msg.sender` as caller, and delivery
invokes `ccipMessageCallback` with `msg.sender == router` — so router identity, sender allowlist,
selector, order id, and payload bytes are all exercised for real.

What is not exercised: the real router's LINK fee handling, confirmation counts, finality assumptions,
rate limits, message-size limits, destination-side gas metering, behaviour when the destination
reverts, and off-chain operational failure.

**A difference in real-router behaviour does not fail loudly. It fails as propagation that quietly
stops** — which, given Finding B in the threat model, is the same shape of failure as two bugs already
found during development.

**What would close it:** a fork or testnet integration test against the real router, covering at
minimum: a successful delivery, an insufficient-fee failure, a destination revert, a message exceeding
a size limit, and a duplicate delivery. Plus an operational decision on how a router upgrade is treated
— a router upgrade is a security-relevant event, because the identity gate is only as strong as the
contract behind the address.

### G5 — `currentAllocation` is a caller-supplied argument

**Severity: high.** An integrator-facing correctness and security gap, not a contract bug.

`AccessRequest` carries `currentAllocation` as a caller-supplied argument because allocation lives in
the pool's own accounting and duplicating it would create two sources of truth that drift. That is a
defensible design choice, and it is documented in the SDK.

The consequence: `maxAllocationPerInvestor` is only as good as the value passed. An integrator that
passes `0` gets the cap checked against the increment alone:

```solidity
uint256 total = request.currentAllocation + request.requestedAmount;
```

A holder already at the cap then adds another full cap's worth. Mutation
`M10-allocation-cap-ignores-current-holding` proves the module's own arithmetic is covered; nothing
covers an integrator lying about the input.

**What would close it:** an optional per-pool `allocationOracle` address on `PoolPolicyManager` that
the module queries for `currentAllocation`, falling back to the caller-supplied value when unset. The
cap becomes self-enforcing for pools that configure it, and the caller-supplied path remains for pools
that do not.

**Interim guidance:** the SDK's `AccessRequest.currentAllocation` doc comment says "**The caller must
supply this truthfully** — the cap is only as good as this value." An integrator integrating a pool
with a non-zero `maxAllocationPerInvestor` must read allocation from the pool's accounting, never from
a client-supplied value.

### G6 — No formal verification

**Severity: medium.** Properties are tested, not proved.

The central promise — only `Valid` may produce an `Allow` — is stated as
`invariant_allowRequiresEveryPrecondition`, which re-derives every condition independently of
`_evaluate`'s ordering. That is genuinely stronger than a test asserting a specific reason code. It is
not a proof.

**What exists:** 13 mutation definitions covering the main behavioural defects, all caught; 14
invariants; 237 deterministic tests across nine suites; a two-deployment fixture that exercises the
real replica path rather than a mock of it.

**What does not:** no Halmos, Certora, or solc-in-a-box proofs. No mechanised property that "for all
sequences of length n, `evaluate` returns `Allow` only if ...".

**What would close it:** model `_evaluate` in a verifier and prove `Allow ⟹ Valid ∧ activePolicy ∧
providerBacks ∧ jurisdictionOK ∧ classOK`. The function is `view` and side-effect free, which makes it
a tractable target — one of the easier contracts in the repository to verify. The registry's
transition table is the other tractable target: a small pure function whose reachable-state space is
finite.

### G7 — No gas benchmarks

**Severity: medium.** Nothing in this repository is a gas budget.

Measured sizes exist (`check-contract-sizes.mjs`: largest is `ComplianceGateway` at 11524 bytes
against a 24576 limit), so the bytecode-size risk is understood. The *execution* cost is not.

**What would close it:** `forge snapshot` committed to the repository, plus a documented budget per
operation — issuance, `evaluate`, `evaluateAndRecord`, `revoke`, `renew`, `expireDue` at
`MAX_SWEEP_BATCH`, and CCIP fan-out at `MAX_DESTINATIONS`. Those two batched operations are the ones
most likely to surprise: `expireDue` at 100 records and `sendCredentialState` at 10 destinations are
the cost cliffs, and both interact with the block gas limit in a way nobody has measured.

### G8 — No formal spec-to-code traceability

**Severity: medium.** `ENGINEERING_SPEC.md` and `PRD.md` describe the system in prose. Nothing
mechanically ties a requirement to a contract, a function, or a test.

An auditor reading the spec and the code must do this by hand, which is where gaps hide.

**What would close it:** a requirements table with one row per spec requirement, each naming the
contract, the function, and the test that covers it. Maintain it in CI: fail when a requirement has no
linked test. The mutation harness is already the mechanism for the reverse direction — it proves a
behaviour is covered; a traceability matrix would prove nothing is *absent*.

### G9 — The invariant suite is sampled over sequences, exhaustive over keys

**Severity: medium.** Stated in the suite's own documentation and repeated here so it is not
over-claimed.

**What is exhaustive:** the key space. `4 subjects × 3 classes × 3 jurisdictions = 36` credentials
against 2 pools, enumerated in full inside every invariant. A sampled invariant could miss the one
misconfigured credential; this one cannot.

**What is sampled:** sequences. The fuzzer explores `runs × depth` random action sequences
(64 × 32 default, 128 × 64 in CI). No two runs explore the same sequences, so a defect reachable only
from a specific ordering may not be found.

**What would close it:** raise CI to 256 × 128 and accept the runtime cost, or add a directed
generator that constructs the specific orderings the design cares about — renew-after-revoke,
resume-after-suspend, reissue-after-expiry, policy-supersede-during-review.

### G10 — The invariant handler cannot reach two system states

**Severity: medium.** A coverage limit in the test infrastructure, stated because an auditor will
find it.

`ComplianceLifecycleHandler` deploys one system with `NUM_SUBJECTS = 4` and `NUM_POOLS = 2`. It has
no propagation, so:

- **`revoke` after a replica.** The handler never propagates, so no credential in the invariant
  fixture is ever a replica. `invariant_locallyIssuedCredentialsAreNeverReplicas` asserts exactly that
  and is correct, but nothing in the invariant suite exercises a revocation reaching a destination.
  That is covered only by the deterministic `CrossChainPropagation.t.sol` suite (42 tests).
- **Policy supersession under load.** `activatePolicyVersion` needs a 7-day warp, so the handler
  rarely reaches a second active version. `invariant_atMostOneActivePolicyVersionPerPool` therefore
  mostly tests the single-version case.

**What would close it:** a second invariant fixture deploying source and destination systems sharing a
mock router, so cross-chain invariants hold alongside the local ones. The deterministic suite already
proves these paths; the invariant suite would prove they hold in combination.

### G11 — `reason` on lifecycle calls is unvalidated

**Severity: low.** `revoke(ccid, poolId, reason, destinations)`, `suspend(ccid, reason, ...)`, and
`resume(ccid, reason, ...)` accept an arbitrary `bytes32`, unvalidated against
`ComplianceTypes.allReasons()`.

The privacy argument still holds — 32 bytes of arbitrary content is not a readable name, and
`reasonToString` reports `UNRECOGNIZED` for anything not in the list, so
`test_ReasonCodesAreTheOnlyThingStoredAsText` passes because the *stored* value is a hash either way.
The audit entry cannot be scrubbed, though, so an arbitrary value lands permanently.

**What would close it:** validate against `allReasons()` and add a separate bounded free-text field
for operators, clearly marked as non-auditor-facing. Or emit an event when an unrecognised reason is
used, so monitoring can flag it.

### G12 — `receiveMessage` is a second entry point to `_accept`

**Severity: low.** `CrossChainComplianceReceiver.receiveMessage` is `public` and applies every check
in `_accept` **except** `msg.sender == ROUTER`. Its stated purpose is testability and local relay.

It is not a bypass of `_accept`'s rules — binding hash, source allowlist, nonce, local-authority, and
provider checks all still apply — but it is a reachable path to `_accept` that the router-identity
gate does not cover.

**What would close it:** restrict it to test deployments (constructor flag or a separate test-only
contract), or gate it behind an immutable "relay mode" set at construction and documented as
trust-expanding.

### G13 — No secrets management, no rehearsal

**Severity: low operationally, high if ignored.** There is no key inventory, no rotation runbook, no
rehearsal of any incident procedure in
[`incident-response.md`](./incident-response.md), and no live environment.

The `WORKFLOW_SUBMITTER`, `ISSUER`, `ADMIN`, `GUARDIAN`, `TIMELOCK_ADMIN`, `PROVIDER_ADMIN`,
`ISSUER_ADMIN`, and audit-trail admin keys are all either raw deployer-controlled addresses or
`DEFAULT_ADMIN_ROLE` holders in one of the four `AccessControl`-based contracts
(`ProviderRegistry`, `PoolPolicyManager`, `AuditTrail`, `EmergencyControls`).

Two specifics worth checking in any real deployment: `GUARDIAN` must differ from `ADMIN` (the deploy
script refuses it) and both should be multisigs; and `ComplianceGateway`'s constructor grants
`ADMIN`, `WORKFLOW_SUBMITTER`, and `ISSUER` to the same deployer address, which must be rotated to
distinct addresses before any real use.

**What would close it:** a key inventory naming every role, its expected form, its holder, and its
rotation procedure; a quarterly rehearsal of the pause, unpause, provider-revocation, and
role-rotation procedures against a testnet.

### G14 — No legal or regulatory review

**Severity: blocker.** Outside this repository's competence and outside an auditor's.

Whether this design satisfies any jurisdiction's securities, AML, or privacy requirements is a
question for qualified counsel. Nothing in this repository, its tests, or its documentation answers it.

**What would close it:** external counsel review scoped to: whether a `jurisdictionCode` +
`investorClass` credential is sufficient for the jurisdictions in scope; whether the privacy model
satisfies applicable data-protection requirements; whether the audit trail satisfies record-keeping
obligations; and whether the accreditation determination delegated to providers is acceptable in each
jurisdiction.

## 3. What does exist

Stated so the gaps are read in proportion.

| Area | Status |
| --- | --- |
| Unit and integration tests | 237 deterministic tests across 9 Solidity suites, on a two-deployment fixture that exercises the real replica path rather than a mock of it |
| Invariants | 14 properties, exhaustive over a 36-credential key space, sampled over sequences; plus 3 handler-coverage tests proving the fuzzer reaches the states the invariants depend on |
| Mutation testing | 13 mutations, all caught (see §4) |
| Code quality | `forge fmt --check`, `forge lint` with a documented exclusion list, `forge build --sizes` |
| Size budget | EIP-170 gate; largest contract at 11524 of 24576 bytes, with a 200-byte near-limit failure |
| Privacy (storage shape) | `check-no-dynamic-storage.mjs`, walking the compiled `types` graph, with a verified mutation procedure |
| Privacy (storage values) | Field-by-field assertions in `AuditTrail.t.sol` |
| Privacy (source names) | CI grep for identity-bearing field names in `contracts/src/**` |
| Privacy (repository hygiene) | CI check for secret-like filenames, CRLF, and unverified claims in docs |
| Cross-chain wire format | 22 tests including round-trip, truncation, trailing junk, overflow, and tamper |
| CCID parity | Vectors generated from the contract, with a CI freshness check |
| Deployment | A script that asserts its own postconditions rather than logging them |
| Documentation | Architecture, privacy model, policy schema, provider guide, runbook, incident response, threat model, this file |

## 4. Mutation testing

### 4.1 Running it

```bash
node scripts/mutation-check.mjs
```

Set `FORGE_BIN` if `forge` is not at `%USERPROFILE%/.foundry/bin/forge.exe`. Exits `1` if any
mutation survives unexpectedly, `2` if `forge` is not found.

Expect roughly 15 full `forge test` runs. Not fast.

### 4.2 What it does

Each mutation introduces one real defect, runs the suite, expects a failure, and restores the source.
A mutation that still passes is a hole in the suite.

The harness snapshots every file it will touch into a temp directory outside the repository, and
restores on normal exit, on `SIGINT`, on `SIGTERM`, and on a crash mid-run. It also runs a **baseline
first**: nothing below means anything unless the suite is green to begin with.

### 4.3 Why the full suite, not just the invariants

Each mutation declares the scope it needs, and that is not a convenience. Several properties here are
genuinely unobservable from one chain. `setStatus` stopping to bump the nonce leaves the source chain
completely correct — the credential *is* `Revoked` there — and the damage appears only on a
destination that discards the message as stale. An earlier version of this harness reported that
mutation as surviving for exactly that reason.

### 4.4 The 13 mutations

| ID | Injected defect | Why it matters |
| --- | --- | --- |
| `M1-pending-allows` | `Pending` reported as `REASON_OK` | A provisional allow is the failure the whole design exists to prevent. |
| `M1b-pending-allows-no-provider-backstop` | Both the `Pending` fix and the provider backstop removed at once | The realistic version of M1. M1 alone is caught only because `PolicyEvaluation.t.sol` asserts the provider backstop explicitly. |
| `M2-revoked-resurrects` | `Revoked` no longer terminal | A revoked credential could return to `Valid`. |
| `M3-stale-nonce-renewal` | `renew` accepts a non-increasing nonce | The replay guard on renewal is gone. |
| `M4-policy-version-overwritable` | Every registration overwrites version 1 | An integrator's pinned version becomes meaningless, and the activation delay loses its point. |
| `M5-untrusted-provider-allows` | `backsExistingCredentials` returns `true` always | A revoked provider's existing credentials still pass policy. |
| `M6-status-change-does-not-bump-nonce` | `setStatus` does not advance the nonce | Every destination discards a revocation as stale. Undetectable on one chain — Finding B. |
| `M7-replica-overwrites-local-authority` | The `LocalIssuerOverride` check disabled | A compromised source chain could restore `Valid` over local state. The outcome the system exists to make impossible. |
| `M8-binding-hash-unverified` | The `bindingHash` comparison disabled | A payload edited after the sender signed it would be accepted. |
| `M9-deprecated-provider-invalidates` | `Deprecated` treated as distrust | The opposite error to M5: a routine provider migration invalidates every live credential. |
| `M10-allocation-cap-ignores-current-holding` | Cap checked against the increment | A holder already at the cap adds another full cap's worth. |
| `M11-activation-delay-removed` | A policy activates immediately | No notice window — the attack the 7-day delay exists to prevent. |
| `M12-unpause-immediately-executable` | The unpause delay check disabled | A scheduled unpause executes before its 24 hours elapse. |

**All 13 are caught.** M5 and M9 are the pair that matters most for reading the table: they are
opposite errors in the same function, and the suite catches both.

### 4.5 Adding one

1. Add an entry to the `mutations` array in `scripts/mutation-check.mjs`:

```javascript
{
  id: "M13-descriptive-short-name",
  why: "one sentence: what defect this introduces",
  scope: "full",
  note: "optional: why this case is not obvious",
  edits: [
    {
      file: "contracts/src/SomeContract.sol",
      from: "the exact source line to replace",
      to:   "the mutated line",
    },
  ],
}
```

2. The `from` string must be unique enough in the file to identify one site, and must match the source
   byte for byte. If it does not match, the harness reports `anchor not found` and exits `1` rather
   than silently skipping — the source moved, update the script.

3. A `note` is worth writing when the case is not obvious. Several existing mutations carry one, and
   they are the ones a future reader would otherwise think are redundant.

4. `expect` exists for a mutation that is *known* to survive and is recorded as a known gap. Nothing
   currently uses it, and the summary comment at the end of the file referring to M1 as
   "documented as surviving by design" is stale — M1 is caught, via M1b's realistic pairing.

5. Multiple `edits` are applied together and the restore is atomic per mutation. Snapshots are keyed
   by `${m.id}__${basename(edit.file)}`, so two mutations touching the same file stay distinct and a
   restore cannot cascade.

### 4.6 Two properties the harness has to get right

**Failure detection reads the output, not the exit code.** `spawnSync` with `shell: true` goes through
`cmd.exe`, whose status does not reliably reflect `forge`'s own. An earlier version trusted
`status !== 0` and reported ten mutations as "survived" while the very next line printed the test that
had failed for each. The harness now parses forge's summary line
(`Ran N test suites: N tests passed, N failed`) and falls back to counting `[FAIL:` markers.

**The invariant must not be expressed in terms of the function under test.**
`invariant_untrustedProviderCannotAllow` originally delegated to `backsExistingCredentials`, so the
mutation M5 silenced the very invariant written to catch it. It now reads `getProviderStatus` directly
and derives trust from the status enum — an independent input.

## 5. What an auditor should be asked to prioritise

1. **G1** — is a per-credential-only revocation path acceptable for the intended scale, or is bulk
   revocation a launch blocker?
2. **G2** — is a non-zero `evidenceHash` an acceptable evidentiary position, or is a signed provider
   attestation (option 2) required before any pilot?
3. **G5** — is a caller-supplied `currentAllocation` acceptable with documented integrator guidance, or
   is an `allocationOracle` required?
4. **A6** — is the `LocalIssuerOverride` check sufficient against a compromised source chain, and does
   the "replica can never improve local state" invariant hold under all orderings?
5. **A7** — is "can refuse, cannot mint" the right characterisation of a compromised workflow's
   capability, and is the destination-selector gap (R2) acceptable?
6. **G6** — which properties are worth proving formally, given that `_evaluate` is `view` and the
   transition table is a small pure function?

## 6. Honest closing statement

What this repository demonstrates:

- A coherent design in which the central invariant — only `Valid` may allow — is enforced in one place
  and re-derived independently in a property check.
- A test suite that catches thirteen specific classes of realistic defect, including two propagation
  bugs found during development.
- A privacy model whose structural claims are mechanically enforced against compiled storage layout,
  with a verified procedure for proving the check works.
- Honest documentation of what the system does not do.

What it does not demonstrate:

- That any of it is correct. **No audit exists.**
- That it works against real infrastructure. **No deployment exists; the router is mocked.**
- That it works with a real provider. **No adapter exists.**
- That it satisfies any regulation. **No legal review exists.**

The contracts are written and the tests pass. Everything past that is a gap, and the gaps above are
ranked so that a decision about commissioning an audit can start from the most severe rather than
from the most interesting.