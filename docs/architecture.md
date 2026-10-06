# Architecture

This document describes how the contracts fit together, why each boundary exists, and which
design choices are load-bearing. It is engineering documentation for a reviewer. It is not a
claim about deployment, audit status, or regulatory compliance — none of those exist in this
repository. See [`audit-readiness.md`](./audit-readiness.md).

## 1. What the system is

A privacy-conscious compliance credential layer for tokenized real-world-asset pools. A pool asks
"may this holder access this pool?" and receives a three-way decision with a reason code:
`Allow`, `Deny`, or `ReviewRequired`. No investor personal data reaches chain state.

Two facts frame every design decision:

1. The Chainlink CRE workflow that performs verification runs **off-chain**, outside any boundary
   the contracts can reason about. A workflow bug, a compromised runner, or a replayed request must
   not be able to mint a credential that passes policy. So the gateway re-derives and re-checks
   everything it is handed.
2. The access decision does not need the investor. It needs to know "this credential, presented by
   this holder, represents a US-accredited investor under jurisdiction 840" — which is expressible
   as two small integers. Everything else is deliberately off-chain.

## 2. Components

| Contract | Responsibility | Holds state? |
| --- | --- | --- |
| `ComplianceTypes` (library) | Enums, structs, 14 reason codes, `reasonToString` | No |
| `CCIDResolver` | Derives and verifies the credential content identifier | No |
| `ComplianceRegistry` | The **only** persistent home of credential state | Yes — 2 mappings + roles |
| `ProviderRegistry` | Provider adapters, schema support, operational status, health signals | Yes |
| `PoolPolicyManager` | Versioned, issuer-configured access policy per pool | Yes |
| `AuditTrail` | Append-only history for auditors | Yes |
| `EmergencyControls` | System-wide pause with a reason | Yes (2 scalars) |
| `ComplianceGateway` | Workflow intake, validation, lifecycle writes, propagation trigger | No (roles only) |
| `CrossChainComplianceSender` | Encodes and dispatches state over CCIP | Yes (2 mappings) |
| `CrossChainComplianceReceiver` | Accepts replicas and records them | Yes (4 mappings) |
| `PoolComplianceModule` | The access check a pool calls | No |
| `CompliancePayload` (library) | The single wire-format definition, binding hash | No |
| `ICCIPRouter` / `ICCIPReceiver` | Minimal local subset of the CCIP v2 interface | No |

`PoolComplianceModule` and `ComplianceGateway` are deliberately stateless. They hold only
`immutable` references and role mappings. Anything that needs to be durable belongs in
`ComplianceRegistry`, and the reason for that is not tidiness — it is blast radius.

## 3. Dependency graph

```
                    EmergencyControls
                          |
        +-----------------+------------------+
        |                                    |
   ComplianceGateway                  PoolComplianceModule
     |      |      |                        |     |     |
     |      |      +--> PoolPolicyManager <-----+-----+  (reads policy)
     |      +---------> ProviderRegistry <------------+  (reads provider)
     |      +---------> CCIDResolver
     |      +---------> AuditTrail
     |      +---------> CrossChainComplianceSender
     +----------------> ComplianceRegistry <---- CrossChainComplianceReceiver
                            ^                        |
                            +------------------------+
                          (WRITER_ROLE)

   CrossChainComplianceSender ---> ICCIPRouter ---> (CCIP) ---> CrossChainComplianceReceiver
   CrossChainComplianceReceiver  ---> ProviderRegistry
   CrossChainComplianceReceiver  ---> CompliancePayload
   PoolComplianceModule         ---> AuditTrail
   PoolPolicyManager             ---> (extends AccessControl)
   ProviderRegistry              ---> (extends AccessControl)
   AuditTrail / EmergencyControls ---> (extends AccessControl)

   ComplianceTypes  <-- imported by every contract
   CompliancePayload <-- imported by sender, receiver, gateway
```

Note what is **not** in the graph: no contract holds a reference to another issuer's registry, and
the receiver does not reference the gateway. The two chains are independent deployments; the only
trust relationship between them is the receiver's `ALLOWED_SOURCE_SENDERS` and
`ALLOWED_SOURCE_CHAINS` maps, which are operator-configured per destination.

### 3.1 Split writer authority

`ComplianceRegistry` holds no admin key that can write credential state. Exactly two addresses hold
`WRITER_ROLE`:

1. `ComplianceGateway` — source of truth on the issuing chain.
2. `CrossChainComplianceReceiver` — records replicas arriving via CCIP.

The split is a security property, not an organizational one. A compromised gateway cannot forge
destination state, because it has no writer there; a compromised receiver cannot invent issuance,
because it cannot compute a valid `ccid` (it does not hold the subject commitment — see §6.4).

### 3.2 The two circular dependencies

Neither cycle can be satisfied by a constructor argument list, because each contract must hold the
other's address.

#### Cycle 1: gateway ↔ sender

The gateway dispatches propagation (`SENDER.sendCredentialState`); the sender must know which
gateway is allowed to dispatch (`msg.sender != bridge` → `NotBridge`).

Broken by deploying the sender **first** with an unset bridge, then calling
`CrossChainComplianceSender.initializeBridge(gateway)` once the gateway exists.

Why this is safe:

| Property | Mechanism |
| --- | --- |
| One-way | The gateway holds the sender as `immutable SENDER`; the sender has a mutable `bridge`, but only ever set once |
| Deployer-only | `if (msg.sender != ADMIN) revert NotAdmin(msg.sender)` |
| Exactly once | `if (bridgeInitialized) revert BridgeAlreadyInitialized(bridge)` |
| Fails quiet, not wrong | An unbound sender propagates nothing rather than propagating to the wrong caller (`test_UnboundSenderPropagatesNothing`) |

`initializeBridge` is permanent by design. A rebindable sender would let a compromised deployer
role redirect credential propagation at any later moment — including onto a chain the issuer never
intended to reach. `test_BridgeBindingIsOneTimeAndPermanent` pins this.

#### Cycle 2: receiver ↔ registry

The receiver writes to the registry, so it needs `WRITER_ROLE`. The role is granted to an address
that does not exist until after its constructor returns.

Broken by a separate `registry.setWriter(receiver, true)` followed by
`CrossChainComplianceReceiver.wire()`.

`wire()` is not a formality — it is the verification step:

```solidity
function wire() external {
    if (msg.sender != ADMIN) revert NotAdmin(msg.sender);
    if (wired) revert AlreadyWired();
    if (!REGISTRY.isWriter(address(this))) revert NotRegistryWriter(address(this));
    wired = true;
}
```

And every inbound path refuses while `wired == false` (`if (!wired) revert NotWired();` inside
`_accept`). So a deployment that skipped the `setWriter` produces a receiver that rejects
everything loudly, rather than one that accepts messages and silently writes nothing. The silent
version is the worst failure mode available here: it looks healthy while losing credential state.
`test_UnwiredReceiverRefusesEverything` and `test_WireRequiresRegistryWriterRole` cover both
directions.

### 3.3 The step that is easy to miss

`AuditTrail.authorizeRecorder(gateway)` and `authorizeRecorder(module)` are separate deployer calls.
The gateway **cannot** self-authorize: the trail authorizes by *admin*, and the gateway is not its
admin. Until both calls are made, every issuance and every recorded decision reverts on the audit
hook.

This is the correct failure direction. A gateway that cannot record its own history is worse than
one with no history at all, because the gap is invisible until someone audits. `Deploy.s.sol` performs
the step and asserts the result with `require(gateway.isAuditAuthorized(), ...)`.

`AuditTrail` being `address(0)` is also tolerated (`_recordAudit` returns early), which is what lets
a deployment ship without one. Once configured, a genuine revert is deliberately **not** swallowed:
an audit trail that silently stops recording is worse than none, because an auditor cannot
distinguish "no events occurred" from "the hook is broken".

## 4. Issuance path, end to end

### 4.1 Optional: open a `Pending` record

```
WORKFLOW_SUBMITTER → ComplianceGateway.beginVerification(ccid, credentialType, schemaVersion, ttlSeconds)
                    → EMERGENCY.isPaused()            → SystemPaused
                    → REGISTRY.registerPending(...)   → CredentialAlreadyExists
```

`registerPending` writes a record with `providerId = 0`, `evidenceHash = 0`,
`jurisdictionCode = 0`, `investorClass = Unknown`, `nonce = 0`. The holder can then see "your check
is running" instead of `NO_CREDENTIAL`, which is indistinguishable from "never requested".

`Pending` **denies** access. It is not a provisional allow. Treating it as "probably fine" is
precisely the failure the design exists to prevent, and mutation `M1-pending-allows` in
`scripts/mutation-check.mjs` exists to prove the suite catches that mistake.

### 4.2 The submission

```
WORKFLOW_SUBMITTER → ComplianceGateway.submitCredentialResult(CredentialResult)
```

`CredentialResult` is a `calldata` struct. The gateway then, in order:

| # | Check | Revert |
| --- | --- | --- |
| 1 | `EMERGENCY.isPaused()` | `SystemPaused` |
| 2 | `onlyRole(WORKFLOW_SUBMITTER)` (modifier) | `NotAuthorized` |
| 3 | `ccid == CCID_RESOLVER.compute(...)` | `InvalidCCID(claimed, expected)` |
| 4 | `PROVIDERS.isActive(providerId)` | `ProviderNotActive` |
| 5 | `credentialType != 0` | `CredentialTypeNotRegistered` |
| 6 | `PROVIDERS.supportsSchema(providerId, credentialType, schemaVersion)` | `ProviderNotAdmitted` |
| 7 | `expiresAt > block.timestamp` | `ExpiryNotInFuture` |
| 7 | `issuedAt <= block.timestamp + MAX_CLOCK_SKEW_SECONDS` (5 min) | `IssuanceTooSkewed` |
| 8 | `jurisdictionCode != 0` | `JurisdictionUnset` |
| 8 | `investorClass != Unknown` | `InvestorClassUnknown` |
| 9 | `evidenceHash != 0` | `ZeroEvidenceHash` |
| 10 | nonce strictly increases for this CCID | `NonceNotIncreasing` |

Steps 3–9 are the on-chain re-derivation. Step 10 is enforced in two places: the gateway compares
against the current record before calling, and `resolvePending` / `issue` / `renew` each re-check.
The duplication is deliberate — the registry is a separate trust domain and must not assume its
caller checked.

**What a compromised workflow cannot do.** Steps 4–8 mean it can *refuse* a credential but cannot:

- invent one (the CCID must reproduce, and the fields are the preimage)
- extend a credential's life (`renewCredential` runs the identical `_validate`)
- misstate a jurisdiction (jurisdiction is in the CCID preimage — `test_JurisdictionSwapRejected`)
- attribute a credential to a paused provider (step 4)
- escalate an investor class (`test_InvestorClassEscalationRejected`)

Its worst outcome is denial of service, which is bounded and recoverable by rotating the role. Note
what that is **not**: it cannot mint. See
[`incident-response.md`](./incident-response.md#b-compromised-workflow-submitter-key).

### 4.3 Writes

If `REGISTRY.exists(ccid)` the gateway resolves a `Pending` record; otherwise it issues a new one.
Either way the record lands with `status = Valid`, and `issuedAt` / `expiresAt` / `nonce` come from
the result — the chain does not mint them itself, because the workflow is the authority on when
verification happened.

Then `_recordAudit`, then `_propagate`, then `CredentialResultSubmitted`.

## 5. Revocation path, end to end

```
revoke(ccid, poolId, reason, destinations)
  → EMERGENCY.isPaused()                    → SystemPaused
  → REGISTRY.getRecord(ccid).ccid != 0      → InvalidCCID
  → _requireRevocationAuthority(ccid, poolId) → RevocationNotPermitted
  → REGISTRY.setStatus(ccid, Revoked, reason)
       → transition table check              → IllegalTransition
       → status = Revoked; updatedAt = now; nonce += 1
  → _recordAudit(ccid, poolId, reason, Revoked)
  → _repropagate(...)  // re-reads the record to get the BUMPED nonce
  → CredentialLifecycleAction(ccid, "revoke", Revoked, reason)
```

Two details carry the whole design.

**`setStatus` bumps the nonce.** `r.nonce += 1` on every accepted transition. Without it, a
revocation would carry the same nonce as the issuance it reverses, and every destination would
discard it as stale — leaving a revoked credential valid everywhere it had propagated, while the
source chain correctly reported `Revoked`. This was a real bug during development; see
[`threat-model.md`](./threat-model.md#finding-b-setstatus-did-not-bump-the-nonce).

**`_repropagate` re-reads the record.** Propagating the pre-bump nonce would produce exactly the
same failure. `revoke` explicitly does `REGISTRY.getRecord(ccid)` a second time after the status
change and propagates `fresh.nonce`.

### 5.1 Revocation authority

Scoped by pool, because revocation authority is a property of the policy that admitted the holder —
not a property of the credential.

| Caller role | Admitted? |
| --- | --- |
| `HOLDER` | Always. A holder must always be able to exit; anything else is a trap. Checked **before** policy is consulted. |
| `ADMIN` (governance) | Always. |
| `ISSUER` | Yes, **unless** the active policy for `poolId` is `RevocationMode.GovernanceOnly`. |
| `ISSUER` with no active policy | Yes. Keeps single-pool deployments working before policies are configured. |
| Anyone else | No — `RevocationNotPermitted`. |

`GovernanceOnly` deliberately excludes the issuer: a governance-scoped credential the issuer could
withdraw unilaterally would not be governance-scoped.

### 5.2 There is no separate revocation fast path

Issue, renew, suspend, resume, expire, and revoke all go through
`CrossChainComplianceSender.sendCredentialState`. A channel that only sometimes exists is precisely
how a revoked credential ends up still looking valid somewhere.

## 6. Access-decision path

`PoolComplianceModule._evaluate` is the single implementation. Both public entry points funnel
through it, so the documented precedence order is the only order that can ever run:

- `evaluate(request)` — `view`, no state change, no event. This is what makes a preview possible
  (`eth_call`).
- `evaluateAndRecord(request)` — non-view. Emits and records **allows and review-required only**.

### 6.1 Precedence order

First failure wins.

| # | Condition | Reason code | Decision |
| --- | --- | --- | --- |
| 1 | `EMERGENCY.isPaused()` | `SYSTEM_PAUSED` | Deny |
| 2 | `!POLICIES.hasAnyPolicy(poolId)` | `POOL_NOT_REGISTERED` | Deny |
| 3 | `!POLICIES.hasActivePolicy(poolId)` | `POLICY_INACTIVE` | Deny |
| 3 | `!policy.registered \|\| !policy.active` (re-read) | `POLICY_INACTIVE` | Deny |
| 4 | status `Unknown` | `NO_CREDENTIAL` | Deny |
| 5 | status `Pending` | `PENDING` | Deny |
| 6 | status `Revoked` | `REVOKED` | Deny |
| 7 | status `Suspended` | `SUSPENDED` | Deny |
| 8 | status `Expired` | `EXPIRED` | Deny |
| 9 | `!PROVIDERS.backsExistingCredentials(providerId)` | `PROVIDER_PAUSED` | Deny |
| 10 | `!POLICIES.isJurisdictionAccepted(...)` | `JURISDICTION_BLOCKED` | Deny |
| 11 | `!POLICIES.isInvestorClassAccepted(...)` | `INVESTOR_CLASS_BLOCKED` | Deny |
| 12 | `policy.requiresFreshReplica && isReplica && ageOf > tolerance` | `STALE_DESTINATION` | Deny |
| 13 | `requestedAmount != 0 && exceedsAllocationCap(current + requested)` | `ALLOCATION_CAP_EXCEEDED` | Deny |
| 14 | `policy.requiresManualReview` | `MANUAL_REVIEW_REQUIRED` | ReviewRequired |
| 15 | — | `OK` | Allow |

Three orderings are deliberate:

- **`REVOKED` before `EXPIRED`.** Revocation is the stronger, more deliberate signal, so it is
  reported even when the credential has also lapsed. `_statusReason` encodes this.
- **`STALE_DESTINATION` after eligibility, before allocation.** The most useful thing to tell a
  holder is "we cannot currently confirm your eligibility", not "you are over your cap", which they
  may dispute.
- **`MANUAL_REVIEW_REQUIRED` last.** A review requirement is a routing instruction, not a defect, so
  it must never mask a real denial.

`POOL_NOT_REGISTERED` and `POLICY_INACTIVE` are two codes rather than one because they demand
different responses: "never configured" is an integration bug on the integrator's side, "configured
but switched off" is a deliberate operational state that resolves itself. Collapsing them would make
a pool operator deactivating a policy look like a broken integration.

### 6.2 The freshness tolerance default

```solidity
uint64 tolerance = policy.maxReplicaAge == 0 ? 1 days : policy.maxReplicaAge;
```

`maxReplicaAge == 0` means "one day" here, not "no tolerance". Setting `requiresFreshReplica = true`
and forgetting the age therefore yields a usable policy rather than one that denies every replica
permanently.

### 6.3 `isCredentialEligible` is not an access gate

It answers "is the credential itself in good standing" — status plus provider backing. It ignores
pool policy, allocation, and review requirements, because those are properties of the *request*, not
of the credential.

Written as a direct check rather than by reinterpreting `evaluate`'s output: inferring credential
health from a pool-specific decision means a holder on a pool with no active policy looks
credential-ineligible, which is both wrong and alarming.

### 6.4 Why the pool cannot call `registry.isValid` directly

`isValid` is `true` for a credential whose provider has since been paused, for one whose
jurisdiction the pool does not accept, and for a replica this chain last heard from weeks ago. It is
one necessary condition being treated as sufficient. `PoolComplianceModule` exists so that a
partial implementation is not something an integrator can accidentally write.

### 6.5 Denials are deliberately not emitted

`evaluateAndRecord` emits `AccessAllowed` and `AccessReviewRequired` and nothing for `Deny`. An
emitted denial would let anyone inflate a holder's public denial history by probing repeatedly, and
the view function already returns the reason to the caller. `AuditTrail.recordDecision` does support
`EntryKind.AccessDenied`, available to a permissioned compliance officer for denials they resolve.

This is a monitoring cost the design accepts deliberately. See
[`operations-runbook.md`](./operations-runbook.md#5-monitoring).

## 7. Credential identity: the CCID

```solidity
ccid = keccak256(abi.encode(
    DOMAIN,                              // keccak256("rwa-compliance-gateway/CCID/v1")
    credentialType,
    uint256(schemaVersion),
    providerId,
    uint256(jurisdictionCode),
    uint8(investorClass),
    subjectCommitment
));
```

`DOMAIN` and the field order are frozen together. `abi.encode` rather than `abi.encodePacked` is
required: packed encoding would silently truncate the `uint32`/`uint64`/`uint16` inputs and let two
distinct credentials collide. The SDK mirrors this with `encodeAbiParameters` and the same
parameter order (`packages/sdk/src/ccid.ts`).

**The nonce is deliberately excluded.** A CCID is what integrators and holders store, and what
propagates across chains. If renewal produced a new CCID, every renewal would strand the previous
credential on every destination as a dangling, still-`Valid` record — unreachable by any revocation,
because nothing would know its new name. Replay protection is the `nonce`, which lives on the record
and must strictly increase. Keeping the two concerns separate is what makes both correct.
`test_CcidDoesNotDependOnNonce` pins it.

`jurisdictionCode` and `investorClass` are in the preimage so a holder cannot present a
US-accredited attestation as a UK professional one. Both are coarse buckets, so binding them costs
no privacy.

Parity between the contract and the TypeScript derivation is enforced by generated vectors:
`contracts/script/GenerateCcidVectors.s.sol` emits values from `CCIDResolver.compute`,
`scripts/generate-ccid-vectors.mjs` writes `workflows/test/vectors/ccid.json`, and CI fails if the
committed file differs from a fresh generation.

## 8. Cross-chain message format

`CompliancePayload` is the single definition, imported by both the sender and the receiver. Two
definitions of a wire format drift: a field is added on one side and the other silently mis-decodes,
or `abi.decode` reverts deep inside a callback where attribution is hard.

### 8.1 Field order (frozen)

13 words, 416 bytes (`ENCODED_LENGTH`), all statically sized:

| Index | Field | Type | Notes |
| --- | --- | --- | --- |
| 0 | `ccid` | `bytes32` | |
| 1 | `credentialType` | `bytes32` | |
| 2 | `providerId` | `bytes32` | |
| 3 | `evidenceHash` | `bytes32` | |
| 4 | `schemaVersion` | `uint256` on the wire | Narrowed on decode |
| 5 | `jurisdictionCode` | `uint256` | Narrowed on decode |
| 6 | `issuedAt` | `uint256` | Narrowed on decode |
| 7 | `expiresAt` | `uint256` | Narrowed on decode |
| 8 | `nonce` | `uint256` | Narrowed on decode |
| 9 | `status` | `uint256` | Narrowed on decode |
| 10 | `investorClass` | `uint256` | Narrowed on decode |
| 11 | `sourceChainSelector` | `uint256` | Narrowed on decode |
| 12 | `bindingHash` | `bytes32` | |

`test_EncodedLengthMatchesTheFieldCount` asserts the constant equals the real encoded size rather
than trusting the comment.

**`subjectCommitment` is not in the payload.** The destination needs to answer "does a valid
credential exist for this CCID", and the CCID already binds it. Shipping the commitment would
publish a second, correlatable value per holder on every destination chain for no functional gain.

Because the commitment is absent, the receiver cannot re-derive the CCID. Integrity is established
by `bindingHash` instead: the sender commits to the message contents, the receiver recomputes and
rejects any mismatch.

### 8.2 Binding hash

```solidity
keccak256(abi.encode(
    PAYLOAD_DOMAIN,   // keccak256("rwa-compliance-gateway/propagation/v1")
    ccid, credentialType, providerId, evidenceHash,
    uint256(schemaVersion), uint256(jurisdictionCode), uint8(investorClass),
    issuedAt, expiresAt, nonce, uint8(status), sourceChainSelector
))
```

The sender is the **single authority** on this value. A caller-supplied `bindingHash` is discarded
and recomputed (`test_SenderIgnoresSuppliedBindingHashAndRecomputes`). So is `sourceChainSelector`:
a caller that could choose it could forge messages claiming to originate from another chain
(`test_SenderIsSoleAuthorityOnSourceChainSelector`).

The tamper test targets `jurisdictionCode` specifically. Tampering the source chain selector instead
would be caught by the chain-allowlist check regardless of the binding hash, so a test written that
way passes even with hash verification removed — which is exactly what the mutation harness
reported for an earlier version of that test.

### 8.3 Decode is defensive at three levels

1. **Exact length** (`data.length != ENCODED_LENGTH` → `BadLength`). A longer buffer would otherwise
   be accepted with a valid prefix and attacker-chosen trailing bytes.
2. **Explicit numeric bounds** before every narrowing conversion, so a maliciously wide word cannot
   wrap into a small plausible value.
3. **Enum range checks before conversion.** Solidity panics on an out-of-range enum conversion,
   which would turn malformed input into an unhandled panic rather than a named error.

`DecodeError` distinguishes `BadLength` (suggests a version mismatch) from `UnknownStatus` (suggests
a sender bug), because operators act on those differently.

### 8.4 Sender

`sendCredentialState(Message, destinations)` — `msg.sender` must be `bridge`. Rejects: empty
destination list, more than `MAX_DESTINATIONS` (10), nonce not increasing, unknown status, unknown
class, self-destination, system paused.

`lastSentNonce[ccid]` is written **before** the dispatch loop. A partially failed batch must not be
retryable with the same nonce, or a destination could be skipped silently while the retry appears to
succeed.

**No per-destination deduplication.** `sentTo[ccid][dest]` is a query, never a skip-list. See
[`threat-model.md`](./threat-model.md#finding-a-per-destination-dedup-made-revocation-impossible).

### 8.5 Receiver

`ccipMessageCallback` is the CCIP entry point. Validation, one attack per check:

| Check | Attack it stops | Error |
| --- | --- | --- |
| `msg.sender == ROUTER` | Direct calls bypassing CCIP | `NotRouter` |
| `EMERGENCY.isPaused()` | Writes during an incident | `SystemPaused` |
| `receivedSelector == receiveCredential.selector` | Misrouted call / wrong function | `UnknownSelector` |
| `ALLOWED_SOURCE_SENDERS[sender]` | Any address forging a payload | `UntrustedSourceSender` |
| `wired` | Accepting messages this contract cannot write | `NotWired` |
| `!consumedOrderIds[orderId]` | Replay of the same message | `ReplayedMessage` |
| `ALLOWED_SOURCE_CHAINS[m.sourceChainSelector]` | Message from an unexpected chain | `UntrustedSourceChain` |
| source chain ≠ own selector | Self-addressed message | `UntrustedSourceChain` |
| `bindingHash` recomputed | Payload altered after the sender signed it | `BindingHashMismatch` |
| `!exists \|\| isReplica` | Remote state overwriting local authority | `LocalIssuerOverride` |
| `PROVIDERS.backsExistingCredentials` | Reliance on a compromised provider | `ProviderUnavailable` |
| nonce strictly increasing | Out-of-order and replayed state | `NonceNotIncreasing` |

Rejections revert rather than silently dropping. In CCIP v2 that marks the message failed — an
operational signal the system would rather surface loudly.

`consumedOrderIds[orderId]` is written **last**, after every other check. If any check reverts the
whole transaction reverts, leaving the order id unconsumed so the message can be retried once an
operator has fixed the underlying cause, rather than being burned permanently.

`receiveMessage(orderId, sender, m)` is `public` and exists so the same rules can be exercised
directly in tests and by a local relay without impersonating the router. It performs the same
validation but **not** the router-identity check, which is why it is a deliberate testability
surface rather than a shortcut — see the adversary table in
[`threat-model.md`](./threat-model.md).

## 9. Storage layout notes

### 9.1 `ComplianceCredential` — 6 storage slots (192 bytes)

| Field | Slot offset | Width | Investor-shaped? |
| --- | --- | --- | --- |
| `ccid` | 0 | 32 | No — one-way content identifier |
| `credentialType` | 0 | 32 | No |
| `providerId` | 0 | 32 | No |
| `evidenceHash` | 0 | 32 | No — a commitment |
| `schemaVersion` | 0 | 4 | No |
| `jurisdictionCode` | 4 | 2 | **Coarse bucket — a country, not a person** |
| `investorClass` | 6 | 1 | **Coarse bucket — 4 values** |
| `status` | 7 | 1 | No |
| `issuedAt` | 8 | 8 | No |
| `expiresAt` | 16 | 8 | No |
| `updatedAt` | 24 | 8 | No |
| `nonce` | 0 | 8 | No |

Two investor-shaped values in 96 bytes of packed state, and neither is an identity. See
[`privacy-model.md`](./privacy-model.md).

### 9.2 `PoolPolicy` — 7 slots (224 bytes)

`poolId`, `version`/`active`/`registered`/`requiresManualReview`/`requiresFreshReplica` pack into
slot 0's neighbours; `effectiveAt` and `createdAt` share a slot. The two dynamic arrays
(`acceptedJurisdictions`, `acceptedInvestorClasses`) are the only free-form-shaped members anywhere
in the system, and they are `uint16[]` and `InvestorClass[]` — fixed-width elements. The privacy
check prints them for visibility rather than treating them as failures.

### 9.3 `Provider` — 4 slots (128 bytes)

`providerId`, `metadataURI`, `lastHeartbeat`, `failureCount`, `registeredAt`, `updatedAt`, `status`,
`registered`. `metadataURI` is the **single allowlisted free-form field** in the repository, bounded at
`MAX_METADATA_URI_LENGTH = 512`. It is a governance-chosen documentation pointer, not
investor-supplied. `scripts/check-no-dynamic-storage.mjs` names it explicitly so that a *second*
`string` on the same contract still fails.

`PoolComplianceModule` has **zero** storage entries — it is fully stateless apart from its `immutable`
references. `EmergencyControls` holds only `paused`, `unpauseExecutableAt`, and the roles mapping.

### 9.4 Allocation is deliberately absent

The registry stores no allocation. `AccessRequest.currentAllocation` is a caller-supplied argument,
because allocation lives in the pool's own accounting and duplicating it here would create two
sources of truth that drift. The cap is therefore only as good as the value the integrator passes —
stated as a gap in [`audit-readiness.md`](./audit-readiness.md).

### 9.5 Audit trail cost

One `Entry` is 192 bytes (6 storage slots): `ccid`, `poolId`, `actor`, `reasonCode`, `amount`, and
`timestamp` + `kind` packed together. That is expensive and deliberate — a log that can be rewritten is
not evidence. Deployments expecting very high decision volume should index off-chain from the emitted
events and use this contract for a sampled or policy-level subset.

### 9.6 Size budget

Measured from the compiled artifacts, EIP-170 limit 24576 bytes:

| Contract | Runtime bytes | Margin |
| --- | --- | --- |
| `ComplianceGateway` | 11524 | 13052 |
| `PoolPolicyManager` | 10721 | 13855 |
| `PoolComplianceModule` | 7356 | 17220 |
| `CrossChainComplianceReceiver` | 7135 | 17441 |
| `ComplianceRegistry` | 5880 | 18696 |

`scripts/check-contract-sizes.mjs` enumerates deployable contracts by walking `contracts/src`
rather than scanning `out/`, because Foundry names artifact directories after the *source file*, so
the artifact path carries no hint of whether a contract is deployable. It also fails a contract
within 200 bytes of the limit, because EIP-170 counts the runtime code as deployed but constructor
arguments are appended at deploy time.

## 10. Foundry configuration choices

From `foundry.toml`, each with the reason it is what it is.

### 10.1 Compiler

| Setting | Value | Reason |
| --- | --- | --- |
| `solc = "0.8.28"` | Pinned | CI and local runs produce identical bytecode. An unpinned compiler means an auditor's build and a production build may not be the same artifact. |
| `evm_version = "cancun"` | Pinned | Explicit target; the default drifts with the compiler version. |
| `optimizer = true`, `optimizer_runs = 200` | Moderate | 200 trades a little runtime gas for materially smaller bytecode, which matters more here because five contracts sit near enough to the EIP-170 limit that the choice is not free. |
| `via_ir = true` | Required | **Not cosmetic.** The compliance module's decision logic and the allocator's accounting touch more values than the legacy codegen keeps on the stack. The IR pipeline also yields smaller bytecode. |
| `bytecode_hash = "ipfs"`, `cbor_metadata = true` | On | Metadata is content-addressed rather than a raw URL to a mutable blob, so two builds with the same source produce the same metadata hash. |

### 10.2 Lint excludes

`lint_on_build = false` — advisory rather than a build side effect, so a real compiler error is not
buried in dozens of lint warnings. `forge lint` runs as its own CI step.

| Excluded | Reason |
| --- | --- |
| `unsafe-typecast` | Timestamps are narrowed from `uint256` to `uint64` because the on-chain schema fixes these fields at 64 bits. `block.timestamp` overflows `uint64` around the year 584942417355, so the truncation is unreachable. |
| `block-timestamp` | TTL, expiry, and review-window logic is time-based by definition; the tolerances here are orders of magnitude larger than validator influence. |
| `calls-loop` | CCIP fan-out issues one router call per destination, bounded by `MAX_DESTINATIONS`. |
| `require-revert-in-loop` | Destination validation rejects the whole batch rather than partially sending. Partial sends would leave a credential propagated to some chains and not others with no indication which. |
| `reentrancy-events` | External callees are immutable addresses fixed at deploy time, and nonce and allocation state are committed before the calls. |
| `environment-read-across-mutation` | Test-only: `vm.warp(block.timestamp + n)` is how a time-dependent test advances the clock, and every use warps forward from the current block. |
| `empty-block` | `receiveCredential` is an intentional CCIP dispatch target with no body; it exists so `selector()` has something to name. Enforcement lives in `ccipMessageCallback`. |
| `unused-return` | `_propagate` ignores the sender's message count by design. The count is derivable from the `CredentialSent` events, which are the audit record. |

One exclusion is interesting: `missing-events-access-control` is suppressed inline at
`ComplianceRegistry.setWriter` with a comment. `_grantRole` emits for the `WRITER_ROLE` grant path,
but the lint heuristic cannot associate a non-`role`-named event (`WriterAuthorizationChanged`) with
the `_roles` mapping, so it double-reports. The event **is** emitted on that line; the suppression
prevents a false positive that would otherwise pressure someone to remove the emit.

### 10.3 Test profiles

| Profile | Fuzz runs | Invariant runs × depth |
| --- | --- | --- |
| `default` | 256 | 64 × 32 |
| `ci` | 2048 | 128 × 64 |

The CI invariant size is set against the suite's real cost, not guessed. Each invariant does an
exhaustive sweep of the handler's reachable key space (36 credentials × 2 pools) after every handler
call, so runtime scales with `runs × depth × pairs`. 128 × 64 is roughly 4× the default and lands in
the low minutes; 256 × 128 would multiply that again for coverage the deterministic suites already
provide per-path.

`fail_on_revert = false` for invariants, because the handler picks from a bounded key space
(`NUM_SUBJECTS = 4`, `NUM_POOLS = 2`) precisely so collisions are the common case. With per-call unique
keys no compound path — renew-after-revoke, resume-after-suspend, reissue — would be reachable, and
the corresponding invariants would pass vacuously.

### 10.4 Remappings

```
forge-std/=lib/forge-std/src/
@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/
```

Two submodules, both fetched recursively by CI. The CCIP interface is **declared locally** rather
than vendored from `chainlink-contracts`, for two reasons: a reviewer can `forge build` with
`forge-std` alone without network access, and the security-relevant surface is three declarations —
so the thing an auditor reads is the thing that runs. Signatures match CCIP v2 exactly, so swapping
in the real router is a deployment-time address change.

## 11. Role model

| Contract | Role | Holder | Can |
| --- | --- | --- | --- |
| `ComplianceGateway` | `WORKFLOW_SUBMITTER` | CRE workflow | `beginVerification`, `submitCredentialResult`, `renewCredential` |
| | `ISSUER` | issuer key | `suspend`, `resume`; `revoke` unless `GovernanceOnly` |
| | `HOLDER` | holder keys | `revoke` their own credential, always |
| | `ADMIN` | governance | Grant/revoke all gateway roles; `revoke` anything |
| `ComplianceRegistry` | `WRITER_ROLE` | gateway, receiver | All credential writes |
| | `ADMIN_ROLE` | governance | `setWriter` |
| `ProviderRegistry` | `PROVIDER_ADMIN` | governance | Register providers, change status, schema support, metadata |
| | `PROVIDER_OPERATOR` | provider adapter ops | `heartbeat`, `reportFailure` |
| `PoolPolicyManager` | `ISSUER_ADMIN` | issuer | Register, activate, deactivate policies |
| `AuditTrail` | `AUDITOR_ROLE` | gateway, module, compliance officer | Record entries |
| | `DEFAULT_ADMIN_ROLE` | governance | `authorizeRecorder` |
| `EmergencyControls` | `GUARDIAN` | guardian | `pause` only |
| | `TIMELOCK_ADMIN` | governance | `scheduleUnpause`, `cancelUnpause` |
| `CrossChainComplianceReceiver` | `ADMIN` (immutable) | deployer | Allowlist source senders and chains; `wire` |
| `CrossChainComplianceSender` | `ADMIN` (immutable) | deployer | `initializeBridge`, once |

`ComplianceGateway` grants `ADMIN`, `WORKFLOW_SUBMITTER`, and `ISSUER` to the deployer in its
constructor. That is a deployment convenience and a handover hazard — rotate all three to distinct
addresses before any real use. See
[`operations-runbook.md`](./operations-runbook.md#2-post-deploy-smoke-checks).

`ProviderRegistry`, `PoolPolicyManager`, `AuditTrail`, and `EmergencyControls` all declare explicit
`_setRoleAdmin` hierarchies. Without them `AccessControl.grantRole` resolves a role's admin to
`bytes32(0)` and reverts, so the role would be permanently ungrantable and a handover would be
impossible. `ProviderRegistry` uses two levels
(`DEFAULT_ADMIN_ROLE → PROVIDER_ADMIN → PROVIDER_OPERATOR`) so adding health reporters is a
`PROVIDER_ADMIN` action rather than a change to the root of trust.

## 12. Test coverage

| Suite | Tests | Covers |
| --- | --- | --- |
| `CredentialLifecycle.t.sol` | 31 | Issue, resolve, renew, suspend, revoke, lazy expiry, sweeper, transition table |
| `PolicyEvaluation.t.sol` | 39 | Every reason code, precedence order, allocation cap, review routing, denials not emitted |
| `ProviderRegistry.t.sol` | 31 | Status lifecycle, schema support, heartbeat monitoring-only, role handover |
| `CrossChainPropagation.t.sol` | 42 | Sender validation, receiver rejection matrix, local-authority protection, nonce propagation |
| `AuditTrail.t.sol` | 22 | Append-only, indexing, paging, and the privacy claim per field |
| `PolicyVersioning.t.sol` | 25 | Immutability, activation delay, supersession, list semantics, cap semantics |
| `EmergencyControls.t.sol` | 19 | Pause asymmetry, two-step unpause, cancel, rescheduling |
| `WireFormat.t.sol` | 22 | CCID determinism, nonce independence, payload round-trip, decode rejection |
| `CheatcodeSemantics.t.sol` | 6 | The test harness's own semantics — prank/expectRevert interaction |
| `invariant/ComplianceInvariant.t.sol` | 14 invariants | Properties over sequences of legal actions |
| `invariant/HandlerCoverage.t.sol` | 3 | That the handler reaches the states the invariants depend on |

The invariant suite is **sampled over sequences, exhaustive over keys**. The key space is
`4 subjects × 3 classes × 3 jurisdictions = 36` credentials against 2 pools, enumerated in full
inside each invariant. A sampled invariant can miss the one credential that was misconfigured.
`HandlerCoverage.t.sol` exists because an invariant whose precondition is never reached passes
vacuously — it asserts the handler actually produces issued, revoked, nonce-advanced, and
digest-captured states.

`invariant_untrustedProviderCannotAllow` reads `getProviderStatus` directly rather than calling
`backsExistingCredentials`. An earlier version delegated to the function under test, which made the
invariant self-defeating: the mutation `backsExistingCredentials → true` silenced the very check
written to catch it, and the harness reported it as surviving. A property check must not be
expressed in terms of the thing it checks.

## 13. Related documents

| Document | Subject |
| --- | --- |
| [`privacy-model.md`](./privacy-model.md) | What is stored, what is absent, and how it is enforced |
| [`policy-schema.md`](./policy-schema.md) | Every `PoolPolicy` field and its semantics |
| [`provider-adapter-guide.md`](./provider-adapter-guide.md) | Provider lifecycle and what an integrator must build |
| [`operations-runbook.md`](./operations-runbook.md) | Deploy order, configuration, monitoring |
| [`incident-response.md`](./incident-response.md) | Pause, unpause, and specific incident playbooks |
| [`threat-model.md`](./threat-model.md) | Adversaries A1–A9, residual risks, development findings |
| [`audit-readiness.md`](./audit-readiness.md) | Ranked gaps and what would close each |