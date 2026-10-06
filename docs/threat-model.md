# Threat model

Adversaries, the control that stops each, and where that control lives. Then the residual risks,
ranked honestly, and two real bugs found during development.

**No audit has been performed.** Nothing here has been verified by an external party. This is the
repository's own analysis of its own code, which is a weaker thing — see
[`audit-readiness.md`](./audit-readiness.md).

## 1. Scope and trust boundaries

### Inside the trust boundary

The contracts, and the keys that hold their roles. An attacker who compromises `ADMIN` is inside.

### Outside the trust boundary

| Party | Why it is outside | How it is constrained |
| --- | --- | --- |
| The Chainlink CRE workflow | Runs off-chain; a bug, a compromised runner, or a replayed request cannot be reasoned about from the contract | The gateway re-derives and re-checks everything it is handed (ten steps) |
| The identity verification provider | Off-chain; the chain cannot verify that an attestation is *true* | `ProviderStatus`, evidence commitments, revocation |
| The holder | Wants access | Nothing. The holder has no on-chain role and no way to influence a decision |
| The CCIP router | External dependency; its guarantees are Chainlink's, not this repository's | Treated as trusted — see A9 |
| A destination chain's operator | Configures the receiver's allowlists | Trusted for their own chain |
| `currentAllocation` supplied to `evaluate` | A caller-supplied argument | Trusted from the integrator — see A10 |

### The one thing the system is built around

Only `Valid` may produce an `Allow`. Every adversary below is, in the end, an attempt to make that
false — to get an `Allow` for a credential, holder, or request that should not have one.

`invariant_allowRequiresEveryPrecondition` re-derives each condition independently of
`_evaluate`'s ordering, so an invariant asserting `reason == OK` cannot hide a module that started
allowing `Pending`.

## 2. Adversaries

### A1 — An arbitrary external caller

**Capability.** Any address. No keys, no role, no on-chain presence.

**What they attack.** The access path: get an `Allow` without a valid credential; write credential
state; forge a propagation message.

**Controls.**

| Attempt | Stopped by | Where |
| --- | --- | --- |
| Write to the registry | `onlyWriter` — only gateway and receiver hold `WRITER_ROLE` | `ComplianceRegistry.setWriter` |
| Forge a replica by calling the receiver | `msg.sender == ROUTER` | `CrossChainComplianceReceiver.ccipMessageCallback` |
| Mint without the role | `onlyRole(WORKFLOW_SUBMITTER)` | `ComplianceGateway.submitCredentialResult` |
| Revoke someone's credential | `_requireRevocationAuthority` | `ComplianceGateway.revoke` |
| Pause | `GUARDIAN` only | `EmergencyControls.pause` |
| Register a provider | `PROVIDER_ADMIN` only | `ProviderRegistry.registerProvider` |
| Change a policy | `ISSUER_ADMIN` only | `PoolPolicyManager.registerPolicy` |
| Write audit entries | `AUDITOR_ROLE` only | `AuditTrail.recordDecision` et al. |
| Enumerate holder identities | No identity data exists to enumerate | The privacy model |

**Residual:** none material. `complianceClient.ts` and `policyClient.ts` are convenience clients;
there is no client-side guard that could be bypassed for a security-relevant effect.

### A2 — A caller claiming to be a trusted message source

**Capability.** Can construct arbitrary payloads and get them delivered through a router, or find a
path that bypasses one.

**Controls.**

| Attempt | Stopped by | Where |
| --- | --- | --- |
| Deliver without the router | `msg.sender == ROUTER` | `ccipMessageCallback` |
| Pose as an allowlisted sender | `ALLOWED_SOURCE_SENDERS[sender]` | `ccipMessageCallback` |
| Pose as an allowlisted chain | `ALLOWED_SOURCE_CHAINS[m.sourceChainSelector]` | `_accept` |
| Alter a payload after signing | `bindingHash` recomputed and compared | `_accept` |
| Truncate or pad a payload | `data.length != ENCODED_LENGTH` | `CompliancePayload.decode` |
| Widen a word to wrap into a plausible value | Explicit bounds before each narrowing | `decode` |
| Force an enum panic instead of a named error | Enum range checks precede conversion | `decode` |
| Misrouted call to the wrong function | `receivedSelector` check | `ccipMessageCallback` |

**Why the binding hash is load-bearing.** The receiver cannot re-derive the CCID — that would require
the subject commitment, which the payload deliberately omits. Integrity rests entirely on
`bindingHash`. That is a real dependency on the source chain's honesty, mitigated by the sender
allowlist.

**Residual:** an attacker who compromises an allowlisted sender address on a source chain can forge
messages the receiver will accept. Mitigated by running source senders under multisig control and
monitoring `CredentialSent`.

### A3 — A replayer

**Capability.** A previously valid message.

**Two independent defences, because they stop different things:**

| Defence | Stops | Where |
| --- | --- | --- |
| `consumedOrderIds[orderId]` | The same message delivered twice | `_accept` |
| `lastAcceptedNonce[ccid]` strictly increasing | An older message arriving after a newer one | `_accept` |

`consumedOrderIds` is written **last**, after every other check. If any check reverts the transaction
reverts, leaving the order id unconsumed — so a message refused for a fixable cause can be retried
rather than burned permanently (`test_FailedDeliveryLeavesOrderIdRetryable`).

On the source side, `lastSentNonce[ccid]` is written **before** the dispatch loop, so a partially
failed batch cannot be retried with the same nonce and silently skip a destination.

**Residual:** none for a pure replay.

### A4 — An out-of-order or stale state source

**Capability.** A message that is genuine but late — a suspension overtaken by a renewal, or a
delayed delivery arriving after a newer one.

**Control.** `lastAcceptedNonce[ccid]` strictly increasing, on both the sender
(`lastSentNonce`) and the receiver. A destination accepts a message only when its nonce exceeds what
it holds, so an older state can never overwrite a newer one.

**This is why `setStatus` bumps the nonce.** See Finding B.

**Residual:** the first status change after issuance is rejected on a destination that has not
received the issuance at all (nothing to compare against, and `lastAcceptedNonce` starts at 0). A
revocation for a credential a destination has never seen writes a `Revoked` replica — which is correct
and harmless, since the destination had no `Valid` state to contradict.

### A5 — A source chain lying about its state

**Capability.** The source chain is compromised or malicious. It can send any message the allowlists
permit, with any nonce, for any CCID.

**What the destination can still stop:**

| Attack | Stopped by |
| --- | --- |
| Overwriting a credential this chain is the issuer for | `LocalIssuerOverride` |
| Overwriting an already-revoked local credential with `Valid` | `LocalIssuerOverride` |
| Accepting a provider this chain has revoked | `ProviderUnavailable` |
| Sending with a misattributed source selector | The sender's `SOURCE_CHAIN_SELECTOR` is `immutable`; a caller-supplied value is overwritten |

**What it cannot stop:** the source chain asserting a *false but coherent* credential for a holder this
destination has never seen. The destination verified nothing. A replica is a cache of trust, and
`isReplica` exists so a pool can require freshness. See §4, residual risk R3.

### A6 — A compromised source chain overwriting locally-issued state

This is separated from A5 because it is the specific outcome the system exists to make impossible,
and because **a nonce check alone does not catch it.**

#### The attack

1. This chain issued a credential locally: jurisdiction 840, class `USAccredited`, nonce 1, `Valid`.
2. A governance action revoked it: `Revoked`, nonce 2, `isReplica = false`.
3. The source chain is compromised and sends: the same CCID, `Valid`, **nonce 500**.
4. `500 > 2`. **Every nonce check passes.** `consumedOrderIds` is a fresh order id. `bindingHash` is
   valid because the compromised source computes it correctly.

The nonce guard is not just insufficient — it points the wrong way. The remote nonce is *higher*,
because the attacker controls it.

#### The control

```solidity
if (REGISTRY.exists(m.ccid) && !REGISTRY.getPropagationState(m.ccid).isReplica) {
    emit CredentialReplicaRejected(m.ccid, m.nonce, "LOCAL_ISSUER_OVERRIDE");
    revert LocalIssuerOverride(m.ccid);
}
```

The invariant being enforced: **a replica can never improve local state.** If this chain is the
issuer for a CCID, no inbound message may touch it, regardless of nonce.

`isReplica` is set only by `ComplianceRegistry.applyReplica` and is false for anything issued locally
or revoked locally. So the check separates "state this chain owns" from "state this chain is caching",
and the latter is the only thing an inbound message may modify.

#### Why it is checked before any write

"Checked before any write, so a refused override costs nothing" — a refused override costs zero gas
beyond the read.

#### The cost of this design

A destination chain that is *also* the issuer for a CCID cannot receive replicas for it, ever. If you
want both chains to issue for the same holder, they need different CCIDs, which means different
subject commitments. This is a real constraint, stated here so nobody discovers it as a surprise.

#### Tests

`test_ReplicaCannotOverwriteLocalIssuance` and `test_ReplicaCannotResurrectLocallyRevokedCredential`
— the second is the harder case, since it explicitly asserts that the remote nonce is higher.
Mutation `M7-replica-overwrites-local-authority` replaces the condition with `if (false)` and the
suite catches it.

### A7 — A compromised workflow

**Capability.** Full control of the `WORKFLOW_SUBMITTER` key. Can submit any
`CredentialResult`, and choose `destinationChainSelectors`.

This is the boundary the gateway's validation was written for. Full detail in
[`incident-response.md`](./incident-response.md#b-compromised-workflow-submitter-key); the security
property is:

**A compromised workflow can refuse a credential. It cannot invent one, extend its life, misstate a
jurisdiction, misstate an investor class, or attribute a credential to a paused provider.**

| Cannot | Enforced by |
| --- | --- |
| Mint for an arbitrary holder | `_validate` step 3 — CCID must reproduce |
| Extend a life | `renewCredential` runs the identical `_validate` |
| Misstate a jurisdiction | Jurisdiction in the CCID preimage |
| Misstate a class | Class in the CCID preimage |
| Attribute to a paused provider | Step 4 — `isActive` |
| Attribute to a non-admitting schema | Step 6 — `supportsSchema` |
| Set a past expiry | Step 7 |
| Replay | Step 10 — nonce strictly increasing |
| Write empty eligibility | Step 8 |
| Write without evidence commitment | Step 9 |
| Write while paused | Step 1 |
| Write without the role | Step 2 |

**Can:** stop issuance (DoS), stop renewal (creds lapse over time), flood transactions, and choose
destination selectors. The last is the sharpest — the destination list is caller-supplied and the
sender's only constraints are non-empty, ≤10, no self-destination, nonce increasing, and not paused.
**A credential can be propagated to a chain the issuer did not intend.**

**Residual:** R2. Bounded DoS plus propagation to an unintended destination.

### A8 — A compromised provider

**Capability.** The provider's vendor account, or its adapter's signing path.

**Controls.**

| Layer | Effect |
| --- | --- |
| `setProviderStatus(Revoked)` | Every credential that provider signed fails policy, everywhere the provider is registered. Immediate. |
| `ProviderUnavailable` at the receiver | Destinations refuse new replicas from a revoked provider, **per destination, without waiting for propagation**. |
| Provider registration | New providers start `Paused`; activation is a human decision. |
| Schema support | A provider that does not declare `(type, version)` cannot attest it at all. |
| Evidence commitments | The chain cannot verify evidence, but a compromised provider's attestations are attributable to it. |

**Not a control:** heartbeats and failure reports. Denying on liveness would let a missed heartbeat
become a DoS against every holder the provider signed. Health is monitoring only.

**Residual:** R4. A compromised provider can mint *false but coherent* attestations until governance
notices and revokes. Nothing on chain detects a false attestation — the chain checks coherence, not
truth.

### A9 — The CCIP router, treated as a trusted external dependency

**Capability.** Whatever the real router's failure modes are.

The router is **trusted**. This is a decision, and the receiver's structure follows from it:
`msg.sender == ROUTER` is the primary gate, and the sender allowlist is defence in depth behind it.

**What the mock does and does not exercise.** `MockCCIPRouter` preserves the two properties the
receiver actually depends on:

1. `send` returns a message id and the caller is `msg.sender`.
2. Delivery invokes `ccipMessageCallback` with `msg.sender == router`.

So router identity, source sender, selector, order id, and payload bytes are all exercised for real.

**What is not exercised:** the real router's own guarantees — LINK fee handling, confirmation counts,
finality assumptions, rate limits, message-size limits, gas metering for the destination call,
behaviour when the destination reverts, and off-chain operational failure. `deliver` and `deliverRaw`
are permissionless in test code specifically so a test can impersonate a misbehaving source chain,
which means the router's adversarial behaviour is partly simulated rather than reproduced.

**`receiveMessage` is a second entry point.** `CrossChainComplianceReceiver.receiveMessage` is
`public` and performs the same validation **except** the router-identity check. Its stated purpose is
so the rules can be exercised directly in tests and by a local relay without impersonating the router.
It is a deliberate testability surface, and it is a standing residual risk: anything that can call it
can attempt a replica. The binding-hash, allowlist, and nonce checks still apply — so this is an
additional reachable path to `_accept`, not a bypass of `_accept`'s rules.

**Residual:** R1. Stated plainly rather than argued away.

### A10 — The reader / integrator implementing a partial check

**Capability.** None on chain. The risk is entirely in what the integrator chooses to call.

**The failure this targets:** a pool that calls `registry.isValid(ccid)` and treats `true` as
sufficient. That call is `true` for a credential whose provider has since been paused, for one whose
jurisdiction the pool does not accept, and for a replica this chain last heard from weeks ago.

**Why the failure is likely.** It is one call instead of one call. It compiles. It works in testing.
It returns `true` for a compliant holder, so every test passes.

**Controls.**

| Layer | Effect |
| --- | --- |
| `PoolComplianceModule.evaluate` | The single place all conditions are considered together, so a partial version is not something an integrator can accidentally write. |
| `evaluate` is `view` | `eth_call` preview, no state change, no event — makes the correct path no harder than the wrong one. |
| `AccessDecision` in the SDK | Returns the reason always; `isAllowed` is the only correct question. A client returning a bare `bool` is one refactor away from treating `ReviewRequired` as `true`. |
| `isCredentialEligible` | Explicitly documented as *not* an access gate, and written as a direct check rather than by reinterpreting `evaluate`'s output — so it cannot be mistaken for one. |

**The second partial-check failure:** `AccessRequest.currentAllocation` is a **caller-supplied
argument**. The registry deliberately stores no allocation. An integrator that passes `0` gets a cap
check against the increment alone, which lets a holder already at the cap add another full cap's
worth.

Mutation `M10-allocation-cap-ignores-current-holding` covers the module's own arithmetic; it does not
cover an integrator lying about the input. See R5.

### A11 — Governance abuse

**Capability.** `ADMIN`, `DEFAULT_ADMIN_ROLE`, `POOL_POLICY_MANAGER`'s `ISSUER_ADMIN`,
`PROVIDER_ADMIN`.

**Controls.**

| Control | Effect |
| --- | --- |
| `POLICY_ACTIVATION_DELAY` = 7 days | Governance cannot instantly exclude every existing investor. There is a window in which the pending version is public and readable. |
| Immutable policy versions | An integrator that pinned version 3 can still read what it means. |
| `GovernanceOnly` revocation mode | Governance authority over credentials cannot be usurped by the issuer. |
| Guardian ≠ admin (enforced by `Deploy.s.sol`) | Pause asymmetry survives. |
| `GUARDIAN` cannot resume | A compromised guardian cannot control the system's recovery. |
| `TIMELOCK_ADMIN` + 24h | Resuming is slow; `cancelUnpause` is the safety valve. |
| Exactly one active version per pool | No ambiguity in what a request is evaluated under. |
| Public events | Every governance action emits. |

**What governance can still do:** revoke any credential, permanently. Deactivate a pool. Register a
malicious provider. That is the intended power of a governance key, and the 7-day delay plus the
guardian asymmetry bound how quietly it can be used. A multisig is the expected form for `ADMIN`; a
single EOA defeats the point of the delay.

### A12 — Someone who can call the sweeper

`expireDue` is `onlyWriter` and cosmetic. Its safety impact is **zero**, because `statusOf` applies
expiry lazily. A caller who stalls it loses event-trail cleanliness, not access control. This is
recorded because a design where a keeper's liveness was load-bearing would be a fail-open, and this
one is not.

## 3. Two findings from development

Both were real bugs, both were found by the test suite or the mutation harness, and both are the
reason specific tests exist.

### Finding A: per-destination dedup made revocation impossible

**What it was.** An earlier version of the sibling `identity-bridge-zktls` sender, and this
repository's first cut, skipped destinations a credential had already been sent to:

```solidity
if (sentTo[m.ccid][dest]) continue;   // the bug
```

**Why it was catastrophic.** The destinations that had already seen a credential as `Valid` are
**exactly the destinations that needed to hear about the revocation.** The dedup inverted the
guarantee: it made propagation reliable for issuance and impossible for revocation, and it did so
silently — no error, no event, the credential simply stayed valid everywhere.

**The fix.** `sentTo[ccid][dest]` is retained as a **query** (`hasSentTo`) and is never consulted to
skip a send. Replay defence belongs on the receiver, which requires a strictly increasing nonce.

**Pinned by** `test_RevocationReachesEveryDestinationThatSawIssuance`, which revokes to the same
destination list used at issuance and asserts `router.sentCount()` increased by exactly the number of
destinations.

**The general lesson.** A channel that only sometimes exists is precisely how a revoked credential
ends up still looking valid somewhere. There is no separate fast path for revocation; every state
change goes through the same `sendCredentialState`.

### Finding B: setStatus did not bump the nonce

**What it was.** `ComplianceRegistry.setStatus` changed `status` without advancing `nonce`. A
revocation therefore carried **the same nonce as the issuance it reversed**.

**Why it was catastrophic, and why it was invisible.** On the source chain everything was correct:
`revoke` reverted nothing, the record said `Revoked`, and every source-chain read confirmed it. The
damage appeared only on destinations, which require a strictly increasing nonce and therefore
discarded the message as stale. The result: **a revoked credential stayed valid on every chain it had
propagated to, while the issuer's own chain reported it as revoked.** A revocation that appeared to
succeed and did nothing.

**The fix.** `r.nonce += 1` on every accepted transition, and `_repropagate` / `revoke` re-read the
record after the status change so the **bumped** nonce is what propagates.

**Pinned by** `test_RevocationCarriesANonceTheDestinationWillAccept` and
`test_SuspensionCarriesANonceTheDestinationWillAccept` — asserted against the destination's own
`lastAcceptedNonce` bookkeeping, which is the thing that would actually refuse the message.

**Why the mutation harness had to be pointed at the full suite.** An earlier version of
`scripts/mutation-check.mjs` reported mutation `M6-status-change-does-not-bump-nonce` as surviving.
The reason is structural: the defect is **genuinely unobservable from one chain**, because the source
chain is perfectly correct. No single-chain invariant can see it. The harness now runs the full suite
for every mutation, and each mutation declares the scope it needs.

**The general lesson.** A property that only manifests across a boundary needs a test that crosses it.
Asking "does the source look right?" is not the same as asking "did the effect arrive?"

### Finding C — the mutation harness mis-detected failures

Included because it is a tooling finding, and it produced false confidence rather than a false failure.

`spawnSync` with `shell: true` goes through `cmd.exe`, whose reported exit status does not reliably
reflect `forge`'s own. An earlier version trusted `status !== 0` and reported **ten mutations as
"survived"** while the very next line printed the test that had failed for each one. The harness now
parses forge's own summary line and counts `[FAIL:` markers.

The same class of problem appeared in the invariant suite: `invariant_untrustedProviderCannotAllow`
originally delegated to `backsExistingCredentials`, which made it self-defeating — the mutation
`backsExistingCredentials → true` silenced the very check written to catch it. A property check must
not be expressed in terms of the function under test. The invariant now reads the status enum directly.

## 4. Residual risks

Ranked by expected impact, honestly.

### R1 — The CCIP router is trusted, and the mock does not test it

**Rank: highest.** The receiver's primary gate is `msg.sender == ROUTER`. Everything about the real
router's behaviour — fees, finality, rate limits, size limits, destination gas, behaviour on
destination revert — is untested here. A router behaviour difference does not fail loudly; it fails as
propagation that quietly stops.

Additionally, `receiveMessage` is a reachable second entry point to `_accept` that skips the router
check.

**Mitigation now:** trust the router (Chainlink's guarantee), keep the source sender allowlist as
defence in depth, monitor `lastSourceNonce` divergence per destination, and treat any router upgrade
as a security-relevant event.

**Would close it:** a fork test against the real router on a testnet, and either restricting
`receiveMessage` to a test-only deployment or gating it behind an immutable "relay mode" flag.

### R2 — A compromised workflow can propagate to an unintended chain

**Rank: high.** `destinationChainSelectors` is caller-supplied. The sender's constraints are
structural (non-empty, ≤10, no self-destination, nonce increasing, not paused) but not
*intentional*. A compromised `WORKFLOW_SUBMITTER` can propagate a credential to any chain selector.

**Mitigation now:** run the relay yourself; monitor `CredentialSent` events for unexpected
destination selectors; alert on any propagation from a selector not in your approved set.

**Would close it:** an allowlist of destination selectors per issuer, enforced in the sender or the
gateway.

### R3 — A replica is trust, and nothing detects a false attestation

**Rank: high, and structural.** The destination verified nothing. A compromised source chain can
assert a false-but-coherent credential for a holder this destination has never seen, and it will be
accepted and usable. The nonce and binding-hash checks are irrelevant here: the attacker is
generating genuinely valid messages.

`requiresFreshReplica` + `maxReplicaAge` bounds the *duration*, not the *existence*, of such a state.

**Mitigation now:** enable `requiresFreshReplica` on any pool consuming replicas; monitor
`getPropagationState`; keep destination freshness within the policy's tolerance.

**Would close it:** per-destination policy allowlists of accepted source chains and providers, plus a
mechanism for a destination to challenge a credential it considers false.

### R4 — No per-credential proof that off-chain verification happened

**Rank: medium-high.** `evidenceHash` is a commitment to evidence the chain cannot open. An auditor
must take the provider's word, or the workflow operator's. Nothing binds the attestation to a specific
verification process, and a compromised workflow could assert an `evidenceHash` that commits to
nothing meaningful — the only check is that it is non-zero.

**Mitigation now:** treat the provider and workflow operator as in-scope for assurance; keep short
TTLs so a false attestation expires.

**Would close it:** ZK proofs of verification, or an anchored off-chain log of verification events with
a published commitment scheme. See [`audit-readiness.md`](./audit-readiness.md).

### R5 — `currentAllocation` is caller-supplied

**Rank: medium.** The registry deliberately stores no allocation, so `maxAllocationPerInvestor` is
only as good as the value the integrator passes. An integrator passing `0` gets a cap checked against
the increment alone, which lets a holder already at the cap add another full cap's worth.

This is a deliberate trade against two sources of truth drifting, and the SDK documents the
requirement on the field. It is not a contract bug; it is a trust assumption about the integrator.

**Mitigation now:** document the requirement loudly; verify integrators read their allocation from the
pool's own accounting.

**Would close it:** an optional per-pool `allocationOracle` address the module trusts for
`currentAllocation`, leaving the caller-supplied value as a fallback.

### R6 — No bulk revocation

**Rank: medium operationally, high under a provider compromise.** `revoke` is per credential. A
provider compromise affecting 10,000 holders means 10,000 transactions, each of which must also be
propagated. Mitigable by revoking the *provider* first (one transaction, immediate effect), but the
audit trail then reads `PROVIDER_PAUSED` rather than `Revoked`.

**Would close it:** `revokeBatch(bytes32[] ccids, ...)` with `MAX_SWEEP_BATCH`-style bounding, or a
provider-scoped revocation that cascades.

### R7 — The audit trail is on-chain only

**Rank: medium.** `AuditTrail` is append-only and on-chain, so its integrity rests on the chain's
integrity. There is no off-chain anchoring, no periodic publication of a root hash, and no independent
copy. An attacker who can rewrite chain history can rewrite history.

It also records only what the module chooses: allows and review-required outcomes, plus credential
lifecycle events. Denials are deliberately not emitted.

**Would close it:** periodically publish a Merkle root of `EntryRecorded` events to an independent
medium, and index events off-chain as the primary record.

### R8 — `reason` on lifecycle calls is unvalidated

**Rank: low.** `revoke(ccid, poolId, reason, destinations)` takes an arbitrary `bytes32`. It cannot
carry a readable name — 32 bytes of arbitrary content is not a name — and `reasonToString` reports
`UNRECOGNIZED` for anything unknown. But an arbitrary hash lands in an append-only log that cannot be
scrubbed, and there is no signal that it is not a curated code.

**Would close it:** validate `reason` against `ComplianceTypes.allReasons()` on lifecycle calls, or
add a separate free-form field the auditor-facing surfaces ignore.

### R9 — Enum-parameter range checks rest on the compiler

`ProviderRegistry.setProviderStatus` has no in-body range check, relying on solc's ABI decoder to
reject out-of-range values. If a future toolchain relaxed that, an out-of-range `uint8` would reach
storage and `getProviderStatus`'s enum decode would panic.
`test_OutOfRangeStatusRejectedViaRawCalldata` guards it — it asserts the stored status is unchanged
after a rejected call, so a relaxation would be caught rather than assumed away.

### R10 — Formal verification absent

The properties are tested, not proved. The invariant suite is sampled over sequences (exhaustive
over its 36-credential key space). No gas benchmarks exist. See
[`audit-readiness.md`](./audit-readiness.md).

### R11 — No deployment, no external review

Nothing here has run on a live network against a real router or a real provider. No audit exists.
The tests pass; that is the entire empirical basis for this document's claims.

## 5. Attack-to-control index

| Attack | Primary control | Location | Tested by |
| --- | --- | --- | --- |
| Write credential state without authority | `onlyWriter` | `ComplianceRegistry` | `test_UnauthorizedSubmitterRejected` |
| Mint an arbitrary credential | CCID re-derivation | `ComplianceGateway._validate` step 3 | `test_TamperedCcidRejected`, `test_SubjectSwapRejected` |
| Misstate jurisdiction | Jurisdiction in the CCID preimage | `CCIDResolver.compute` | `test_JurisdictionSwapRejected` |
| Escalate investor class | Class in the CCID preimage | `CCIDResolver.compute` | `test_InvestorClassEscalationRejected` |
| Attribute to a paused provider | `isActive` | `_validate` step 4 | `test_PausedProviderRejected` |
| Attribute to a non-admitting schema | `supportsSchema` | `_validate` step 6 | `test_UnadmittedProviderRejected` |
| Renew on a stale result | Identical `_validate` on renewal | `renewCredential` | `test_RenewExtendsExpiry`, invariant suite |
| Forge a replication | `msg.sender == ROUTER` | `ccipMessageCallback` | `test_ReceiverRejectsDirectCallBypassingRouter` |
| Forge from an untrusted sender | `ALLOWED_SOURCE_SENDERS` | `ccipMessageCallback` | `test_ReceiverRejectsUntrustedSourceSender` |
| Alter a payload post-signing | `bindingHash` | `_accept` | `test_ReceiverRejectsBindingHashMismatchByName` |
| Replay a message | `consumedOrderIds` | `_accept` | `test_ReceiverRejectsReplayedOrderId` |
| Out-of-order state | Strictly increasing nonce | `_accept`, `lastSentNonce` | `test_ReceiverRejectsNonceRegression` |
| Overwrite local authority (A6) | `LocalIssuerOverride` | `_accept` | `test_ReplicaCannotResurrectLocallyRevokedCredential` |
| Accept a compromised provider's replica | `ProviderUnavailable` | `_accept` | `test_ReceiverRejectsWhenProviderNoLongerBacksCredentials` |
| Revoke where propagation cannot follow | No dedup on the sender | `sendCredentialState` | `test_RevocationReachesEveryDestinationThatSawIssuance` |
| Revocation discarded as stale | Nonce bumped on status change | `ComplianceRegistry.setStatus` | `test_RevocationCarriesANonceTheDestinationWillAccept` |
| Partial policy check (A10) | `PoolComplianceModule.evaluate` | `_evaluate` | 39 tests in `PolicyEvaluation.t.sol` |
| Resurrection after revoke | `Revoked` is terminal | `_isTransitionAllowed` | `test_RevocationIsTerminal`, `invariant_revokedIsTerminal` |
| Ignore policy change window | 7-day activation delay | `activatePolicyVersion` | `test_ActivationBlockedBeforeDelay` |
| Resume immediately | 24h unpause delay | `executeUnpause` | `test_ExecuteBlockedUntilDelayElapses` |
| Provisionally allow `Pending` | `PENDING` denial | `_statusReason` | `test_PendingCredentialDeniedNotProvisionallyAllowed` |
| Expire via a stalled sweeper | Lazy expiry in `statusOf` | `ComplianceRegistry` | `test_LazyExpiryWithoutSweeper` |
| Emit a denial to inflate a history | Denials not emitted | `evaluateAndRecord` | `test_EvaluateAndRecordEmitsNothingOnDenial` |
| Treat review as a denial | `ReviewRequired` is a distinct decision | `Decision` | `test_ManualReviewIsNotAnAllow` |
| Invalidate credentials on migration | `Deprecated` backs existing | `backsExistingCredentials` | `test_DeprecatedBlocksIssuanceButBacksExistingCredentials` |
| Deny on a missed heartbeat | Health kept out of policy | `_evaluate` step 9 | `test_HeartbeatStalenessIsAMonitoringSignalNotADenial` |