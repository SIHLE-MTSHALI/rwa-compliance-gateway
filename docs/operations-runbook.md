# Operations runbook

Deploy, configure, and operate the compliance gateway.

**This repository has not been deployed to any testnet or mainnet.** Every address below is a
placeholder. There is no production environment, no funded deployment, and no incident history. This
document describes what a deployment *would* require.

## 1. Deploy order

`contracts/script/Deploy.s.sol` performs the following, in this order. The order matters: each step
depends on an address that the previous step creates.

| # | Step | Depends on |
| --- | --- | --- |
| 1 | `new ComplianceRegistry(admin)` | — |
| 2 | `new ProviderRegistry(admin)` | — |
| 3 | `new PoolPolicyManager(admin)` | — |
| 4 | `new AuditTrail(admin)` | — |
| 5 | `new CCIDResolver()` | — |
| 6 | `new EmergencyControls(admin, guardian)` | `guardian` |
| 7 | `new CrossChainComplianceSender(admin, router, sourceChainSelector, emergency)` | `emergency` |
| 8 | `new ComplianceGateway(admin, registry, providers, policies, resolver, audit, sender, emergency)` | steps 1–7 |
| 9 | `sender.initializeBridge(gateway)` | 7, 8 |
| 10 | `registry.setWriter(gateway, true)` | 1, 8 |
| 11 | `audit.authorizeRecorder(gateway)` | 4, 8 |
| 12 | `new PoolComplianceModule(registry, providers, policies, emergency, audit)` | 1–6 |
| 13 | `audit.authorizeRecorder(module)` | 4, 12 |
| 14 | *(if `DEPLOY_RECEIVER`)* `new CrossChainComplianceReceiver(router, sourceChainSelector, admin, registry, providers, emergency)` | 1–7 |
| 15 | *(if `DEPLOY_RECEIVER`)* `registry.setWriter(receiver, true)` | 1, 14 |
| 16 | *(if `DEPLOY_RECEIVER` and `TRUSTED_SOURCE_SENDER` set)* `receiver.setAllowedSourceSender(...)` and `setAllowedSourceChain(...)` | 14 |
| 17 | *(if `DEPLOY_RECEIVER`)* `receiver.wire()` | 15 |

Steps 9–11 break the two constructor cycles and authorize the audit hook. Steps 12–13 build the
integrator-facing module.

### 1.1 Environment variables

Read via `vm.envOr`, so the same script serves every chain.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `ADMIN` | No | `msg.sender` | Governance address. |
| `GUARDIAN` | **Yes** | — | Emergency-pause address. Must differ from `ADMIN`. |
| `CCIP_ROUTER` | **Yes** | — | Chainlink CCIP v2 router address. |
| `SOURCE_CHAIN_SELECTOR` | **Yes** | — | This chain's CCIP selector. |
| `DEPLOY_RECEIVER` | No | `false` | Deploy the inbound receiver as well. |
| `TRUSTED_SOURCE_SENDER` | No | unset | Source-chain sender address to allowlist. |
| `TRUSTED_SOURCE_SELECTOR` | No | `0` | Source chain selector to allowlist. Applied only when `TRUSTED_SOURCE_SENDER` is set. |

The script **refuses** rather than defaulting on three conditions:

| Error | Condition |
| --- | --- |
| `GuardianNotConfigured` | `GUARDIAN` unset (defaults to `address(0)`). |
| `GuardianMustDifferFromAdmin` | `GUARDIAN == ADMIN`. |
| `RouterNotConfigured` | `CCIP_ROUTER` unset or zero. |
| `SourceChainSelectorNotConfigured` | `SOURCE_CHAIN_SELECTOR` unset or zero. |

The guardian check deserves emphasis: **`GUARDIAN` defaulting to `ADMIN` is refused, not allowed.**
A single key that can both stop the system and control it is not an emergency control — the pause
becomes a governance action with the asymmetry gone. The mistake is easy to make by forgetting the
variable, so the default is a refusal.

### 1.2 Postconditions asserted, not logged

`Deploy.s.sol` ends with `require` calls, not log lines:

```solidity
require(gateway.isAuditAuthorized(), "gateway is not an audit recorder");
require(audit.hasRole(audit.AUDITOR_ROLE(), address(complianceModule)), "module is not a recorder");
require(sender.bridge() == address(gateway), "sender is not bound to the gateway");
require(registry.isWriter(address(gateway)), "gateway is not a registry writer");
require(!emergency.isPaused(), "system must not deploy paused");
```

Every one of these is a step whose absence leaves a system that looks deployed and fails later, in
production, on the first transaction that needs it. Asserting is the point.

## 2. Post-deploy smoke checks

Run all of these. Each is a read.

### 2.1 Wiring

| Check | Call | Expected |
| --- | --- | --- |
| Gateway can record audit | `gateway.isAuditAuthorized()` | `true` |
| Module can record audit | `audit.hasRole(audit.AUDITOR_ROLE(), module)` | `true` |
| Sender bound to gateway | `sender.bridge()` | the gateway address |
| Sender bound once | `sender.bridgeInitialized()` | `true` |
| Gateway is a registry writer | `registry.isWriter(gateway)` | `true` |
| Receiver armed *(destination)* | `receiver.wired()` | `true` |
| Receiver is a registry writer *(destination)* | `registry.isWriter(receiver)` | `true` |
| System not paused | `emergency.isPaused()` | `false` |

`gateway.isAuditAuthorized()` is the single most important check, and the one most often missed. The
gateway **cannot** self-authorize: `AuditTrail` authorizes by admin, and the gateway is not its admin.
Until the deployer calls `audit.authorizeRecorder(gateway)`, **every issuance reverts on the audit
hook.**

That is the correct failure direction. A gateway that cannot record its own history is worse than one
with no history at all, because the gap is invisible until someone audits. But it looks like a silent
failure to anyone who has not read `Deploy.s.sol`.

The SDK exposes it as `IssuerClient.isAuditAuthorized()`, documented as worth checking after
deployment and in a health check.

### 2.2 Cross-chain trust *(destination chains)*

| Check | Expected |
| --- | --- |
| `receiver.ALLOWED_SOURCE_SENDERS(trustedSender)` | `true` |
| `receiver.ALLOWED_SOURCE_CHAINS(sourceSelector)` | `true` |
| `receiver.ROUTER` | the real CCIP router |
| `receiver.DESTINATION_CHAIN_SELECTOR` | this chain's selector |

Note that steps 16's allowlisting is skipped entirely when `TRUSTED_SOURCE_SENDER` is unset, leaving
the receiver correctly refusing everything. If you deploy the receiver without it, propagation fails
with `UntrustedSourceSender` until you configure it.

### 2.3 Behavioural checks

| Check | Call | Expected |
| --- | --- | --- |
| Unregistered pool denies | `module.evaluate({ccid, unknownPoolId, 0, 0})` | `Deny` / `POOL_NOT_REGISTERED` |
| Unknown credential denies | `module.evaluate({unknownCcid, poolId, 0, 0})` | `Deny` / `NO_CREDENTIAL` |
| Reason is describable | `module.describeReason(<that code>)` | a real label |

### 2.4 Role handover

`ComplianceGateway`'s constructor grants `ADMIN`, `WORKFLOW_SUBMITTER`, and `ISSUER` to the deployer.
That is a deployment convenience and a handover hazard: the same key can submit results, suspend, and
revoke. Before any real use, move all three to distinct addresses.

| Role | Move to |
| --- | --- |
| `ADMIN` | Governance (multisig) |
| `WORKFLOW_SUBMITTER` | The CRE workflow's signer |
| `ISSUER` | The issuer key |
| `HOLDER` | Holder keys, if holders withdraw directly |

`EmergencyControls` is constructed with `admin` holding `TIMELOCK_ADMIN` and the separate `guardian`
holding `GUARDIAN`. Verify both are distinct addresses and that both are multisigs or HSM-backed in
production — a single EOA as guardian means a single key compromise pauses (or, worse, if it is also
admin, controls) the whole system.

## 3. Provider registration and activation

Order matters: a provider cannot influence any decision until it is `Active`, and it starts `Paused`.

```
PROVIDER_ADMIN → registerProvider(providerId, metadataURI)
               → setSchemaSupport(providerId, credentialType, schemaVersion, true)
               → setProviderStatus(providerId, ProviderStatus.Active)
```

Step 3 is a human decision. `registerProvider` cannot auto-activate, deliberately: a new entry should
not be able to mint credentials the moment it exists.

For each credential type the provider will assert, declare schema support separately. The schema
version is part of the key — a provider supporting v1 does not thereby support v2, and a credential
asserting v2 against a v1 review would be a misrepresentation.

**On every destination chain, separately.** A replica will be refused with `ProviderUnavailable` for
a provider that is `Active` on the source and simply not registered locally. Provider state does not
propagate; only credential state does.

### 3.1 Migrating providers

The routine event. Do not use `Revoked`.

```
1. Register the new provider            -> Paused
2. Declare its schema support
3. Activate it                          -> Active
4. Move issuance to it
5. Mark the old one Deprecated          -> new issuance blocked, existing credentials still valid
6. Let the old provider's credentials lapse naturally
```

Step 5 is the one that matters. Using `Revoked` instead would invalidate every credential the old
provider signed, across every chain where it is registered — punishing every existing holder for a
contract migration. `Deprecated` exists precisely so this does not happen.

Monitor step 6: the credential count backing a deprecated provider should trend to zero. When it does,
the old provider can be removed from consideration.

### 3.2 Revoking a provider

Only on compromise, fraud, or a data-handling failure. `Revoked` immediately fails policy for every
credential that provider signed, everywhere it is registered, and blocks the inbound propagation of
any further replica.

Ordering in an incident: **revoke the provider first**, then sweep the credentials. Revoking the
provider denies access immediately without a per-credential transaction; sweeping is the cleanup that
produces a clean audit trail. See
[`incident-response.md`](./incident-response.md#a-provider-compromise).

## 4. Policy rollout

`POLICY_ACTIVATION_DELAY` is 7 days. A change is a two-week operation from intent to effect.

| Day | Action | Event |
| --- | --- | --- |
| 0 | `registerPolicy(...)` as `ISSUER_ADMIN` | `PolicyRegistered(poolId, version, ...)` |
| 0 | `notifyPending(poolId, version)` | `PolicyPending(poolId, version, activateAfter)` |
| 0–7 | Diff the pending version against the active one; notify holders if holders are affected | — |
| ≥7 | `activatePolicyVersion(poolId, version)` | `PolicyActivated`, plus `PolicyDeactivated` for the previous |

Use `PolicyClient.register`, which returns `activatableAt`, and `secondsUntilActivatable`, rather than
discovering the delay when a transaction reverts with `ActivationDelayNotElapsed`.

### 4.1 What to check during the window

The delay exists so the change is observable. Use it:

| Question | Where to look |
| --- | --- |
| What exactly changes? | Diff `getPolicy(poolId, version)` against `getPolicy(poolId, activeVersion(poolId))`. |
| Does this exclude anyone who is currently admitted? | Compare each live credential's `jurisdictionCode` and `investorClass` against the new lists. |
| Does this cap allocations below what holders already hold? | Compare `getRecord(ccid).`-derived holdings against `maxAllocationPerInvestor`. **Registry reads will not tell you current allocation** — that is in the pool's accounting; query the pool. |
| Does this change revocation authority? | `revocationMode`. Moving to `GovernanceOnly` revokes issuer authority; moving off it restores it. |
| Does this force review? | `requiresManualReview`. Note this cannot be removed for another week. |

That second question is the one operators skip. A policy that silently excludes existing investors is
the exact scenario the delay was built to surface.

### 4.2 Closing a pool without replacing its policy

`deactivateActivePolicy(poolId)` sets `active = false` on the current version. The pool returns
`POLICY_INACTIVE` for every request, and the policy stays readable so past decisions remain
explainable. Reversible with `activatePolicyVersion`.

## 5. Monitoring

### 5.1 Alert on

| Signal | Source | Why |
| --- | --- | --- |
| `PauseStateChanged(true, ...)` | `EmergencyControls` | Someone paused. Everything is denying. |
| `ProviderStatusChanged(..., Revoked)` | `ProviderRegistry` | A provider's attestations are no longer trusted anywhere. |
| `ProviderStatusChanged(..., Paused)` | `ProviderRegistry` | New issuance from that provider is blocked. |
| `ProviderStatusChanged(..., Deprecated)` | `ProviderRegistry` | A migration is under way; watch the backing-credential count. |
| `isProviderHealthy == false` | `ProviderRegistry` | Monitoring only — **this is a page, not a policy outcome.** |
| `heartbeatAge > HEARTBEAT_STALENESS_SECONDS` | `ProviderRegistry` | Liveness. Informational. |
| `CredentialStatusChanged(..., Revoked)` | `ComplianceRegistry` | A credential was withdrawn. |
| `CredentialStatusChanged` rate spike | `ComplianceRegistry` | Possible mass revocation or an incident. |
| `CredentialReplicaRejected` | `CrossChainComplianceReceiver` | Propagation is failing; see §5.3. |
| `WriterAuthorizationChanged` | `ComplianceRegistry` | The writer set changed. Verify it was expected. |
| `RecorderAuthorized` | `AuditTrail` | A recorder was authorized. Verify it was expected. |
| `PolicyActivated` | `PoolPolicyManager` | A policy changed. Check it was the expected version. |
| `PolicyDeactivated` | `PoolPolicyManager` | A pool was closed. |
| Gateway reverting with `NotAuditor` | `ComplianceGateway` | `authorizeRecorder` was never done, or was removed. |
| Sender reverting with `NotBridge` | `CrossChainComplianceSender` | The bridge binding is wrong, or the caller is not the gateway. |
| Receiver reverting with `NotWired` | `CrossChainComplianceReceiver` | `wire()` was never called. |
| Receiver reverting with `NotRegistryWriter` | `CrossChainComplianceReceiver` | `setWriter(receiver, true)` was not done. |

The last four are not hypothetical; each corresponds to a skipped deploy step.

### 5.2 Denials are deliberately NOT emitted

`PoolComplianceModule` emits `AccessAllowed` and `AccessReviewRequired` and **nothing for `Deny`**.

**Do not build a denial-rate dashboard from events.** It cannot be built — the data is deliberately
absent. An emitted denial would let anyone inflate a holder's public denial history by probing
repeatedly, and the caller already receives the reason in the return value.

To monitor denials, you need a channel outside the contracts:

| Approach | Trade-off |
| --- | --- |
| An integrator's own service logs every `evaluate` call and reason | Requires you to run the integrating pool. Honest about what it is. |
| `eth_call` probes from monitoring | Cannot see other integrators' traffic; rate-limited by RPC. |
| `AuditTrail` `AccessDenied` entries via `recordDecision` | Exists and is permissioned, but the module never calls it — a compliance officer must. |

This is a real operational cost, accepted deliberately. Budget for an off-chain log in any integration
you operate, and document that the on-chain event stream is not a complete picture.

### 5.3 Propagation health

`CredentialReplicaRejected` is emitted with a string reason before each revert:
`UNKNOWN_SELECTOR`, `UNTRUSTED_SOURCE_SENDER`, `MALFORMED_PAYLOAD`, `UNKNOWN_STATUS`,
`UNKNOWN_CLASS`, `NUMERIC_OVERFLOW`, `REPLAYED_MESSAGE`, `UNTRUSTED_SOURCE_CHAIN`, `SELF_SOURCE_CHAIN`,
`BINDING_HASH_MISMATCH`, `LOCAL_ISSUER_OVERRIDE`, `PROVIDER_UNAVAILABLE`, `STALE_NONCE`.

| Reason | Meaning | Action |
| --- | --- | --- |
| `UNTRUSTED_SOURCE_SENDER` / `UNTRUSTED_SOURCE_CHAIN` | Allowlist not configured | Configure it. |
| `PROVIDER_UNAVAILABLE` | Provider not registered, or not backing credentials, on this destination | Register it locally. |
| `SELF_SOURCE_CHAIN` | The source chain selector equals the destination's | Configuration error. |
| `SELF_SOURCE_CHAIN` on the sender side | A destination list included this chain | Fix the destination list. |
| `STALE_NONCE` | An older message arrived after a newer one | Usually benign out-of-order delivery; alert if sustained. |
| `REPLAYED_MESSAGE` | The same `orderId` delivered twice | Usually benign redelivery. |
| `LOCAL_ISSUER_OVERRIDE` | A remote chain tried to overwrite local issuance | **Investigate.** This is the one outcome the system exists to make impossible. |
| `BINDING_HASH_MISMATCH` | A payload was altered after the sender signed it | **Investigate immediately.** |
| `NUMERIC_OVERFLOW` / `UNKNOWN_STATUS` / `UNKNOWN_CLASS` / `MALFORMED_PAYLOAD` | A version mismatch between sender and receiver | Deploy matching code. |

A rejected message is **retryable**. `consumedOrderIds[orderId]` is written last, after every other
check, so a message refused for a fixable cause can be redelivered once the cause is resolved rather
than being burned permanently.

Note the source chain cannot observe a destination's rejection directly — CCIP delivery is
asynchronous. Detecting propagation failure requires querying `getPropagationState(ccid)` on the
destination and comparing `lastSourceNonce` against the source record's `nonce`.

### 5.4 Freshness monitoring

For pools with `requiresFreshReplica`, monitor `registry.ageOf(ccid)` on destination chains.
`ageOf` returns `type(uint64).max` for a record that does not exist. `getPropagationState(ccid)`
gives `isReplica`, `sourceChainSelector`, `lastUpdatedAt`, and `lastSourceNonce`.

A replica older than the policy's `maxReplicaAge` returns `STALE_DESTINATION` on the next access
check — automatically, without any keeper. Alert on the trend, because it means propagation has
stopped working for that credential.

## 6. Renewal and expiry

### 6.1 Expiry needs no keeper

`ComplianceRegistry.statusOf` applies expiry lazily from `expiresAt`. A credential is denied the
instant it lapses whether or not `expireDue` has ever run.

**This is the load-bearing property.** A system whose expiry depended on a sweeper being alive fails
**open** the moment that sweeper stalls — the one unacceptable direction for a compliance control.

`expireDue` is therefore cosmetic as far as safety is concerned. It exists so monitoring and audit
exports see a clean terminal transition instead of a set of `Valid` records that quietly lapsed.

### 6.2 Running the sweeper

```solidity
function expireDue(bytes32[] calldata ccids) external onlyWriter returns (uint256 expiredCount)
```

| Property | Value |
| --- | --- |
| Authorization | `WRITER_ROLE` only — the gateway or the receiver |
| Batch bound | `MAX_SWEEP_BATCH = 100`, else `BatchTooLarge` |
| Behaviour | Only transitions `Valid` records whose `expiresAt <= block.timestamp` |
| Idempotent | Yes — a second call over the same list does nothing |
| Safety impact | None |

The SDK exposes `IssuerClient.sweepExpiries(ccids)` and `maxSweepBatch()`.

**Do not treat sweeper liveness as a safety property.** Treat a stalled sweeper as a *reporting*
defect. If your monitoring shows a growing set of `Valid`-but-lapsed records, that is a monitoring
bug, not an access-control bug.

### 6.3 Renewal

```solidity
gateway.renewCredential(CredentialResult r, uint64[] destinations, uint64 newExpiresAt, uint64 newNonce)
```

- Requires `WORKFLOW_SUBMITTER`.
- Requires the system not paused.
- Requires the credential to exist.
- Runs the **identical** `_validate` as issuance — so renewal is impossible without a fresh provider
  attestation that passes the full gate. That is what stops a stale or forged result from extending a
  credential's life.
- `ComplianceRegistry.renew` requires `newExpiresAt > expiresAt` (`ExpiryNotLater`), `newNonce` strictly
  increasing (`NonceNotIncreasing`), and refuses a `Revoked` credential.

**The CCID does not change on renewal.** Only the nonce and expiry move. See
[`architecture.md`](./architecture.md#7-credential-identity-the-ccid) for why — a new CCID per renewal
would strand the previous credential on every destination chain as a dangling, still-`Valid` record
unreachable by any revocation.

### 6.4 Renewal cadence

Set credential TTLs so holders are not silently cut off, and schedule re-verification before expiry.
A `Pending` credential denies access, so a holder mid-renewal who has had `beginVerification` called
on them is refused until the result lands — plan the overlap so the gap is not visible.

If re-verification cannot complete before `expiresAt`, the credential lapses and the holder must
re-verify from scratch. A `Revoked` credential cannot be renewed at all.

## 7. Routine schedule

| Cadence | Task |
| --- | --- |
| Per issuance | `beginVerification` → `submitCredentialResult`. |
| Before expiry | Re-verify and `renewCredential`, with a nonce strictly above the last. |
| Daily | Run `expireDue` over near-expiry CCIDs, for a clean event trail. |
| Daily | Check `isProviderHealthy` and `heartbeatAge` for every provider. Page, do not act on it. |
| Daily | Compare `lastSourceNonce` on destinations against source nonces for active credentials. |
| Weekly | Count credentials backed by each `Deprecated` provider; watch for the migration to complete. |
| On change | Diff the pending policy version against the active one during the 7-day window. |
| On change | Confirm `PolicyActivated` / `PolicyDeactivated` events were the expected versions. |
| On change | Review `WriterAuthorizationChanged` and `RecorderAuthorized` events. |

## 8. Known operational gaps

Stated plainly so nobody builds a runbook that assumes otherwise.

| Gap | Consequence |
| --- | --- |
| No bulk revocation | Per-credential only. Untenable at scale during a provider compromise — the top item in [`audit-readiness.md`](./audit-readiness.md). |
| No formal verification | Properties are tested, not proved. |
| No gas benchmarks | Nothing here is a gas budget. |
| Mock CCIP router in tests | Real router behaviour — fees, confirmations, finality, rate limits — is untested. |
| Audit trail is on-chain only | No off-chain anchoring. |
| `reason` on lifecycle calls is not validated | An arbitrary `bytes32` can be written into an audit entry's `reasonCode`. |
| No deployed environment | Every step in this document is untested against a live network. |