# Provider adapter guide

This document is for whoever builds the off-chain component that talks to a KYC/KYB provider and
hands a result to `ComplianceGateway`.

**Read this first: this repository ships no provider adapter.** There is no mock adapter in
`workflows/src/adapters/` — the directory is empty. There is no integration with any real identity
verification provider, no partnership with one, and no testnet or mainnet deployment of any kind.
The contracts are written and tested; everything on the off-chain side of the provider boundary is
yours to build. Treat this document as the specification for that work, not as a description of
something that exists.

Nothing here establishes legal or regulatory compliance.

## 1. What a provider is, on chain

A provider is a `bytes32` identifier registered in `ProviderRegistry`. That is the whole contract.
The adapter itself — the code that talks to the vendor, normalizes the response, computes the
evidence hash — is entirely off chain.

```
ProviderRegistry
  _providers[providerId]              -> Provider { providerId, metadataURI, lastHeartbeat,
                                                  failureCount, registeredAt, updatedAt,
                                                  status, registered }
  _schemaSupport[providerId][credentialType][schemaVersion] -> bool
```

There is no on-chain adapter contract, no callback, and no per-provider code path. The chain knows
only an identifier and a status.

## 2. The `ProviderStatus` lifecycle

```solidity
enum ProviderStatus { Unknown, Active, Paused, Deprecated, Revoked }
```

| Status | `isActive` (issuance gate) | `backsExistingCredentials` (policy gate) | Meaning |
| --- | --- | --- | --- |
| `Unknown` | false | false | Unregistered. |
| `Paused` | false | false | Temporary operational stop. Backlog, rate limiting, incident. |
| `Active` | **true** | **true** | Normal operation. |
| `Deprecated` | false | **true** | Planned wind-down. No new issuance; existing credentials keep their validity. |
| `Revoked` | false | false | Attestations are no longer trusted at all. Issued on compromise. |

Two distinct predicates, and the difference between them is the whole point of the four-value set:

- `isActive(providerId)` — the **issuance** gate. Checked by `ComplianceGateway._validate` step 4.
- `backsExistingCredentials(providerId)` — the **policy** gate. Checked by
  `PoolComplianceModule._evaluate` step 9 and by `CrossChainComplianceReceiver._accept`.

### 2.1 The `Paused` / `Deprecated` / `Revoked` distinction

`Paused` and `Revoked` both deny policy checks, so keeping them apart is purely operational:

- **`Paused`** — "stop for now". The adapter may be rate-limited, backlogged, or mid-outage. Nothing
  about its past attestations is in question. Resume when the backlog clears.
- **`Deprecated`** — "no new work". The provider is being replaced. Existing credentials it signed
  remain valid, so a migration does not invalidate the pool's investors.
- **`Revoked`** — "we no longer trust this". Issued on compromise, fraud, or a data-handling failure.

### 2.2 Why `Deprecated` still backs existing credentials

```solidity
function backsExistingCredentials(bytes32 providerId) external view returns (bool) {
    Provider storage p = _providers[providerId];
    if (!p.registered) return false;
    return p.status == uint8(ProviderStatus.Active) || p.status == uint8(ProviderStatus.Deprecated);
}
```

**Collapsing `Deprecated` into `Paused` would invalidate every live credential during a routine
provider migration.** That is a real failure mode, not a hypothetical one: providers get replaced,
contracts get renegotiated, vendors get acquired. A migration is the single most likely routine
operational event in the adapter's life, and it must not cost every holder their access.

With `Deprecated` as a distinct state, a migration is: register the new provider, activate it,
declare its schema support, move issuance to it, then mark the old one `Deprecated`. Holders signed
by the old provider keep passing policy until their credentials lapse naturally.

`Revoked` is the opposite: the moment you set it, every credential that provider signed fails policy
across every chain where it is registered. That is the intended blast radius for a compromise, and
it is why the transition is `PROVIDER_ADMIN`-only and not available to the operator role.

Two tests pin the distinction from both sides:
`test_DeprecatedBlocksIssuanceButBacksExistingCredentials`, `test_RevokedBlocksEverything`, and
mutation `M9-deprecated-provider-invalidates` proves the suite catches the collapse — the opposite
error to `M5-untrusted-provider-allows`, and the one this repository's docs warn about most.

### 2.3 New providers start `Paused`

```solidity
p.status = uint8(ProviderStatus.Paused);
```

`registerProvider` hard-codes `Paused` on creation. An adapter must be registered, reviewed, schema
support declared, and explicitly activated before it can influence any decision.

This is deliberate: provider registration is a trust decision, and a new entry should not be able to
mint credentials the moment it exists. `test_NewProviderStartsPaused` pins it.

There is no automatic path from `registerProvider` to `Active`. A human has to make that call.

## 3. Schema support

```solidity
_schemaSupport[providerId][credentialType][schemaVersion] -> bool
```

Per **(provider, credential type, schema version)**. Checked at issuance by
`ComplianceGateway._validate` step 6:

```solidity
if (!PROVIDERS.supportsSchema(r.providerId, r.credentialType, r.schemaVersion)) {
    revert ProviderNotAdmitted(r.providerId, r.credentialType, r.schemaVersion);
}
```

Note the schema version is part of the key. A provider that supported `kyc.basic` v1 does not thereby
support v2 — the attribute set, the evidence format, and the verification depth may all differ, and a
credential asserting v2 against a v1 review would be a misrepresentation.

`setSchemaSupport` can be withdrawn (`supported = false`), which blocks future issuance immediately
without touching existing credentials. `test_SchemaSupportIsPerTypeAndVersion` and
`test_SchemaSupportCanBeWithdrawn` cover both.

Because `schemaVersion` is in the CCID preimage, a v1 and a v2 credential are different identities —
which is what makes withdrawal safe: the old records stay intelligible and the new ones are refused.

## 4. Registration sequence

```solidity
registerProvider(providerId, metadataURI)            // PROVIDER_ADMIN -> status = Paused
setSchemaSupport(providerId, credentialType, v, true) // PROVIDER_ADMIN
setProviderStatus(providerId, ProviderStatus.Active)  // PROVIDER_ADMIN -> now usable
setMetadataURI(providerId, newUri)                    // PROVIDER_ADMIN, optional, any time
```

| Revert | Condition |
| --- | --- |
| `NotProviderAdmin` | Caller lacks `PROVIDER_ADMIN` |
| `EmptyProviderId` | `providerId == 0` |
| `ProviderAlreadyRegistered` | The id is already registered |
| `MetadataUriTooLong` | Over `MAX_METADATA_URI_LENGTH` (512) |
| `ProviderNotRegistered` | Status/schema/metadata change on an unregistered id |

Reactivation to `Active` clears `failureCount`, so an operator bringing a provider back does not
inherit a stale alert (`test_ReactivationClearsFailureCounter`).

### 4.1 `setProviderStatus` has no range check, on purpose

```solidity
function setProviderStatus(bytes32 providerId, ProviderStatus status) external onlyProviderAdmin
```

There is no in-body range check. The parameter is the `ProviderStatus` enum, so solc's ABI decoder
already rejects any out-of-range calldata value before the body runs. An in-body check on an enum
parameter would be unreachable code implying a guarantee the compiler — not this function — is
providing.

`ProviderRegistryTest.test_OutOfRangeStatusRejectedViaRawCalldata` pins that behaviour so it is a
tested fact rather than an assumption: it calls with a raw `uint8(99)`, asserts the call fails, and
asserts the stored status is unchanged. It also pins that the revert carries **no return data** —
solc's decoder does a bare `revert(0, 0)` rather than `Panic(0x21)`, which in a raw trace is
indistinguishable from an out-of-gas and would be a behaviour change worth noticing.

## 5. Heartbeats and failure reports are monitoring only

```solidity
function heartbeat(bytes32 providerId) external onlyProviderOperator
function reportFailure(bytes32 providerId) external onlyProviderOperator
function isProviderHealthy(bytes32 providerId) external view returns (bool)
function heartbeatAge(bytes32 providerId) external view returns (uint64)
HEARTBEAT_STALENESS_SECONDS = 7 days
```

`heartbeat` rejects out-of-order reports with `StaleHeartbeat` when `block.timestamp < lastHeartbeat`.
`heartbeatAge` returns `type(uint64).max` when a provider has never been seen, so a never-seen
provider is distinguishable from one last seen a very long time ago.

`isProviderHealthy` requires **all** of: registered, `Active`, `failureCount == 0`, and a heartbeat
within `HEARTBEAT_STALENESS_SECONDS`.

### 5.1 These MUST NOT feed the access path

**A stale heartbeat does not deny access. This is a hard design constraint, not an oversight.**

`isProviderHealthy` is a monitoring view. Nothing in `PoolComplianceModule._evaluate`,
`ComplianceGateway._validate`, or `CrossChainComplianceReceiver._accept` calls it or reads
`lastHeartbeat` or `failureCount`.

**Why.** If liveness fed policy, then a missed heartbeat would become a denial of service against
every holder whose credential that provider signed. Consider what that looks like operationally: the
adapter is healthy, issuance works fine, nothing has actually gone wrong — but a scheduled liveness
job was delayed by a provider API hiccup, and every investor in the pool is now refused access. The
adversary does not even need to attack the provider; they just need to make its heartbeat late.

Conversely, the failure this avoids is the tempting one: "if the provider is down, we cannot rely on
its attestations." That reasoning confuses *current availability* with *historical soundness*. A
credential signed three months ago was signed correctly; the provider's silence today says nothing
about that. The correct response to an untrustworthy provider is `Revoked`, a human decision — not a
timeout.

So: **monitor, alert, and let a human decide.** `isProviderHealthy` returning false is a page, not a
policy outcome.

`test_HeartbeatStalenessIsAMonitoringSignalNotADenial` and `test_HeartbeatRejectsOutOfOrderReports`
pin both the separation and the ordering rule.

`PROVIDER_OPERATOR` cannot change status. Health reporting is deliberately a lower privilege than
provider governance — an operator who could both stall and revoke could weaponize a transient
outage.

## 6. `metadataURI`, and being honest about what is not there

`metadataURI` is the repository's only free-form storage field: a `bytes32`-identified documentation
pointer, bounded at 512 bytes, written by `PROVIDER_ADMIN`. It is allowlisted explicitly in
`scripts/check-no-dynamic-storage.mjs` — named, rather than exempting the whole contract, so a
second `string` on the same contract still fails.

### 6.1 What this repository does not have

Stated plainly, because a reader comparing this against another system will otherwise assume it is
present:

| Thing | Status |
| --- | --- |
| A mock provider adapter | **Not present.** `workflows/src/adapters/` is empty. |
| Any real provider integration | **None.** No vendor, no API client, no partnership. |
| Adapter metadata transport | **Not implemented.** There is no code in this repository that fetches, parses, validates, or displays anything at `metadataURI`. There is no `MetadataTransportNotConfiguredError` because there is no metadata transport to be unconfigured. |
| Provider key custody | **Off-chain and unspecified.** Nothing here manages a vendor API key. |
| Vendor response normalization | **Not implemented.** This is the core of what you must build. |
| Rate limiting, retry, backoff | **Not implemented.** |

`ProviderRegistry` stores a URI and bounds its length. Everything else about adapters is unimplemented
by design — the on-chain surface is deliberately the smallest thing that can support a real adapter,
so that a reviewer of the contracts is not also reviewing an HTTP client.

## 7. What an integrator must implement and review

### 7.1 The off-chain workflow (yours)

For each verification, off chain:

1. **Collect** the holder's information from the vendor.
2. **Verify** it — sanctions, PEP, adverse media, document authenticity. **The chain checks that an
   attestation is coherent, not that it is true.**
3. **Compute `subjectCommitment`** as a salted commitment. The salt stays in the workflow's secret
   store and never reaches the chain. Use a proper HMAC over the verified attribute or a keyed
   commitment — **not** the SDK's `saltedSubjectCommitment`, whose own doc comment says not to use it
   in production.
4. **Compute `evidenceHash`** over the vendor's evidence artifact.
5. **Derive the CCID** with `CCIDResolver.compute` semantics (or the SDK's `computeCcid`).
6. **Submit** to `ComplianceGateway.submitCredentialResult` as `WORKFLOW_SUBMITTER`.
7. **Propagate sensitive-data handling**: raw vendor responses must never be logged, never written to
   chain, and never left in workflow logs. Consider confidential compute as the processing boundary
   where supported.

### 7.2 Review checklist

Before your adapter is activated on any real deployment, confirm each of these. They are the
questions whose answers are not derivable from the contracts.

| # | Question |
| --- | --- |
| 1 | Is `subjectCommitment` computed with a key that never leaves the workflow's secret store? |
| 2 | Is the salt discarded after use, or at least never persisted alongside the commitment? |
| 3 | Is `evidenceHash` computed over the actual evidence, salted per-verification so two identical verifications do not produce the same hash? |
| 4 | Are raw vendor responses excluded from every log, trace, and error message the workflow produces? |
| 5 | Does the workflow refuse to submit when the vendor response is partial, ambiguous, or an error envelope? |
| 6 | Does `jurisdictionCode` come from a verified source rather than a self-declared field the holder filled in? |
| 7 | Does `investorClass` come from a documented accreditation determination rather than a holder checkbox? |
| 8 | Can a holder influence `nonce`? It must strictly increase per CCID, and a workflow replaying a result must not reuse one. |
| 9 | Is the nonce derived from a monotonic per-CCID counter on your side, so a restarted workflow cannot reissue at the same value? |
| 10 | Is the `WORKFLOW_SUBMITTER` key held in an HSM or managed signer, with rotation rehearsed? |
| 11 | Have you tested what your workflow does when `submitCredentialResult` reverts? It must not retry blindly with the same nonce. |
| 12 | Have you tested a provider outage? The answer must be "stop issuing", not "deny existing holders". |
| 13 | Is the adapter's schema version declared in `setSchemaSupport` matching what your workflow actually asserts? |
| 14 | Do you have a documented path to `Deprecated` the old provider on migration, rather than `Revoked`? |

### 7.3 What the contracts will not tell you

Three failure modes the on-chain validation cannot catch, so they must be handled off chain:

| Failure | Why the chain misses it |
| --- | --- |
| A false attestation (vendor said approved, it was not) | The gateway checks coherence, not truth. |
| A wrong jurisdiction or class from a manipulated source | The value is inside the CCID preimage, so it is *consistent*; consistency is not correctness. |
| PII leakage inside the workflow | Nothing off chain reaches the contracts. |

The contracts' guarantee is precise: a compromised workflow **can refuse a credential but cannot
invent one, extend its life, misstate a jurisdiction, or attribute it to a paused provider.** Its
worst outcome is denial of service. That guarantee is worth having and it is not the same as
"the workflow is correct".

## 8. Cross-chain provider status is per destination

`CrossChainComplianceReceiver._accept` checks `PROVIDERS.backsExistingCredentials(m.providerId)`
against the **destination's own** `ProviderRegistry`:

```solidity
if (!PROVIDERS.backsExistingCredentials(m.providerId)) {
    emit CredentialReplicaRejected(m.ccid, m.nonce, "PROVIDER_UNAVAILABLE");
    revert ProviderUnavailable(m.providerId);
}
```

**Checked per destination, so pausing a provider in one jurisdiction does not depend on propagation
from another.** A destination that has revoked a provider rejects that provider's replicas
immediately and locally, without waiting to hear about it from the source chain.

This has a direct operational consequence: **you must register and status providers on every
destination chain yourself.** A replica will be refused with `ProviderUnavailable` for a provider
that is `Active` on the source and simply not registered locally. There is no automatic
provider-state propagation — only credential state propagates.

`test_ReceiverRejectsWhenProviderNoLongerBacksCredentials` and
`test_ReceiverAcceptsFromDeprecatedProvider` cover both directions, including that `Deprecated` is
accepted.

## 9. Rejection reasons a provider issue produces

| Where | Code or error | Meaning |
| --- | --- | --- |
| Issuance | `ProviderNotActive(providerId)` | Provider not registered or not `Active`. Checked before anything else about the provider. |
| Issuance | `ProviderNotAdmitted(providerId, credentialType, schemaVersion)` | Provider is `Active` but does not declare support for this schema. |
| Policy | `PROVIDER_PAUSED` | `backsExistingCredentials` is false: `Paused`, `Revoked`, or unregistered. Reported for both, so the holder sees one class of answer. |
| Propagation | `ProviderUnavailable(providerId)` | The destination cannot accept a replica from this provider. |
| Policy status | `Active`, `Paused`, `Deprecated`, `Revoked`, `Unrecognized` | Via `getProviderStatus`. |

Note that the policy path reports `PROVIDER_PAUSED` even when the status is `Revoked`. That is
intentional: the holder's actionable answer is "we cannot rely on who verified this", and
distinguishing "temporarily paused" from "revoked for compromise" in a reason code the holder sees
would leak operational detail about an incident.

## 10. Quick reference

| Constant | Value |
| --- | --- |
| `MAX_METADATA_URI_LENGTH` | 512 |
| `HEARTBEAT_STALENESS_SECONDS` | 7 days |
| New provider status | `Paused` |
| Roles | `PROVIDER_ADMIN` (governance), `PROVIDER_OPERATOR` (health reporting only) |
| Role hierarchy | `DEFAULT_ADMIN_ROLE → PROVIDER_ADMIN → PROVIDER_OPERATOR` |

| View | Answers |
| --- | --- |
| `getProvider(providerId)` | The full `Provider` struct. |
| `getProviderStatus(providerId)` | The status enum. |
| `isActive(providerId)` | Issuance gate. |
| `backsExistingCredentials(providerId)` | Policy gate. `Deprecated` returns **true**. |
| `supportsSchema(providerId, credentialType, schemaVersion)` | Schema admission. |
| `isProviderHealthy(providerId)` | Monitoring only. **Never** a policy input. |
| `heartbeatAge(providerId)` | Seconds since last heartbeat, or `type(uint64).max`. |