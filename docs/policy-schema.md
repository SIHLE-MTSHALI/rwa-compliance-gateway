# Policy schema

`PoolPolicy` is the issuer's configuration for one pool. This document describes every field, its
semantics, and the reasoning behind the choices that a reviewer would otherwise have to infer.

None of this constitutes legal or regulatory advice. Whether any pool's policy satisfies a
jurisdiction's rules is a question for qualified counsel.

## 1. The struct

```solidity
struct PoolPolicy {
    bytes32       poolId;
    uint32        version;
    bool          active;
    bool          registered;
    bool          requiresManualReview;
    bool          requiresFreshReplica;
    uint16[]      acceptedJurisdictions;
    InvestorClass[] acceptedInvestorClasses;
    uint64        maxReplicaAge;
    uint256       maxAllocationPerInvestor;
    RevocationMode revocationMode;
    uint64        effectiveAt;
    uint64        createdAt;
}
```

7 storage slots (224 bytes), plus the two dynamic arrays. Registered by
`PoolPolicyManager.registerPolicy`, activated by `activatePolicyVersion`.

## 2. Fields

### `poolId`

`bytes32`. The pool this policy governs. Convention in tests and examples is a hash of a label
(`keccak256("pool.treasury")`); the contract only requires non-zero
(`PoolNotRegistered` on `bytes32(0)`).

The pool's own accounting contract is the natural referent, since allocation is read from there
rather than stored here.

### `version`

`uint32`. Assigned automatically as `latestVersion[poolId] + 1`; a caller cannot choose it.

**Why versions rather than mutable fields.** Without immutability, "integrate against version 3" is
a claim with nothing behind it — a later `registerPolicy` could silently change what version 3 means,
and an integrator would have no way to detect it. Versioning is what makes policy auditable *and*
what makes the activation delay (§7) enforceable.

`VersionMustIncrease` fires if the computed version would be `0`.

### `active`

`bool`. Whether this version is the one in force. **The only field that ever changes after
registration.** Activation sets it `true`; supersession sets the previous version's to `false`.

The invariant suite asserts the material fields are otherwise immutable by capturing a digest of each
version at registration and re-checking it:
`invariant_registeredPolicyVersionsAreImmutable`.

### `registered`

`bool`. Exists as a distinct flag so deactivation is reversible.

Collapsing `registered` into `active` would mean deactivating a policy destroyed the record of what
it said, and a past decision could no longer be explained. `deactivateActivePolicy` "closes a pool to
new access while leaving the policy readable" — a distinction that matters to an auditor long after
the fact.

`registered` is set at registration and never cleared.

### `requiresManualReview`

`bool`. Forces every otherwise-valid request into `ReviewRequired` / `MANUAL_REVIEW_REQUIRED`.

Checked **last** in the evaluation order, after every denial. A review requirement is a routing
instruction, not a defect, so it must never mask a real denial — otherwise a suspended credential
would be sent to a review queue instead of rejected, and the review requirement would make the
system's actual denials less visible.

Forces `Decision.ReviewRequired`, never `Decision.Allow`. `test_ManualReviewIsNotAnAllow` and
`test_ReviewRequirementDoesNotMaskARealDenial` pin both properties.

Use it for a rollout period, a new jurisdiction, or any state where a human should confirm before
capital is deployed.

### `requiresFreshReplica`

`bool`. Reject replicas older than `maxReplicaAge`.

Opt-in and off by default. A replica is a cache of another chain's state; this is how a pool refuses
to act on a cache it can no longer vouch for. Checked **per replica** — a locally issued credential
is never subject to the freshness test, because it is local truth rather than a cache.

Only reached for records where `getPropagationState(ccid).isReplica` is true.

### `acceptedJurisdictions`

`uint16[]` of ISO 3166-1 numeric codes. **Empty means all jurisdictions are permitted.**

```solidity
if (p.acceptedJurisdictions.length == 0) return true; // empty means all
```

**Why empty-means-all is safe here.** An empty list is the most permissive setting, so a mistake
omitting the field *widens* the pool rather than narrowing it — which is the loud failure: every
credential that should have been excluded now passes, and the mismatch is visible in access patterns.
The opposite default would make a mistake quietly exclude a whole country, which is the quiet
failure. Widening is the recoverable direction.

The asymmetric case is `acceptedInvestorClasses`, where empty is **not** means-all. See §2.2.

Bounded at `MAX_JURISDICTIONS = 64`, which is a gas bound on the linear scan in
`isJurisdictionAccepted`.

`0` is rejected by the gateway at issuance (`JurisdictionUnset`), so listing it would produce a
policy entry that can never match a real credential.

### 2.2 `acceptedInvestorClasses`

`InvestorClass[]`. **Empty means all classes except `Blocked`.**

```solidity
if (p.acceptedInvestorClasses.length == 0) {
    // An empty list never implicitly accepts `Blocked`. An issuer must opt
    // in to serving blocked investors explicitly.
    return cls != ComplianceTypes.InvestorClass.Blocked;
}
```

**Why this field is the opposite of the jurisdiction field.** With `acceptedJurisdictions`, an empty
list widening access is loud and recoverable. Here the empty list would mean admitting a class
explicitly defined as *blocked* — a holder the issuer or a provider has affirmatively marked as
ineligible. That is the one case where the default must be conservative, because the widening is
silent: nothing looks wrong, the credential simply passes.

So `Blocked` requires a deliberate opt-in:

```solidity
acceptedInvestorClasses = [InvestorClass.Blocked]
```

`test_BlockedInvestorNeverImplicitlyAccepted` and `test_BlockedInvestorAcceptedWhenExplicitlyOptedIn`
pin both directions. `PoolComplianceModule` reports a blocked-but-unlisted holder as
`INVESTOR_CLASS_BLOCKED`.

Note the gateway does not reject `investorClass == Blocked` at issuance — a blocked investor can hold
a credential, because the denial is a *pool policy* question, not a credential question. Rejecting
at issuance would make the denial unexplainable to the holder.

Bounded at `MAX_CLASSES = 4`, which is a sanity bound rather than a gas bound: there are only four
enum values.

### `maxReplicaAge`

`uint64` seconds. Only consulted when `requiresFreshReplica` is true.

Measured against `REGISTRY.ageOf(ccid)` — seconds since the record was last written.

```solidity
uint64 tolerance = policy.maxReplicaAge == 0 ? 1 days : policy.maxReplicaAge;
```

**Zero means one day, not zero tolerance.** Setting `requiresFreshReplica = true` and forgetting the
age yields a usable policy. Treating zero as "no tolerance" would deny every replica permanently,
which is a silent permanent denial — the worst way for a flag to be misconfigured.

Evaluated only when `requestedAmount` and eligibility have already passed, so the holder is told
"we cannot currently confirm your eligibility" rather than "you are over your cap", which they may
dispute.

### `maxAllocationPerInvestor`

`uint256`, in the pool's accounting token. **Zero means uncapped.**

```solidity
if (p.maxAllocationPerInvestor == 0) return false;
return totalRequested > p.maxAllocationPerInvestor;
```

**Why zero means uncapped.** Zero is the natural "not configured" value and is
indistinguishable from a cap of zero. Treating zero as a cap would reject *everything* — a pool with
a default-constructed policy would refuse all access, and the reason (`ALLOCATION_CAP_EXCEEDED`)
would be actively misleading. A pool that wants a cap must set one; the failure mode of forgetting
is no cap, which is visible.

Note the comparison is **strictly above**: a total exactly equal to the cap is allowed
(`test_CapBoundaryIsInclusive`).

**The cap is checked against the total, not the increment:**

```solidity
uint256 total = request.currentAllocation + request.requestedAmount;
```

Checking the increment alone would let a holder already at the cap add another full cap's worth.
Mutation `M10-allocation-cap-ignores-current-holding` exists to prove the suite catches the
regression.

`currentAllocation` is a **caller-supplied argument**, not a registry read — allocation lives in the
pool's accounting, and duplicating it here would create two sources of truth that drift. The
consequence: the cap is only as good as the value the integrator passes. See
[`audit-readiness.md`](./audit-readiness.md).

`requestedAmount == 0` skips the check entirely, which is how a caller asks a pure eligibility
question (`test_ZeroAmountRequestStillEvaluatesEligibility` — eligibility is still evaluated).

### `revocationMode`

`RevocationMode`, decided **per policy version**.

```solidity
enum RevocationMode { IssuerOnly, HolderOrIssuer, GovernanceOnly }
```

| Value | Meaning | Effect in `_requireRevocationAuthority` |
| --- | --- | --- |
| `IssuerOnly` | The issuer administers the credential. | Issuer admitted; governance also admitted; holder always admitted. |
| `HolderOrIssuer` | Either the holder or the issuer may act. | Same as above in practice — `HOLDER` and `ADMIN` are checked before the mode is read, so the mode only matters in excluding the issuer. |
| `GovernanceOnly` | Governance only; the issuer is deliberately excluded. | `ISSUER` → `RevocationNotPermitted`. |

`GovernanceOnly` excludes the issuer on purpose: a governance-scoped credential the issuer could
withdraw unilaterally would not be governance-scoped.

Two behaviours are unconditional, and the mode does not override them:

- A `HOLDER` may **always** withdraw their own credential. Checked before policy is consulted. A
  holder must always be able to exit; anything else is a trap.
- An `ADMIN` (governance) may always revoke.

With no registered active policy for the pool, the issuer is admitted. That keeps single-pool
deployments working before policies are configured.

Covered by `test_GovernanceOnlyPolicyExcludesIssuer`,
`test_HolderCanAlwaysWithdrawTheirOwnCredential`, and `test_OutsiderCannotRevoke`.

### `effectiveAt`

`uint64`. Timestamp from which this version applies, as supplied by the issuer.

Stored verbatim. It is **not** consulted by `activatePolicyVersion` — that function gates on
`createdAt + POLICY_ACTIVATION_DELAY`, not on `effectiveAt`. So `effectiveAt` is currently a
declaration the issuer records for its own readers rather than an enforced gate. An integrator
comparing versions should read the active version via `activeVersion(poolId)` rather than filtering
on `effectiveAt`.

### `createdAt`

`uint64`. `block.timestamp` at registration. **This is the value the activation delay runs from:**

```solidity
uint64 activateAfter = p.createdAt + POLICY_ACTIVATION_DELAY;
```

The `PolicyRegistered` event emits `activateAfter` as `0`; `notifyPending(poolId, version)` emits the
real `p.createdAt + POLICY_ACTIVATION_DELAY`, and `getPolicy` returns `createdAt` so an operator can
compute it. The SDK's `PolicyClient.register` returns `activatableAt` and
`secondsUntilActivatable` so a rollout can be planned rather than discovered on revert.

## 3. Worked examples

These are the argument objects for `registerPolicy`. The SDK's `PolicyClient.register` takes exactly
these fields, each with a documented default.

### 3.1 Permissive

An open pool: any jurisdiction, accredited and non-US professionals, no cap, no review.

```json
{
  "poolId": "0x706f6f6c2e7472656173757279000000000000000000000000000000000000000000",
  "requiresManualReview": false,
  "acceptedJurisdictions": [],
  "acceptedInvestorClasses": [1, 2],
  "requiresFreshReplica": false,
  "maxReplicaAge": 0,
  "maxAllocationPerInvestor": 0,
  "revocationMode": 0,
  "effectiveAt": 0
}
```

Reads as: all jurisdictions (empty list), classes `USAccredited` (1) and `NonUSProfessional` (2) —
`Blocked` (3) not listed, so excluded; no review; no freshness requirement; uncapped; issuer
administers.

### 3.2 Accreditation-only

A US-only, accredited-investors-only pool with a per-investor cap.

```json
{
  "poolId": "0x706f6f6c2e75732d616363726564000000000000000000000000000000000000000000",
  "requiresManualReview": false,
  "acceptedJurisdictions": [840],
  "acceptedInvestorClasses": [1],
  "requiresFreshReplica": true,
  "maxReplicaAge": 86400,
  "maxAllocationPerInvestor": "1000000000000000000000",
  "revocationMode": 0,
  "effectiveAt": 0
}
```

`840` is the United States. `1` is `USAccredited` — a `NonUSProfessional` holding a US-accredited
class would be rejected at issuance anyway (the class is in the CCID preimage), and a non-840
jurisdiction is refused with `JURISDICTION_BLOCKED`.

`maxReplicaAge` 86400 = 1 day, so a destination replica older than a day is refused with
`STALE_DESTINATION`.

`maxAllocationPerInvestor` is 1000 × 10^18. A holder whose `currentAllocation + requestedAmount`
exceeds it is refused with `ALLOCATION_CAP_EXCEEDED`.

### 3.3 Governance-only revocation

A regulated pool where the issuer must not be able to withdraw credentials unilaterally.

```json
{
  "poolId": "0x706f6f6c2e726567756c61746564000000000000000000000000000000000000000",
  "requiresManualReview": true,
  "acceptedJurisdictions": [],
  "acceptedInvestorClasses": [1, 2],
  "requiresFreshReplica": false,
  "maxReplicaAge": 0,
  "maxAllocationPerInvestor": "500000000000000000000",
  "revocationMode": 2,
  "effectiveAt": 0
}
```

`revocationMode: 2` is `GovernanceOnly`. An `ISSUER` calling `revoke` gets
`RevocationNotPermitted`. `HOLDER` and `ADMIN` still work — a holder must always be able to exit.

`requiresManualReview: true` routes every otherwise-valid request to a human first.

### 3.4 Review-required rollout

A new jurisdiction, brought in under review before it is opened.

```json
{
  "poolId": "0x706f6f6c2e72656c617573650000000000000000000000000000000000000000000",
  "requiresManualReview": true,
  "acceptedJurisdictions": [840, 826, 392, 643],
  "acceptedInvestorClasses": [1, 2],
  "requiresFreshReplica": true,
  "maxReplicaAge": 3600,
  "maxAllocationPerInvestor": 0,
  "revocationMode": 1,
  "effectiveAt": 0
}
```

All jurisdictions in the CCID vector set: US, UK, Japan, Russia. One hour of replica tolerance. No
allocation cap. `revocationMode: 1` is `HolderOrIssuer`.

Every eligible holder gets `Decision.ReviewRequired` / `MANUAL_REVIEW_REQUIRED` until a new version
drops the flag — which means waiting out another `POLICY_ACTIVATION_DELAY`. Plan for it.

Note the ordering consequence: a holder who is *also* over their cap, or whose replica is stale, gets
`ALLOCATION_CAP_EXCEEDED` or `STALE_DESTINATION` — never `MANUAL_REVIEW_REQUIRED`. The review flag
never masks a real denial.

## 4. Registration and activation

```solidity
registerPolicy(
    poolId, requiresManualReview, acceptedJurisdictions, acceptedInvestorClasses,
    requiresFreshReplica, maxReplicaAge, maxAllocationPerInvestor, revocationMode, effectiveAt
) external onlyIssuerAdmin
```

Reverts:

| Error | Condition |
| --- | --- |
| `NotIssuerAdmin` | Caller lacks `ISSUER_ADMIN` |
| `PoolNotRegistered` | `poolId == 0` |
| `TooManyJurisdictions` | More than 64 jurisdictions |
| `TooManyClasses` | More than 4 classes |
| `VersionMustIncrease` | Computed version would be `0` |

Registration does **not** activate. `active` starts `false`.

```solidity
activatePolicyVersion(poolId, version) external onlyIssuerAdmin
```

Reverts `PoolNotRegistered` if the version was never registered, and `ActivationDelayNotElapsed(activateAfter, nowTs)`
until `block.timestamp >= createdAt + POLICY_ACTIVATION_DELAY`.

Activation deactivates the previously active version, so **exactly one version is active per pool at
a time**. Two active versions would give integrators two different answers for the same request
depending on which they read — `invariant_atMostOneActivePolicyVersionPerPool` guards it.

`deactivateActivePolicy(poolId)` closes a pool to new access without replacing its policy. Reverts
`NoVersionRegistered` if `activeVersion == 0`.

`notifyPending(poolId, version)` emits `PolicyPending` with the real activation timestamp. Read-only
in effect, and useful for an operator dashboard.

## 5. Read-only surface

| Function | Answers |
| --- | --- |
| `getPolicy(poolId, version)` | The full struct for any registered version. |
| `getActivePolicy(poolId)` | The active version, or a zeroed struct when none. |
| `hasActivePolicy(poolId)` | "A version is selected **and** that version is active." Folds both, so a caller cannot pass a check while the policy behind it is off. |
| `hasAnyPolicy(poolId)` | "Any version was ever registered." The counterpart, and the reason `POOL_NOT_REGISTERED` and `POLICY_INACTIVE` are two codes. |
| `isPolicyDeactivated(poolId)` | "Selected but switched off." |
| `activeVersion(poolId)` / `latestVersion(poolId)` | The pointers. |
| `isJurisdictionAccepted(poolId, version, code)` | Empty-means-all scan. |
| `isInvestorClassAccepted(poolId, version, cls)` | Empty-means-all-except-`Blocked` scan. |
| `exceedsAllocationCap(poolId, version, total)` | Zero-cap-means-uncapped. |
| `POLICY_ACTIVATION_DELAY()` | `7 days`. |
| `MAX_JURISDICTIONS()` / `MAX_CLASSES()` | `64` / `4`. |

`PoolComplianceModule` reads `activeVersion`, then `getPolicy`, then re-checks `registered && active`
on the struct it got — belt and braces, because the pointer and the flag should agree and a
disagreement is worth refusing over.

## 6. Version pinning: what an integrator can rely on

1. A registered version's material fields never change. Only `active` moves.
2. Version numbers only increase. Re-registering at the same number is impossible.
3. At most one version is active per pool at any time.
4. `activeVersion(poolId)` names the version that will be evaluated.

So an integrator that pins `version = 3` can hold that value and read `getPolicy(poolId, 3)` to
display exactly the rules its integration was written against — even after versions 4, 5, and 6 have
been registered and activated. That is the property the immutability requirement exists to provide,
and it is what makes the activation delay (§7) enforceable rather than advisory: a window in which
holders can see a change coming, and respond to it, before it binds.

## 7. The activation delay, and the attack it prevents

```solidity
uint64 public constant POLICY_ACTIVATION_DELAY = 7 days;
```

### 7.1 The attack

Without a delay, an issuer — or someone holding a compromised issuer key — could:

1. Register a policy with `acceptedJurisdictions: []` narrowed to a single code, or
   `acceptedInvestorClasses: [USAccredited]` on a pool that serves professionals, or
   `maxAllocationPerInvestor: 1`.
2. Activate it in the next block.
3. Every existing investor becomes instantly ineligible.

Nobody gets a window in which to notice. Holders discover it by being refused access. Pool operators
discover it from support tickets. And because nothing about the change looks wrong on chain — a
version bump and an activation are ordinary events — there is no signal to alert on.

Policy that can change without notice is indistinguishable from arbitrary denial.

The delay makes the sequence observable: `PolicyRegistered` fires, `PolicyPending` reports the
activation timestamp, and for seven days the incumbent version stays in force. Holders and operators
can read the pending version, understand what changes, and — for a legitimate tightening — re-verify
before it binds. For an illegitimate one, governance has a week in which to react.

`test_ActivationBlockedBeforeDelay` and `test_ActivationAllowedAtDelay` pin both sides; mutation
`M11-activation-delay-removed` proves the suite catches its removal.

### 7.2 Operating consequence

A policy change is a two-week operation from intent to effect:

| Day | Step |
| --- | --- |
| 0 | `registerPolicy(...)` → `PolicyRegistered` |
| 0 | `notifyPending(poolId, version)` → `PolicyPending(activateAfter)` |
| 0–7 | Read `getPolicy(poolId, version)` and diff it against `getPolicy(poolId, activeVersion)` |
| 7 | `activatePolicyVersion(poolId, version)` → `PolicyActivated` |

Plan the rollout accordingly. See
[`operations-runbook.md`](./operations-runbook.md#4-policy-rollout).

Note the delay runs from `createdAt`, not from a separately chosen timestamp. There is no way to
shorten it, and no way to register a version with a retroactive activation — which is the point.

## 8. Validation errors an integrator will see

| Error | Meaning |
| --- | --- |
| `NotIssuerAdmin` | The caller is not `ISSUER_ADMIN`. |
| `PoolNotRegistered` | Either `poolId == 0` on registration, or `activatePolicyVersion` named a version that was never registered. Distinct from `InvalidAdminAddress` so a bad constructor argument is not reported as an unknown pool. |
| `TooManyJurisdictions` / `TooManyClasses` | Over the bounds. |
| `ActivationDelayNotElapsed` | Attempted activation before the week was up. |
| `VersionMustIncrease` | Computed version overflowed to `0`. |
| `NoVersionRegistered` | `deactivateActivePolicy` on a pool with no active version. |

## 9. Design summary

| Choice | Alternative | Why this way |
| --- | --- | --- |
| Immutable versions | Mutable policy fields | Otherwise an integrator's pinned version is a claim with nothing behind it, and the activation delay is unenforceable. |
| 7-day activation delay | Immediate activation | Otherwise a compromised issuer key excludes every investor instantly with no notice window. |
| Exactly one active version | Multiple active versions | Otherwise two integrators get two different answers for the same request. |
| Empty jurisdictions = all | Empty = none | A mistake widening access is loud and recoverable; a mistake narrowing it is quiet. |
| Empty classes = all except `Blocked` | Empty = all | The one case where the widening is silent: a class explicitly marked ineligible is admitted without anyone choosing it. |
| `maxAllocationPerInvestor == 0` = uncapped | `== 0` = reject all | Zero is indistinguishable from a zero cap; treating it as a cap refuses everything and reports a misleading reason. |
| `maxReplicaAge == 0` = 1 day | `== 0` = no tolerance | A flag set without its age yields a usable policy rather than a permanent silent denial. |
| `registered` separate from `active` | One flag | Deactivation stays reversible and past decisions stay explainable. |
| Allocation read from the caller | Registry stores allocation | Two sources of truth drift. The cost is documented as a gap. |
| `RevocationMode` per policy | One global rule | Revocation authority is a property of the policy that admitted the holder, not of the credential. |
| `GovernanceOnly` excludes the issuer | Issuer always allowed | A credential the issuer could withdraw unilaterally would not be governance-scoped. |
| Holder may always withdraw | Mode decides | A holder must always be able to exit. Anything else is a trap. |
| `MANUAL_REVIEW_REQUIRED` last in order | Checked with the rest | A review requirement is a routing instruction, so it must never mask a real denial. |