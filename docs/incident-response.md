# Incident response

What to do when something goes wrong.

**No incident has ever occurred.** This repository has not been deployed to any network. Every
procedure below is written against the contracts as they exist, and has not been rehearsed against a
live system.

## 1. Pause and unpause are deliberately asymmetric

This asymmetry is the core of the emergency design and everything else in this document follows from
it.

| | Pause | Unpause |
| --- | --- | --- |
| Who | `GUARDIAN` | `TIMELOCK_ADMIN` schedules; **anyone** executes |
| Steps | 1 | 2 |
| Delay | None | `UNPAUSE_DELAY = 24 hours` |
| Reverts if wrong caller | `NotGuardian` | `NotTimelockAdmin` on schedule / `NotPaused` on execute |

**Stopping is cheap and reversible, so it should be instant.** **Resuming is the risky direction,
and it is exactly when pressure to resume is highest** — during an unresolved incident. Making resume
slow gives that pressure somewhere to land other than the pause itself.

### 1.1 What a pause does and does not do

| Effect | Detail |
| --- | --- |
| `evaluate` returns | `Deny` / `SYSTEM_PAUSED` for **every** request |
| Issuance | `submitCredentialResult`, `beginVerification`, `renewCredential` revert `SystemPaused` |
| Lifecycle | `revoke`, `suspend`, `resume` revert `SystemPaused` |
| Propagation | `sendCredentialState` reverts `SystemPaused` |
| Inbound replicas | `ccipMessageCallback` reverts `SystemPaused` |
| Registry / policy reads | **Still available** |

That last row is deliberate. A pause does not hide existing state: holders, integrators, and auditors
keep seeing what is true right now. A pause stops new decisions; it does not rewrite history.

Fail-closed is the safe direction. If the system cannot tell whether its own state is trustworthy,
it must not report that an investor is compliant. `invariant_pausedSystemAllowsNobody` asserts this.

### 1.2 Pausing

```solidity
function pause(string calldata reason) external  // GUARDIAN only
```

| Revert | Cause |
| --- | --- |
| `NotGuardian` | Caller lacks `GUARDIAN`. Note `ADMIN` is **not** implicitly a guardian. |
| `AlreadyPaused` | Already paused. |
| `ReasonTooLong` | Over `MAX_REASON_LENGTH` (256). |

One transaction. `GUARDIAN` **cannot** resume — `test_GuardianCannotResume` pins it. A compromised
guardian can stop the system and nothing else.

The reason string is public chain state. It must not contain investor data.

`pause` does not clear a pending unpause, because that would be unreachable: an unpause can only be
scheduled while paused, and `pause` rejects an already-paused system. The operator procedure for an
incident recurring inside the delay window is `cancelUnpause`.

## 2. Unpausing: two steps, and the timing trap

### 2.1 The trap

**`scheduleUnpause` and `executeUnpause` cannot both succeed in the same transaction. The 24-hour
delay must elapse AFTER the scheduling transaction.**

```solidity
function scheduleUnpause(string calldata reason) external {
    unpauseExecutableAt = uint64(block.timestamp) + UNPAUSE_DELAY;   // always in the future
    emit UnpauseScheduled(unpauseExecutableAt, reason);
    emit PauseStateChanged(false, reason);                          // <-- reads as "unpausing"
}

function executeUnpause() external {
    if (unpauseExecutableAt == 0) revert UnpauseNotScheduled();
    if (uint64(block.timestamp) < unpauseExecutableAt) {
        revert UnpauseDelayNotElapsed(unpauseExecutableAt, uint64(block.timestamp));
    }
    paused = false;
    unpauseExecutableAt = 0;
}
```

`block.timestamp` is the timestamp of the block that *includes* the scheduling call. Adding 24 hours to
it can only ever produce a time in the future, so an immediate `executeUnpause` always reverts with
`UnpauseDelayNotElapsed`. There is no batching that gets around it.

`test_SchedulingDoesNotUnpause` and `test_ExecuteBlockedUntilDelayElapses` pin both halves. Mutation
`M12-unpause-immediately-executable` proves the suite catches removal of the delay check.

### 2.2 A misleading event — worth knowing about

`scheduleUnpause` emits `PauseStateChanged(false, reason)` even though the system **remains paused**
for another 24 hours.

This is a genuine footgun: an automated monitor keying on `PauseStateChanged` will conclude the
system is live 24 hours before it is. Monitor `EmergencyControls.paused()` (or the
`UnpauseScheduled` / `UnpauseExecuted` events) as the source of truth, not
`PauseStateChanged(false)`.

### 2.3 The procedure

```
1. TIMELOCK_ADMIN: scheduleUnpause(reason)        -> UnpauseScheduled(executableAt, reason)
   (system is STILL PAUSED)
2. wait until executableAt has passed — at least 24 hours after step 1
3. anyone: executeUnpause()                       -> UnpauseExecuted
```

| Revert on step 1 | Cause |
| --- | --- |
| `NotTimelockAdmin` | Caller lacks `TIMELOCK_ADMIN`. |
| `NotPaused` | The system is not paused; there is nothing to unpause. |
| `ReasonTooLong` | Over 256 bytes. |

| Revert on step 3 | Cause |
| --- | --- |
| `NotPaused` | Not paused. |
| `UnpauseNotScheduled` | `scheduleUnpause` was never called. |
| `UnpauseDelayNotElapsed` | **Too early.** Wait. |

Re-scheduling resets the delay: `unpauseExecutableAt` is recomputed from the new `block.timestamp`
(`test_ReschedulingResetsTheDelay`).

### 2.4 Why `executeUnpause` is permissionless

The consent is already given: a `TIMELOCK_ADMIN` scheduled this, and the delay has passed. Requiring
the same key a second time adds no safety and creates a real failure mode — **a lost or rotated
timelock key would leave the system paused indefinitely, which is the worst outcome an emergency
control can produce.**

`test_AnyoneMayExecuteOnceEligible` pins it.

### 2.5 `cancelUnpause` is the safety valve

```solidity
function cancelUnpause() external   // TIMELOCK_ADMIN only
```

Clears `unpauseExecutableAt` and leaves the system paused. Reverts `NotTimelockAdmin` or `NotPaused`.

This is what makes the open execute window safe: whoever scheduled the unpause can withdraw it before
execution, so an open execute never outruns the operator's intent. `test_CancelUnpauseKeepsTheSystemPaused`
and `test_RecurringIncidentIsHandledByCancelling` cover it.

**Use it** when an incident recurs or the investigation reopens inside the window. The 24-hour window
is time to change your mind.

## 3. Playbooks

### A. Provider compromise

The provider's attestations are no longer trustworthy. Every credential it signed must stop granting
access.

**Order matters: revoke the provider first, sweep credentials second.**

```
1. PROVIDER_ADMIN: setProviderStatus(providerId, ProviderStatus.Revoked)
      -> ProviderStatusChanged(providerId, <previous>, Revoked)

   This is instant and complete for policy: every credential that provider signed now
   returns PROVIDER_PAUSED on every chain where the provider is registered, with no
   per-credential transaction and no dependence on propagation.

2. Repeat step 1 on EVERY destination chain.
   Provider state does not propagate. A destination that has not revoked the provider
   locally will keep accepting its replicas until it does.

3. Sweep the affected credentials for a clean audit trail:
   gateway.revoke(ccid, poolId, reason, destinations)   for each affected ccid

   Only if you need the record to say Revoked rather than PROVIDER_PAUSED.
   Pervasive, and see the gap in audit-readiness.md: there is no bulk revocation.

4. AuditTrail.recordProviderChange(providerId, actor, uint8(Revoked))
```

Why step 1 comes first: it is one transaction and it takes effect immediately, everywhere the
provider is registered. Sweeping credentials is cleanup — it improves the audit trail but is not what
stops access.

**Do not use `Paused` for a compromise.** Both statuses deny existing credentials — step 1 would work
either way — but they say different things. `Paused` means "stop for now, backlogged"; it carries no
finding that past attestations are untrustworthy. `Revoked` means "we no longer trust these
attestations". Recording a compromise as `Paused` misrepresents it to anyone reading the event log
later, and `ProviderStatusChanged` is the record that survives.

Also consider, in parallel:
- `EmergencyControls.pause(...)` if you believe live access must stop immediately and you cannot
  enumerate the affected credentials.
- `gateway.suspend(...)` per credential if you need to distinguish "under investigation" from
  "withdrawn" — `Suspended` is reversible, `Revoked` is terminal.

Watch: step 2 is the step that gets forgotten, and a destination that has not revoked the provider
will accept fresh replicas from the compromised source for as long as the source keeps sending.

### B. Compromised workflow submitter key

The `WORKFLOW_SUBMITTER` key is the Chainlink CRE workflow's signer.

**The worst outcome is denial of service.** That is bounded, recoverable, and — critically — the
compromised key **cannot mint**.

```
1. ADMIN: revokeRole(WORKFLOW_SUBMITTER, compromisedAddress)
2. ADMIN: grantRole(WORKFLOW_SUBMITTER, newWorkflowSigner)
3. Verify: gateway.hasRole(WORKFLOW_SUBMITTER, newSigner) == true
4. Review what the compromised key did while it held the role:
     - CredentialResultSubmitted log for unexpected ccids
     - Credentials created since the key's compromise window
```

#### What it cannot do

This is the security argument for the gateway's ten-step validation, and it is worth stating precisely
because it determines how urgent step 1 is:

| Cannot | Enforced by |
| --- | --- |
| Mint a credential for an arbitrary holder | `_validate` step 3 — the CCID must reproduce from the submitted fields |
| Extend a credential's life | `renewCredential` runs the identical `_validate` |
| Misstate a jurisdiction | Jurisdiction is in the CCID preimage (`test_JurisdictionSwapRejected`) |
| Misstate an investor class | Class is in the CCID preimage (`test_InvestorClassEscalationRejected`) |
| Attribute a credential to a paused provider | `_validate` step 4 — `isActive` |
| Attribute to a provider that does not admit the schema | `_validate` step 6 — `supportsSchema` |
| Set an expiry in the past | `_validate` step 7 |
| Replay an old result | Nonce must strictly increase (step 10) |
| Write an empty jurisdiction or class | Steps 8 — `JurisdictionUnset`, `InvestorClassUnknown` |
| Write without an evidence commitment | Step 9 — `ZeroEvidenceHash` |
| Write while the system is paused | Step 1 — `SystemPaused` |
| Write without the role | Step 2 — `NotAuthorized` |

#### What it can do

- **Refuse to issue.** Stop all new credentials. Holders cannot onboard.
- **Stop renewing.** Existing credentials lapse on schedule. Holders fall off over time, not instantly.
- **Flood transactions.** Cost and noise.
- **Choose `destinationChainSelectors`.** So a credential it issues can be propagated anywhere the
  sender will accept. This is the sharpest of the four: the destination lists are caller-supplied, and
  the sender's only constraints are non-empty, ≤10, no self-destination, nonce increasing, and the
  system not paused. **Propagation to an unintended chain is possible.** Mitigate by running your own
  relayer and monitoring `CredentialSent` events for unexpected destination selectors.
- **Delay issuance to create pressure.** The holder's experience degrades to `NO_CREDENTIAL` or
  `PENDING`.

**Why denial of service is acceptable here.** It is bounded, time-limited, and fixed by rotating one
role — no data is lost, no credential is invalidated, no pool's investors are wrongly excluded, and
recovering requires no migration. And the alternative — trusting the key to make irreversible
decisions — is strictly worse. A system where a compromised key can only stop the doors has already
reduced the blast radius to its floor.

**What this is not:** this is not "the compromised key is harmless". A sustained DoS denies every new
investor for as long as it lasts, and in a time-sensitive raise that is a real cost. Rotate promptly
and treat the window as an availability incident.

### C. Compromised issuer key

The `ISSUER` key can `suspend`, `resume`, and — unless the pool's policy is `GovernanceOnly` —
`revoke`.

**Cannot mint.** The issuer has no path to issuance; that is `WORKFLOW_SUBMITTER`. The issuer cannot
create a credential, extend one, or change a holder's jurisdiction or class.

**Can:**

| Action | Blast radius | Reversible? |
| --- | --- | --- |
| `suspend(ccid, ...)` | One credential denies. | Yes — `resume`. |
| `revoke(ccid, poolId, ...)` | One credential, **permanently**. | **No.** `Revoked` is terminal. |
| Repeated suspend/resume churn | Audit noise; possible gas griefing. | Yes. |

Under `RevocationMode.GovernanceOnly` the issuer **cannot revoke at all** —
`RevocationNotPermitted`. That is the point of the mode, and it is the control that bounds this
incident. See [`policy-schema.md`](./policy-schema.md#revocationmode).

```
1. Governance decides: suspend is reversible, revoke is not.
2. ADMIN: revokeRole(ISSUER, compromisedAddress)
3. ADMIN: grantRole(ISSUER, newIssuerKey)
4. Audit trail review for unintended lifecycle calls:
     CredentialLifecycleAction(ccid, "revoke"|"suspend"|"resume", status, reason)
   Each irrevocable revoke needs individual justification. This is where the lack of
   off-chain anchoring (audit-readiness.md) matters most.
```

The asymmetry to weigh: a compromised issuer key under `IssuerOnly` can destroy access permanently
for any credential, one transaction each, with no way back. `GovernanceOnly` is the mitigation for
regulated pools, and it is a policy choice made at registration — 7 days before it can be activated.

Note the registry refuses to resurrect a revoked credential via `renew` or any status transition
(`if (from == Revoked) return false`), so an issuer cannot accidentally undo a mistake.

### D. Compromised guardian key

`GUARDIAN` can do exactly one thing: `pause`. It **cannot** resume
(`test_GuardianCannotResume`), cannot revoke a credential, cannot write to the registry, cannot
change a policy, and cannot touch the audit trail.

**Worst outcome: a permanent denial of service until a `TIMELOCK_ADMIN` schedules and executes an
unpause.**

```
1. Confirm the pause was not legitimate: emergency.isPaused()
2. DEFAULT_ADMIN_ROLE: grantRole(GUARDIAN, newGuardian)
   (the admin of GUARDIAN is DEFAULT_ADMIN_ROLE — declared explicitly in the constructor,
    or the role would be permanently ungrantable and a handover impossible)
3. DEFAULT_ADMIN_ROLE: revokeRole(GUARDIAN, compromisedAddress)
4. TIMELOCK_ADMIN: scheduleUnpause(reason)
5. Wait 24 hours from step 4. Then: executeUnpause()  — anyone may do this
6. Investigate: PauseStateChanged carries the reason the attacker supplied.
```

The 24-hour window is a genuine cost here — a compromised guardian can buy the attacker 24 hours of
denial by pausing and letting the delay run. That is the price of an asymmetric control, and it is
bounded: the guardian cannot extend the pause indefinitely (a second `pause` reverts
`AlreadyPaused`), cannot prevent the unpause, and cannot do anything except deny access.

If the guardian and admin are the same address, the attacker's capability is far worse: they can pause
*and* schedule the unpause, at which point 24 hours later the system resumes under their control with
their own timeline. `Deploy.s.sol` refuses `GUARDIAN == ADMIN` for exactly this reason — verify it
held in your deployment.

### E. Stuck or missing guardian

The guardian key is lost, or the holder is unreachable.

**Impact: none, until an incident needs it.** The system operates normally. The failure appears at the
worst possible moment — the one where nobody can pause.

```
1. DEFAULT_ADMIN_ROLE: grantRole(GUARDIAN, newGuardian)     // rotate first
2. DEFAULT_ADMIN_ROLE: revokeRole(GUARDIAN, oldGuardian)
3. Verify: emergency.hasRole(emergency.GUARDIAN(), newGuardian)
```

Because `GUARDIAN`'s admin is declared as `DEFAULT_ADMIN_ROLE`, this is possible without the original
guardian. Had the role hierarchy not been declared, `AccessControl.grantRole` would resolve the admin
to `bytes32(0)` and revert — the role would be permanently ungrantable and an incident would have to
be handled by whichever address happened to be in the constructor. `test_GuardianKeyIsHandoverable`
pins the handover.

If `DEFAULT_ADMIN_ROLE` is also lost, the system cannot be reconfigured at all and the only remaining
controls are `TIMELOCK_ADMIN` (which needs the delay) and `POOL_POLICY_MANAGER`'s
`DEFAULT_ADMIN_ROLE` (a separate contract, a separate key). Keep the two admins distinct.

**Prevention:** multisig or HSM for the guardian; rehearse the rotation before you need it. A
guardian that cannot be rotated under pressure is not an emergency control.

### F. Revocation did not reach a destination chain

The source chain reports `Revoked`. A destination does not. This is the most consequential
propagation failure, because an operator checking the source sees the correct state while holders on
the destination are still admitted.

**Diagnose in this order:**

```
1. Read the destination's view of the credential:
     destRegistry.getRecord(ccid)                  -> status, nonce
     destRegistry.getPropagationState(ccid)        -> isReplica, lastSourceNonce
   If lastSourceNonce < the source record's nonce, the revocation never arrived.

2. Read the source:
     sender.getLastSentNonce(ccid)                 -> highest dispatched
     sender.hasSentTo(ccid, destSelector)          -> ever dispatched (a query, not a skip-list)
   If getLastSentNonce < the record's nonce, the send itself failed.

3. Check for the two propagation regressions:
     a) Per-destination dedup  -> the send would have been skipped because the
        destination had already seen the credential. Fixed; test_RevocationReachesEveryDestinationThatSawIssuance
        pins it. If you are on a build with that behaviour, this is the cause.
     b) setStatus not bumping the nonce -> the revocation carries the issuance's nonce and
        every destination discards it as stale. Fixed; test_RevocationCarriesANonceTheDestinationWillAccept
        pins it.

4. Check destination-side rejection reasons (the receiver emits CredentialReplicaRejected
   with a string before reverting):
     UNTRUSTED_SOURCE_SENDER / UNTRUSTED_SOURCE_CHAIN -> allowlist
     PROVIDER_UNAVAILABLE                            -> provider not registered/backing locally
     SYSTEM_PAUSED                                   -> destination paused; message stays retryable
     MALFORMED_PAYLOAD / UNKNOWN_* / NUMERIC_OVERFLOW -> version mismatch
     NONCE issues                                    -> out-of-order or duplicate delivery

5. If the destination is simply behind, wait or re-drive. If it is behind permanently,
   the source record's nonce is authoritative and the destination can be brought forward
   by a fresh message carrying a higher nonce.
```

**Interim mitigation while propagation is broken:** revoke the *provider* locally on the affected
destination (playbook A step 2). That denies access immediately without waiting for a message, and is
the only lever that does not depend on the propagation path working.

**Detection is inherently after the fact.** The source cannot observe a destination's rejection
directly — CCIP delivery is asynchronous. Monitor by comparing `getPropagationState(ccid).lastSourceNonce`
against the source record's `nonce` per destination. Any sustained divergence is a page.

**Structural note.** There is no timeout that revokes a credential automatically if propagation stops.
That would be a fail-open in the other direction. The correct controls are the freshness check
(`requiresFreshReplica` + `maxReplicaAge` → `STALE_DESTINATION`) and monitoring. If a pool wants
replicas to fail closed on staleness, that is a policy setting to make deliberately.

## 4. Decision guide

| Situation | First action | Why this one |
| --- | --- | --- |
| Suspected provider compromise | `setProviderStatus(Revoked)` on every chain | One transaction, immediate, no per-credential work |
| Suspected workflow key compromise | `revokeRole(WORKFLOW_SUBMITTER)` | Stops the ability to issue; cannot mint either way |
| Suspected issuer key compromise | Decide suspend vs revoke, then `revokeRole(ISSUER)` | Revoke is irreversible; suspend is not |
| Suspected guardian compromise | `grantRole(GUARDIAN, new)` then `revokeRole` | The pause is already done; rotating stops nothing further |
| Suspected admin/governance compromise | **No immediate lever** | See below |
| Destination not showing a revocation | Revoke the provider locally on that destination | The only lever that does not depend on propagation |
| Anything else | `pause(reason)` | Stops all new decisions, preserves reads |

**On a compromised governance key:** there is no pause-equivalent for governance. `DEFAULT_ADMIN_ROLE`
can re-grant roles, re-configure the audit trail, and authorize new recorders. Response is to rotate
the admin through whatever mechanism holds it — which, on a multisig, means the other signers
replacing the compromised one. The system's assumption is that `DEFAULT_ADMIN_ROLE` is a threshold or
a multisig, not a key. Verify that assumption in your deployment.

## 5. Post-incident

1. **Document the timeline on chain.** Events are the only durable record; capture block numbers and
   transaction hashes as you go.
2. **Confirm the audit trail is intact.** `AuditTrail` is append-only with no update or delete, so a
   silent removal is structurally impossible — but a broken recorder hook would leave a gap. Check
   `audit.totalEntries()` is monotonic and that entries exist for the window.
3. **If propagation was involved**, reconcile every destination: for each credential, compare the
   destination's `lastSourceNonce` against the source's `nonce`.
4. **Do not unpause until the cause is understood.** The 24-hour delay exists so this decision is made
   deliberately rather than under pressure.
5. **If the cause was a deploy gap** (`NotAuditor`, `NotWired`, `NotBridge`, `NotRegistryWriter`), fix
   it and add the corresponding check to §2.1 of
   [`operations-runbook.md`](./operations-runbook.md#21-wiring) so the next deployment catches it.

## 6. What these runbooks assume

| Assumption | If it does not hold |
| --- | --- |
| `GUARDIAN != ADMIN` | The pause/resume asymmetry collapses. `Deploy.s.sol` refuses this. |
| `GUARDIAN` and `DEFAULT_ADMIN_ROLE` are multisigs or HSMs | A single key compromise in §3D or §4 becomes a total compromise. |
| `POOL_POLICY_MANAGER`'s admin is a different address from `EmergencyControls`' | Both must be rotated independently. |
| Providers are registered and revoked on every destination | Playbook A step 2 is missed, and a destination keeps accepting compromised attestations. |
| `TIMELOCK_ADMIN` is reachable | A lost key plus a needed unpause leaves the system paused indefinitely. `executeUnpause` being permissionless mitigates this, but only once a schedule exists. |
| Deployment followed `Deploy.s.sol` | Every step in §3 may hit a "looks deployed, fails later" condition. Run §2.1. |
| There is a live deployment | **There is not.** No incident has occurred, and no procedure here has been rehearsed. |