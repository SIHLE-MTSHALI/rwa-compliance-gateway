# RWA Compliance Gateway

A credential and policy layer for tokenized real-world-asset pools. Holders prove
eligibility off-chain; the chain stores only hashes and returns a **reason-coded
decision** so an integrator can act on the *difference* between "expired", "revoked",
and "this pool has no active policy".

> **Status: implemented core, pre-release.** The contracts, SDK, and workflows
> below are built, tested, and mutation-checked. There is **no external audit, no
> deployed environment, no real KYC provider, and no legal compliance**. See
> [What is and is not built](#what-is-and-is-not-built) before drawing conclusions.

## The problem this solves

A tokenized pool needs to know who may invest. The usual answers each leak or lock
something in:

- **Store the investor's data.** Now every pool operator holds a PII database, and
  every breach is a reportable incident.
- **Call a centralized KYC API per pool.** Every pool integrates separately, every
  operator sees every holder, and there is no shared revocation.
- **Verify once, never again.** Credentials go stale silently and a revoked holder
  keeps their allocation on every chain that already accepted them.

This system takes a narrower position: **the chain should store evidence that
something was attested, never the thing attested.** A holder's identity attributes
stay in an off-chain workflow, which derives a salted commitment and submits a hash.
What reaches the chain is a credential record with a lifecycle status.

## How it works

```
holder          CRE workflow              contracts                    destination chain
  |                  |                        |                              |
  |  attributes      |                        |                              |
  |----------------->|                        |                              |
  |            provider adapter                |                              |
  |            (attests off-chain)             |                              |
  |                  |--- submitResult ------>|                              |
  |                  |                   ComplianceGateway                   |
  |                  |                   re-derives CCID from the fields,     |
  |                  |                   rejects a mismatch                 |
  |                  |                   ComplianceRegistry                  |
  |                  |                   status: Pending -> Valid             |
  |                  |<-- decision + reason --|                              |
  |                  |                        |--- CCIP: status change ------>|
  |                  |                        |                     CrossChainReceiver
  |                  |                        |                     nonce check, so a
  |                  |                        |                     replayed or stale
  |                  |                        |                     message is discarded
```

The **CCID** (Compliance Credential ID) is the load-bearing idea: a `keccak256` over
the credential type, schema version, provider, jurisdiction, investor class, and the
holder's salted subject commitment. The gateway *recomputes it* from the submitted
fields, so a provider cannot return one holder's attestation and have it recorded
against another.

It deliberately excludes the nonce. Renewal therefore keeps the same CCID, which is
what makes revocation possible — see [Why the CCID has no nonce](#why-the-ccid-has-no-nonce).

## Quick start

```bash
pnpm install
pnpm run build          # workflows import the SDK through its built entrypoint

forge test              # 244 tests
pnpm run typecheck
pnpm run test           # SDK + workflow + script tests
```

Deploy locally against the included CCIP mock:

```bash
forge script script/Deploy.s.sol --broadcast --rpc-url $RPC_URL
```

## The decision model

Every access decision is `(Decision, ReasonCode)`. The reason is the product — a bare
boolean would force an integrator to re-derive *why* from chain state they may not be
able to read, at the moment a holder is asking.

| Decision | Meaning |
|---|---|
| `Allow` | Every check passed. |
| `Deny` | A specific check failed. The reason says which. |
| `ReviewRequired` | Not a denial; a human must look. Deliberately never masks a `Deny`. |

15 reason codes, evaluated in a fixed order — the order *is* the security argument,
and it is pinned by a test. `SYSTEM_PAUSED` is checked first because a paused system
cannot trust its own state. `MANUAL_REVIEW_REQUIRED` is last so it can never shadow a
`SUSPENDED` or `REVOKED`.

The SDK sorts them into three categories an integrator can branch on without parsing
strings:

```ts
import { classifyDecision, REASONS } from "@rwa-compliance/sdk";

const decision = await client.evaluate({ ccid, poolId, requestedAmount });

if (decision.isPoolConfigurationIssue) {
  // The operator's problem, not the holder's: no active policy, unregistered pool.
} else if (decision.holderCanAct) {
  // Tell the holder to re-verify.
} else {
  // A trust decision. Nobody can fix this by re-verifying.
}
```

## What is and is not built

This is the section to read before trusting anything above.

### Built and tested

| | |
|---|---|
| **9 contracts + 2 libraries** | 12 deployable contracts, largest 11,485 B against a 24,576 B limit |
| **244 Foundry tests** | Unit, fuzz, invariant (128×64 in CI), wire-format, and a storage-privacy scan |
| **14 mutations, all caught** | Every seeded defect is caught by the suite; a green suite is therefore evidence of coverage |
| **CCID parity vectors** | 12 vectors generated from `CCIDResolver.compute`, asserted byte-for-byte in TypeScript |
| **SDK** | Read/write split; write clients require an explicit account and chain |
| **Workflows** | Verification, renewal monitoring, revocation propagation checking, provider health |
| **Docs** | 8 documents, including a threat model and an audit-readiness checklist |

### Not built

- **No audit.** No third party has reviewed this code. `docs/audit-readiness.md` is a
  scope document, not a report.
- **No deployment.** Nothing is on a public network. There are no contract addresses
  in this repository because there are none.
- **No real verification provider.** `workflows/src/adapters/mock-provider.ts` is a
  fixture. It resolves a jurisdiction and class from a label; it verifies nothing, and
  every value it produces is tagged `fixture-only-mock-provider` so it can never be
  mistaken for an attestation.
- **No zkTLS transport.** `adapters/reclaim.ts` and `adapters/tlsnotary.ts` throw a
  named error rather than return evidence they cannot back up. An adapter that
  constructs the right types without attesting the HTTP transcript would let a caller
  believe it holds a proof it does not.
- **Not legal compliance.** This checks conditions an integrator *encodes*. It does not
  establish that a holder is who they claim to be, and it is not KYC/AML. See
  `docs/threat-model.md`.
- **CCIP is mocked.** `MockCCIPRouter` stands in for the real router. Cross-chain
  delivery semantics are therefore *modelled*, not demonstrated on a live network.

## Why the CCID has no nonce

Including the nonce would give every renewal a fresh CCID. The consequence is subtle
and severe: the previous credential would remain `Valid` on every destination chain
that had already accepted it, with a different identity and therefore **nothing able
to revoke it**. A holder's revocation would clear the newest record and leave the old
one live.

So the CCID is nonce-free, and revocation is a *status transition on one identity* that
propagates like any other write. The nonce is a separate replay counter, which is what
`ComplianceRegistry` actually uses to discard a stale cross-chain message.

## Why the harness rejects some of your test mutations

The invariant handler has a `reconcileSystem()` escape, and `HandlerCoverage.t.sol`
ships in the permanent suite to assert the handler still reaches enough states. Without
it, a property could be "verified" over a run that never issued a credential, revoked
anything, or activated a policy — an invariant suite that passes because it explored
nothing is worse than no suite.

Similarly, `contracts/test/CheatcodeSemantics.t.sol` exists to pin Foundry behaviour
that bit this suite during development: `vm.prank` surviving `vm.expectRevert`, and
`block.timestamp` hoisting above a `vm.warp` under `via_ir`. Those are harness facts,
not product facts, and the next person to change the config would otherwise rediscover
them the hard way.

## Documentation

| Document | What it answers |
|---|---|
| [`architecture.md`](docs/architecture.md) | How the contracts fit together and why the boundaries are where they are |
| [`privacy-model.md`](docs/privacy-model.md) | What is stored, what is derivable, what a correlation attack gets |
| [`threat-model.md`](docs/threat-model.md) | What this defends against, and — more importantly — what it does not |
| [`policy-schema.md`](docs/policy-schema.md) | How to write a `PoolPolicy`, field by field |
| [`provider-adapter-guide.md`](docs/provider-adapter-guide.md) | What a real verification adapter must do |
| [`operations-runbook.md`](docs/operations-runbook.md) | Day-two: monitoring, pausing, unpausing, rotating a provider |
| [`incident-response.md`](docs/incident-response.md) | What to do when a provider is compromised |
| [`audit-readiness.md`](docs/audit-readiness.md) | Scope and open questions for a future audit |

## Layout

```
contracts/
  src/            9 contracts, 2 libraries, CCIP interfaces
  test/           244 tests across 12 suites, incl. invariant/ and NoPiiStorage
packages/sdk/     read clients, write clients, CCID derivation, reason labels
workflows/        CRE workflows; privacy redaction; provider adapters
scripts/          size + storage + mutation + docs-claims gates; CCID vectors
docs/             8 documents
```

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`ENGINEERING_SPEC.md`](ENGINEERING_SPEC.md)
first — the spec is the source of truth for the gates CI enforces.

## License

MIT. See [`LICENSE`](LICENSE).
