# RWA Compliance Gateway PRD

**Status:** Product design ready for implementation  
**Last reviewed:** 2026-06-17  
**Primary audience:** RWA issuers, institutional investors, compliance teams, smart contract engineers, security reviewers  
**Public-readiness goal:** define a serious compliance automation layer with privacy boundaries, issuer controls, and realistic legal disclaimers.

## 1. Product Vision

RWA Compliance Gateway lets an institutional investor verify once, receive a portable compliance credential, and access participating tokenized real-world asset pools across supported chains. Issuers define pool-specific rules. Investors keep sensitive identity data off-chain. Chainlink CRE coordinates verification workflows. Confidential compute isolates sensitive provider responses. CCIP propagates credential status. Automation manages renewal and expiry.

The product should feel like compliance infrastructure, not a DeFi marketing wrapper.

## 2. Problem

Tokenized real-world assets require investor verification, jurisdiction rules, sanctions screening, accreditation checks, and ongoing monitoring. Today, every RWA platform tends to rebuild this pipeline. That creates duplicated investor onboarding, repeated PII exposure, inconsistent rules, and slow capital deployment.

The core product problem: an investor verified for one RWA pool cannot safely and privately reuse that verification across other pools and chains.

## 3. Target Users

| Persona | Job to be done | Success condition |
| --- | --- | --- |
| Institutional investor | Complete verification once and access approved pools | Can see credential status, expiry, and allowed pools |
| RWA issuer | Configure pool compliance rules | Can enforce jurisdiction, accreditation, freshness, and allocation rules |
| Compliance officer | Review and revoke credentials when needed | Has auditable actions without exposing raw PII on-chain |
| Protocol developer | Integrate compliance checks | Can call a clear interface and handle allow/deny/review states |
| Auditor/regulator | Inspect policy enforcement | Can verify rules, events, and credential lifecycle without seeing PII |

## 4. Product Principles

- Compliance is policy-driven: issuers define rules, the gateway enforces them.
- PII minimization is mandatory: raw identity documents and provider responses must not touch chain state.
- Credentials are lifecycle objects: issue, active, renew, expire, suspend, revoke.
- Legal claims require legal review: docs should describe architecture, not promise regulatory compliance.
- Cross-chain state is eventually consistent and must show freshness.
- Operators need emergency controls, but not arbitrary fund or credential control.

## 5. Scope

### MVP Scope

- Investor credential registry with status, type, jurisdiction attributes, expiry, issuer/provider, and hash references.
- Pool policy module for issuer-configured access rules.
- CRE workflow for KYC/AML provider result intake and credential issuance.
- Confidential compute boundary for provider responses and sensitive attributes where available.
- CCIP propagation of credential state to destination chains.
- Automation for expiry monitoring, renewal reminders, and scheduled revocation checks.
- Issuer dashboard requirements for policy configuration, credential status, and audit trail.
- Investor portal requirements for verification status, renewal, and revocation request visibility.

### Non-Goals for MVP

- Replacing legal counsel or regulated compliance officers.
- Storing investor documents, beneficial owner data, or raw provider reports on-chain.
- Guaranteeing securities-law compliance in every jurisdiction.
- Supporting retail investors in every country.
- Performing asset custody or fund administration for RWA pools.

## 6. Core Workflows

### Investor Verification

1. Investor starts verification from an issuer or gateway portal.
2. Investor selects or is routed to a supported KYC/KYB provider.
3. Provider completes identity, entity, sanctions, and accreditation checks off-chain.
4. CRE workflow receives a provider-signed result or status reference.
5. Confidential compute evaluates sensitive attributes and emits only the minimum credential output.
6. Credential registry records status, expiry, policy-relevant attributes, and evidence hash.
7. CCIP propagates credential state to selected destination chains.

### Pool Access

1. Investor attempts to subscribe or deposit into an RWA pool.
2. Pool calls `checkAccess(investorCcid, poolId, amount)`.
3. Policy module evaluates credential status, jurisdiction, accreditation, freshness, allocation cap, and pool-specific rules.
4. Pool receives `ALLOW`, `DENY`, or `REVIEW_REQUIRED` with a reason code.
5. Event log records the access decision without PII.

### Credential Lifecycle

1. Credential approaches expiry.
2. Automation triggers renewal notice or renewal workflow.
3. Provider re-checks required fields.
4. Credential is renewed, suspended, expired, or revoked.
5. State propagates across chains.

## 7. Functional Requirements

| ID | Requirement | Priority | Acceptance criteria |
| --- | --- | --- | --- |
| FR-001 | Issue compliance credential | P0 | Credential has CCID, type, status, expiry, issuer/provider, and evidence hash |
| FR-002 | Keep PII off-chain | P0 | No raw document, name, address, tax ID, phone, email, or provider report in storage/events |
| FR-003 | Configure pool policy | P0 | Issuer can define jurisdiction, accreditation, freshness, allocation, and manual review rules |
| FR-004 | Evaluate pool access | P0 | Module returns allow, deny, or review with reason code |
| FR-005 | Renew credential | P0 | Renewal updates expiry and status with event trail |
| FR-006 | Revoke credential | P0 | Revoked credential fails access checks on source and propagated chains |
| FR-007 | Propagate via CCIP | P0 | Destination chain validates source and updates credential freshness state |
| FR-008 | Support compliance roles | P0 | Admin, issuer, compliance officer, emergency pauser, and auditor roles are distinct |
| FR-009 | Expose audit trail | P0 | Policy changes, credential lifecycle, access decisions, and propagation events are indexed |
| FR-010 | Support manual review | P1 | Ambiguous cases can return review state instead of false allow/deny certainty |
| FR-011 | Integrate Proof of Reserve references | P2 | Pool policy can reference reserve attestation status where available |

## 8. Chainlink Architecture

- CRE orchestrates verification, renewal, revocation, and provider adapter workflows.
- Confidential compute is the privacy boundary for sensitive KYC/KYB result processing where supported.
- ACE-style identity and policy concepts inform CCID binding and pool rule evaluation.
- CCIP propagates credential status to destination chain registries.
- Automation monitors expiry and scheduled lifecycle tasks.
- Proof of Reserve can provide reserve status inputs for RWA pools where appropriate.

Design constraints:

- CCIP destination state must expose source chain, source registry, nonce, and last update time.
- Pool policies must be versioned and timelocked where changes affect investor access.
- Manual review states must not be treated as allow by default.
- No provider API keys or secrets may be committed to the repo or emitted in workflow logs.

## 9. Smart Contract Architecture

| Contract | Responsibility |
| --- | --- |
| `ComplianceGateway` | CRE result intake, credential lifecycle coordination, role gateway |
| `CredentialRegistry` | Credential status, expiry, version, evidence hash, revocation state |
| `PoolPolicyManager` | Issuer-defined rules and policy versioning |
| `PoolComplianceModule` | Access evaluation and reason-code output |
| `CrossChainCredentialSender` | CCIP propagation from source registry |
| `CrossChainCredentialReceiver` | Destination registry update validation |
| `ProviderRegistry` | Supported KYC/KYB providers and adapter metadata |
| `EmergencyControls` | Scoped pause for issuance, access checks, propagation, or provider use |

## 10. Data and Privacy Model

Data categories:

- Raw PII: documents, names, addresses, tax IDs, beneficial ownership. Must remain off-chain with regulated providers or controlled backend systems.
- Sensitive provider response: detailed provider result. Process only inside confidential workflow where available.
- Policy attributes: minimum required facts such as jurisdiction class, investor type, accreditation tier, sanctions pass/fail, expiry. Store only if needed and preferably as hashes or compact enums.
- Public state: credential status, expiry, policy version, reason codes, evidence hashes, and events.

The docs must state that privacy architecture reduces on-chain exposure but does not by itself create legal compliance.

## 11. UX Requirements

### Investor Portal

- Shows verification status, required next action, expiry, supported pools, and destination chain freshness.
- Explains what data is stored on-chain and what is not.
- Provides renewal and revocation request flow.
- Avoids blockchain jargon where possible.

### Issuer Dashboard

- Policy builder with jurisdiction, accreditation, freshness, cap, and manual-review rules.
- Change preview before policy updates.
- Audit trail for policy changes and access decisions.
- Exportable compliance evidence without raw PII leakage.

## 12. Security and Abuse Cases

| Risk | Mitigation |
| --- | --- |
| PII leakage | Do not store raw PII on-chain; prohibit sensitive workflow logs; secret scanning |
| Provider compromise | Provider pause, short credential TTLs, evidence hashes, manual review fallback |
| Wrong pool access | Reason-coded policy engine, tests for deny/review states, no default allow |
| Cross-chain spoofing | Validate CCIP router, source chain, source sender, nonce, and credential schema |
| Stale destination state | Freshness timestamps and strict freshness checks in pool policy |
| Governance abuse | Safe multi-sig, timelock, scoped roles, public policy-change events |
| Regulatory overclaim | Docs include legal-disclaimer language and require counsel review before launch |

## 13. Verification Plan

Required before testnet launch:

- Unit tests for credential issue, renew, suspend, revoke, expire, and access checks.
- Fuzz tests for policy parameters, allocation caps, expiry boundaries, and reason codes.
- Invariant tests: revoked never allows, expired never allows, manual review never allows by default, policy version changes are traceable.
- CCIP local simulator tests for propagation, replay, wrong source, stale nonce, and destination pause.
- CRE simulation tests for provider pass, fail, manual review, timeout, malformed response, and revoked provider.
- Secret scanning and documentation review for PII and unsupported legal claims.
- Static analysis with no unresolved high or critical findings.

## 14. Launch Criteria

The project is ready for public testnet when:

- One provider adapter works in a simulated or testnet-safe flow.
- One source chain and one destination chain can issue and propagate credential state.
- One sample RWA pool can enforce allow, deny, and review states.
- Privacy and legal limitations are documented plainly.
- No docs imply real investor onboarding or regulatory approval before those exist.

## 15. Success Metrics

| Metric | Target |
| --- | --- |
| Raw PII in on-chain state/events | 0 tolerated |
| Revoked or expired access allowed | 0 tolerated |
| Policy change auditability | 100% of changes emit versioned events |
| Destination state freshness visibility | 100% of propagated credentials expose last update time |
| Integrator time to first access check | Under 20 minutes from docs |

## 16. Open Questions

- Which provider should be first for a non-production MVP adapter?
- Which jurisdiction and investor-type fields are necessary for launch without over-collecting data?
- Should pool policies live entirely on-chain or use off-chain signed policy bundles with on-chain hashes?
- What counsel review is required before public claims about RWA compliance?
- How should users request deletion or revocation when on-chain events are immutable?

## 17. References

- Chainlink CRE: https://docs.chain.link/cre
- Chainlink CCIP: https://docs.chain.link/ccip
- Chainlink Automation: https://docs.chain.link/chainlink-automation
- Chainlink Proof of Reserve: https://docs.chain.link/data-feeds/proof-of-reserve
