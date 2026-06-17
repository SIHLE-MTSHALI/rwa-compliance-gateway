# RWA Compliance Gateway PRD

**Status:** Full production product specification  
**Last reviewed:** 2026-06-17  
**Primary audience:** RWA issuers, institutional investors, compliance teams, smart contract engineers, security reviewers, Chainlink reviewers  
**Product ambition:** build practical privacy-conscious compliance infrastructure for tokenized real-world asset access, with issuer-controlled policy, credential lifecycle, cross-chain freshness, and auditable decisions.

## 1. Product Thesis

RWA Compliance Gateway lets an investor or institution verify once with approved providers, receive a minimal compliance credential, and access participating tokenized real-world asset pools where issuer-defined policy permits. Chainlink workflows coordinate provider result intake, credential lifecycle, renewal, revocation, and cross-chain propagation. Pools receive reason-coded access decisions without storing raw investor PII on public chain state.

The target is not a demo. The target is production-grade compliance infrastructure that can support real issuers and institutional users only after legal, provider, privacy, security, and operational readiness gates are satisfied.

## 2. Real-World Problem

RWA platforms need identity, entity, sanctions, accreditation, jurisdiction, allocation, and ongoing monitoring controls. Rebuilding these checks for every pool creates repeated onboarding, duplicated PII exposure, inconsistent rules, and slow capital deployment.

The product must solve for:

1. Reusable compliance credential state without raw PII on public chains.
2. Issuer-configured pool policies with versioning and auditability.
3. Allow, deny, and review-required outcomes with reason codes.
4. Credential renewal, expiry, suspension, revocation, and cross-chain freshness.
5. Separation between technical enforcement and legal/regulatory advice.
6. Operational support for providers, issuers, auditors, and investors.

## 3. Product Principles

- Raw PII minimization is mandatory.
- Compliance policy is issuer-defined and versioned.
- Manual review is a first-class state, not an accidental allow.
- Destination-chain state must expose freshness.
- Legal claims require qualified review; the product provides enforcement infrastructure, not legal certainty.
- Every credential and policy decision must be auditable without revealing sensitive personal data.

## 4. Full Product Scope

### Core Production Capabilities

- Provider registry with KYC/KYB provider adapters, schema support, status, pause, and deprecation.
- Credential registry with CCID, credential type, provider ID, schema version, status, expiry, evidence hash, jurisdiction class, investor class, nonce, and timestamps.
- Chainlink workflows for verification, renewal, scheduled expiry, revocation, provider health, and propagation.
- Pool policy manager with issuer-defined jurisdiction, investor class, freshness, allocation cap, manual review, reserve/reference checks, and version delays.
- Pool compliance module returning allow, deny, or review-required with reason codes.
- CCIP sender/receiver for credential propagation and destination freshness.
- Investor portal for credential status, expiry, renewal, revocation request, supported pools, and privacy explanation.
- Issuer dashboard for policy builder, version history, access decisions, audit trail, and export.
- Auditor view for lifecycle events, policy versions, access decisions, and evidence hashes without raw PII.
- Operations runbooks for provider outage, false credential, revocation, privacy incident, stale destination, and emergency pause.

### Scale and Ecosystem Capabilities

- Multiple investor classes, jurisdictions, provider adapters, and credential schemas.
- Multi-issuer policy templates.
- Integration with Proof of Reserve or issuer-specific asset status where appropriate.
- Credential portability across chains and participating pools.
- Institutional reporting exports.
- Provider onboarding and schema migration process.

## 5. Explicit Boundaries

The product must not store raw names, addresses, tax IDs, emails, phone numbers, documents, beneficial owner data, provider case details, or raw reports in public chain state, events, public fixtures, or logs.

The product must not claim legal compliance, regulatory approval, investor suitability, or jurisdictional sufficiency without qualified legal review.

## 6. User Journeys

### Investor

1. Starts verification from a gateway or issuer portal.
2. Completes provider process off-chain.
3. Receives credential status, expiry, supported pools, and destination-chain freshness.
4. Requests renewal or revocation when needed.
5. Sees why access is allowed, denied, or under review without exposing raw PII.

### Issuer

1. Defines pool policy by credential type, jurisdiction, investor class, freshness, allocation, and manual review requirements.
2. Reviews policy preview and version delay.
3. Monitors access decisions and audit trail.
4. Suspends or updates policy through governed process.

### Compliance Officer

1. Reviews flagged credentials or review-required decisions.
2. Suspends, revokes, or requests renewal through reason-coded actions.
3. Exports audit evidence without exposing raw PII.

### Protocol Developer

1. Integrates `checkAccess` or SDK helper.
2. Handles allow, deny, and review-required distinctly.
3. Monitors policy and credential freshness.

## 7. Functional Requirements

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| FR-001 | Credential lifecycle | Issue, renew, suspend, expire, revoke, and propagate states are explicit |
| FR-002 | PII minimization | No raw PII appears in storage, events, logs, or public fixtures |
| FR-003 | Provider registry | Providers have schema support, status, pause, deprecation, and metadata |
| FR-004 | Pool policy | Issuers configure versioned jurisdiction, investor class, freshness, cap, and review rules |
| FR-005 | Access decisions | Module returns allow, deny, or review-required with reason code |
| FR-006 | Cross-chain freshness | Destination state exposes source chain, nonce, and last update time |
| FR-007 | Revocation | Revoked credentials fail source checks immediately and propagate |
| FR-008 | Manual review | Review-required never defaults to allow |
| FR-009 | Audit trail | Credential lifecycle, policy changes, and access decisions are indexed |
| FR-010 | Operations | Provider outage, stale destination, false credential, and privacy incident runbooks exist |

## 8. Chainlink Architecture

- Chainlink CRE coordinates provider result intake, renewal, revocation, and lifecycle workflows.
- Confidential compute is the preferred processing boundary for sensitive provider responses where supported.
- Chainlink CCIP propagates credential state to destination chains.
- Chainlink Automation triggers expiry checks, renewal workflows, revocation checks, and provider health monitoring.
- Chainlink Proof of Reserve can inform pool policy where reserve status matters.

Design constraints:

- Workflow logs must exclude raw PII and provider reports.
- CCIP receivers validate router, source chain, source sender, credential schema, nonce, and payload type.
- Policy changes are versioned and delayed where they affect access.
- Stale destination state cannot be treated as valid by default.

## 9. Security, Privacy, and Abuse Cases

| Risk | Required mitigation |
| --- | --- |
| PII leakage | Data minimization, no raw PII in public state/logs/fixtures, privacy tests |
| Wrong pool access | Reason-coded policy engine and no default allow |
| Provider compromise | Provider pause, TTLs, revocation, manual review fallback |
| Stale destination state | Freshness timestamps and strict destination checks |
| Governance abuse | Scoped roles, timelocks, issuer/compliance/admin separation |
| Regulatory overclaim | Legal boundary docs and counsel review before claims |
| Policy migration error | Version delays, previews, evented changes, rollback plan |

## 10. Production Readiness Gates

### Gate 1: Production Foundation

- Credential registry, provider registry, policy manager, access module, workflows, SDK, and portal implemented locally.
- Fixture providers prove allow, deny, review, renewal, expiry, suspension, revocation, and propagation.

### Gate 2: Public Testnet Pilot

- Source and destination testnet credential state works without real investor PII.
- Issuer dashboard, investor portal, reason-coded access, and monitoring operate.

### Gate 3: Provider and Issuer Pilot

- Provider integration reviewed.
- Legal/privacy review completed for supported credential class and jurisdiction.
- Issuer policy and access decisions tested with capped, non-production or controlled pilot flows.

### Gate 4: Production Network

- Multiple providers, issuers, credential classes, jurisdictions, pools, and chains supported.
- Monitoring, audit exports, incident response, privacy operations, and governance are operational.

## 11. Success Metrics

| Metric | Target |
| --- | --- |
| Raw PII in chain state/events/logs | 0 tolerated |
| Revoked or expired credential allowed | 0 tolerated |
| Review-required treated as allow | 0 tolerated |
| Stale destination state accepted | 0 tolerated |
| Policy change auditability | 100% versioned and evented |
| Access decision explainability | 100% reason-coded |
| Integrator time to first safe check | Under 20 minutes from docs |

## 12. Documentation Requirements

Before public release, the repository must include architecture, privacy model, policy schema, provider adapter guide, issuer guide, investor guide, deployment guide, operations runbook, incident response plan, threat model, and audit readiness checklist.

## 13. References

- Chainlink CRE: https://docs.chain.link/cre
- Chainlink CCIP: https://docs.chain.link/ccip
- Chainlink Automation: https://docs.chain.link/chainlink-automation
- Chainlink Proof of Reserve: https://docs.chain.link/data-feeds/proof-of-reserve
