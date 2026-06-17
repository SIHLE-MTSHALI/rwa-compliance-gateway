# RWA Compliance Gateway Engineering Specification

**Status:** Full production engineering specification  
**Last reviewed:** 2026-06-17  
**Canonical product document:** `PRD.md`  
**Audience:** engineering team building the complete product through production release gates

## 1. Build Contract

This document defines the production engineering target for privacy-conscious RWA compliance infrastructure that can support real issuers, providers, and investors only after legal, privacy, security, and operations gates are satisfied.

Engineers should not need product clarification for credential lifecycle, policy evaluation, provider registry, CCIP propagation, reason codes, tests, or release gates. Escalate only for legal advice, real investor onboarding, real provider contracts, production RWA pools, secrets, or mainnet deployment.

## 2. Product Delivery Model

| Release gate | Purpose | Required outcome |
| --- | --- | --- |
| Production Foundation | Build complete architecture locally | Credential, provider, policy, access, workflow, SDK, portal, and tests prove system shape |
| Public Testnet Pilot | Prove cross-chain credential state safely | Testnet propagation, issuer dashboard, no real PII, monitoring, and runbooks |
| Provider and Issuer Pilot | Connect reviewed real-world workflows | Legal/privacy review, provider adapter, issuer policy, capped controlled pilot |
| Production Network | Operate practical compliance infrastructure | Multiple providers, issuers, pools, chains, monitoring, audit exports, and incident process |

## 3. Target Repository Architecture

```text
contracts/
  src/
    ComplianceGateway.sol
    CredentialRegistry.sol
    ProviderRegistry.sol
    PoolPolicyManager.sol
    PoolComplianceModule.sol
    CrossChainCredentialSender.sol
    CrossChainCredentialReceiver.sol
    AuditTrail.sol
    EmergencyControls.sol
  test/
  script/
workflows/
  src/
    compliance-verify.ts
    renewal-check.ts
    revocation-check.ts
    provider-health.ts
    adapters/mock-provider.ts
  test/
packages/sdk/
  src/
    complianceClient.ts
    policyClient.ts
    issuerClient.ts
apps/portal/
  src/
    investor, issuer, compliance, auditor, and integrator views
docs/
  architecture.md
  privacy-model.md
  policy-schema.md
  provider-adapter-guide.md
  operations-runbook.md
  incident-response.md
  threat-model.md
```

## 4. Required Contract System

### `ProviderRegistry`

Must manage provider ID, schema support, metadata URI, active/paused/deprecated/revoked state, and provider health metadata.

### `CredentialRegistry`

Must store only minimal credential state:

```solidity
enum CredentialStatus { Unknown, Pending, Active, Expired, Suspended, Revoked }
enum InvestorClass { Unknown, USAccredited, NonUSProfessional, Blocked }

struct ComplianceCredential {
    bytes32 ccid;
    bytes32 credentialType;
    bytes32 providerId;
    bytes32 evidenceHash;
    uint32 schemaVersion;
    uint16 jurisdictionCode;
    InvestorClass investorClass;
    CredentialStatus status;
    uint64 issuedAt;
    uint64 expiresAt;
    uint64 updatedAt;
    uint64 nonce;
}
```

### `ComplianceGateway`

Must accept authorized Chainlink workflow results, validate provider/schema/status/TTL/nonce/evidence, update source state, and trigger propagation.

### `PoolPolicyManager`

Must define versioned issuer policy for credential type, schema version, jurisdictions, investor classes, freshness, allocation caps, manual review, and optional reserve references.

### `PoolComplianceModule`

Must return allow, deny, or review-required with reason codes. Required reason codes include `NO_CREDENTIAL`, `EXPIRED`, `SUSPENDED`, `REVOKED`, `JURISDICTION_BLOCKED`, `INVESTOR_CLASS_BLOCKED`, `STALE_DESTINATION`, `ALLOCATION_CAP_EXCEEDED`, `MANUAL_REVIEW_REQUIRED`, `POLICY_INACTIVE`, and `PROVIDER_PAUSED`.

### CCIP Sender and Receiver

Must validate router, chain selector, source sender, payload type, credential type, schema version, nonce, and provider state.

## 5. Chainlink Workflow System

### Workflow: `compliance-verify`

Must load provider adapter, validate result, compute CCID, map provider output to minimal credential fields, compute evidence hash, submit result, and propagate state. It must never log raw PII or provider reports.

### Workflow: `renewal-check`

Must detect credentials approaching expiry and trigger renewal workflow only after fresh provider verification.

### Workflow: `revocation-check`

Must process provider or compliance revocations and propagate revoked state across chains.

### Workflow: `provider-health`

Must detect provider outage, revoked provider, stale integration, or abnormal result patterns.

## 6. Portal and SDK Requirements

Portal views:

- Investor credential status, expiry, supported pools, renewal, revocation, and privacy explanation.
- Issuer policy builder, preview, version history, and access simulation.
- Compliance officer review queue and reason-coded actions.
- Auditor event trail and export.
- Integrator access-check demo.

SDK requirements:

```ts
async function getCredential(ccid: string, credentialType: string): Promise<ComplianceCredential>;
async function checkAccess(ccid: string, poolId: string, amount: bigint): Promise<AccessDecisionResult>;
async function getPolicy(poolId: string): Promise<PoolPolicy>;
```

## 7. Testing and Verification

Required checks once implementation exists:

```bash
forge fmt --check
forge test -vvv
forge test --match-path 'contracts/test/invariant/*' -vvv
pnpm --dir workflows test
pnpm --dir packages/sdk test
pnpm --dir apps/portal test
pnpm --dir apps/portal build
```

Required tests:

- Credential issue, renewal, suspension, expiry, revocation, and propagation.
- Allow, deny, and review-required policy outcomes.
- Manual review never defaults to allow.
- Jurisdiction, investor class, allocation cap, freshness, and provider status rules.
- CCIP spoofing, replay, wrong source, stale nonce, and destination freshness.
- No raw PII in storage, events, logs, public fixtures, or docs.
- Policy version delay and audit events.

## 8. Production Operations Requirements

Before real investor or issuer workflows:

- Legal and privacy review.
- Provider agreement and adapter review.
- External security review.
- Key management and role separation runbook.
- Monitoring for provider status, revocation lag, stale destinations, policy changes, access-denial anomalies, and privacy alerts.
- Incident response for provider compromise, false credential, policy bug, stale propagation, or privacy leak.

## 9. Configuration

```text
SOURCE_CHAIN_SELECTOR=
DESTINATION_CHAIN_SELECTORS=
CCIP_ROUTER=
LINK_TOKEN=
WORKFLOW_SUBMITTER=
PROVIDER_ADMIN=
ISSUER_ADMIN=
COMPLIANCE_OFFICER=
AUDITOR_ROLE=
EMERGENCY_GUARDIAN=
DEFAULT_CREDENTIAL_TTL_SECONDS=
POLICY_CHANGE_DELAY_SECONDS=
PRIVACY_POLICY_URI=
PROVIDER_CONFIG_URI=
```

Never commit private keys, provider credentials, raw PII, investor records, compliance documents, or provider reports.

## 10. Definition of Done for Full Product

The product is not complete until:

- Credential lifecycle, provider registry, policy engine, CCIP propagation, SDK, and portal are implemented.
- Access decisions are reason-coded and audited.
- Privacy tests prove raw PII exclusion.
- Legal/privacy/security review gates are documented before real workflows.
- Monitoring, incident response, and issuer/provider operations are ready.
