# RWA Compliance Gateway Engineering Specification

**Status:** Implementation-ready MVP build contract  
**Last reviewed:** 2026-06-17  
**Canonical product document:** `PRD.md`  
**Audience:** engineering team building the first complete MVP without further product consultation

## 1. Build Contract

This document turns the PRD into an executable engineering handoff. Engineers should be able to build the MVP described here without asking for product decisions. If this file conflicts with `PRD.md`, treat `PRD.md` as the product intent and this file as the implementation contract; update both in the same PR.

Escalate only for legal advice, real investor onboarding, real KYC/KYB provider contracts, production RWA pools, secrets, or mainnet deployment. Do not escalate for MVP credential types, policy fields, contract names, test scope, or default states; those are fixed below.

## 2. Fixed MVP Decisions

| Topic | MVP decision |
| --- | --- |
| First credential type | `ACCREDITED_INVESTOR_US_FIXTURE` |
| Second credential type | `NON_US_PROFESSIONAL_INVESTOR_FIXTURE` |
| Provider | `MockComplianceProvider` fixture adapter only for MVP |
| Real provider adapters | Not required for MVP; add only after legal and provider review |
| Raw PII policy | No raw name, address, tax ID, document, email, phone, provider report, or beneficial-owner data on-chain or in public fixtures |
| Identity binding | `ccid = keccak256(abi.encode(wallet, recoverySalt, version))` for MVP |
| Access decision | `Allow`, `Deny`, or `ReviewRequired` with reason code |
| First sample pool | `MockRwaPool` requiring US accredited investor credential and fresh status |
| Source chain | Local simulator first; Sepolia for public testnet target if supported at implementation time |
| Destination chain | Local simulator first; Avalanche Fuji for public testnet target if supported at implementation time |
| Credential TTL | 365 days production config; 5 minutes in tests |
| Policy change delay | 24 hours production config; 60 seconds in tests |
| Governance | Separate admin, issuer, compliance officer, auditor, and emergency guardian roles |

Open questions in `PRD.md` are future production questions. They do not block this MVP.

## 3. Target Architecture

```text
contracts/
  src/
    ComplianceGateway.sol
    CredentialRegistry.sol
    PoolPolicyManager.sol
    PoolComplianceModule.sol
    CrossChainCredentialSender.sol
    CrossChainCredentialReceiver.sol
    ProviderRegistry.sol
    EmergencyControls.sol
    mocks/MockRwaPool.sol
  test/
  script/
workflows/
  src/
    compliance-verify.ts
    renewal-check.ts
    revocation-check.ts
    adapters/mock-provider.ts
  test/
packages/sdk/
  src/
    complianceClient.ts
    policyClient.ts
apps/portal/
  src/
    investor status, issuer policy, access check, audit trail, and renewal views
docs/
  architecture.md
  privacy-model.md
  policy-schema.md
  runbook.md
  threat-model.md
```

Use Foundry for contracts, TypeScript for CRE-style workflows and SDK code, and Chainlink Local for CCIP tests.

## 4. Data and State Model

Required enums:

```solidity
enum CredentialStatus { Unknown, Pending, Active, Expired, Suspended, Revoked }
enum AccessDecision { Deny, Allow, ReviewRequired }
enum ProviderStatus { Unknown, Active, Paused, Deprecated, Revoked }
enum InvestorClass { Unknown, USAccredited, NonUSProfessional, Blocked }
```

Required credential record:

```solidity
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

Required policy record:

```solidity
struct PoolPolicy {
    bytes32 poolId;
    bytes32 requiredCredentialType;
    uint32 minSchemaVersion;
    uint16[] allowedJurisdictions;
    InvestorClass[] allowedInvestorClasses;
    uint64 maxCredentialAgeSeconds;
    uint256 maxAllocationPerInvestor;
    bool manualReviewEnabled;
    uint64 version;
}
```

PII rule:

- The data above is the maximum public/on-chain model for MVP.
- Do not add name, address, document ID, email, phone, tax ID, beneficial owner, provider case ID, or raw report fields.

## 5. Contract Modules

### `ProviderRegistry`

Responsibilities:

- Register provider ID, metadata URI, schema support, and status.
- Pause or revoke providers.
- Emit provider lifecycle events.

### `CredentialRegistry`

Responsibilities:

- Store compliance credential lifecycle state.
- Expose status and freshness views.
- Enforce issue, renew, suspend, revoke, and expire behavior.
- Prevent manual review from being treated as allow.

Required functions:

```solidity
function getCredential(bytes32 ccid, bytes32 credentialType) external view returns (ComplianceCredential memory);
function getStatus(bytes32 ccid, bytes32 credentialType) external view returns (CredentialStatus status, uint64 expiresAt, uint64 updatedAt);
function isActive(bytes32 ccid, bytes32 credentialType) external view returns (bool);
function revoke(bytes32 ccid, bytes32 credentialType, bytes32 reasonCode) external;
function suspend(bytes32 ccid, bytes32 credentialType, bytes32 reasonCode) external;
```

Required events:

```solidity
event CredentialIssued(bytes32 indexed ccid, bytes32 indexed credentialType, bytes32 indexed providerId, uint64 expiresAt, bytes32 evidenceHash);
event CredentialRenewed(bytes32 indexed ccid, bytes32 indexed credentialType, uint64 expiresAt, uint64 nonce);
event CredentialSuspended(bytes32 indexed ccid, bytes32 indexed credentialType, bytes32 reasonCode, uint64 nonce);
event CredentialRevoked(bytes32 indexed ccid, bytes32 indexed credentialType, bytes32 reasonCode, uint64 nonce);
event CredentialExpired(bytes32 indexed ccid, bytes32 indexed credentialType, uint64 expiredAt);
```

### `ComplianceGateway`

Responsibilities:

- Accept authorized workflow verification results.
- Validate provider, schema, status, TTL, nonce, and evidence hash.
- Update source registry.
- Initiate CCIP propagation.

Required workflow result:

```solidity
struct ComplianceResult {
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
    uint64 nonce;
}
```

### `PoolPolicyManager`

Responsibilities:

- Create and update pool policies.
- Version policy changes.
- Enforce policy-change delay before activation.
- Emit policy events with no PII.

### `PoolComplianceModule`

Responsibilities:

- Evaluate access based on policy, credential state, freshness, jurisdiction, investor class, allocation cap, and manual-review rules.
- Return reason codes.

Required function:

```solidity
function checkAccess(bytes32 ccid, bytes32 poolId, uint256 amount) external view returns (AccessDecision decision, bytes32 reasonCode);
```

Reason codes must distinguish `NO_CREDENTIAL`, `EXPIRED`, `SUSPENDED`, `REVOKED`, `JURISDICTION_BLOCKED`, `INVESTOR_CLASS_BLOCKED`, `STALE_DESTINATION`, `ALLOCATION_CAP_EXCEEDED`, `MANUAL_REVIEW_REQUIRED`, `POLICY_INACTIVE`, and `PROVIDER_PAUSED`.

### `CrossChainCredentialReceiver`

Must validate router, source chain selector, source sender, schema version, nonce, credential type, and payload type. Destination state must expose last update time and source chain.

## 6. CRE Workflow Specification

### Workflow: `compliance-verify`

Trigger:

- Investor verification request from portal or issuer flow.
- Manual trigger in tests.

Inputs:

```json
{
  "wallet": "0x...",
  "recoverySaltHash": "bytes32",
  "credentialType": "ACCREDITED_INVESTOR_US_FIXTURE",
  "providerId": "mock-compliance-provider",
  "schemaVersion": 1,
  "providerResultRef": "fixture://provider/us-accredited-pass"
}
```

Algorithm:

1. Load provider fixture or provider adapter.
2. Validate schema and credential type.
3. Compute `ccid` from wallet, recovery salt hash, and version.
4. Map provider result to `InvestorClass`, jurisdiction code, status, and TTL.
5. Compute `evidenceHash` from normalized result fields only.
6. Submit `ComplianceResult` to `ComplianceGateway`.
7. Propagate accepted result to configured destination chains through CCIP.

Failure behavior:

- Provider fail: issue no active credential; optionally store `Pending` or `Suspended` only if configured.
- Manual review result: do not allow pool access; return `ReviewRequired` from policy module.
- Provider timeout: keep request off-chain pending; do not issue credential.
- Submission failure: retry with same nonce and evidence hash.

### Workflow: `renewal-check`

Scheduled workflow scans credential expiry windows and emits renewal-needed events or off-chain notices. It must not renew without a provider result.

### Workflow: `revocation-check`

Scheduled workflow processes fixture revocation results. Revocation must propagate across chains and immediately fail access checks on source chain.

## 7. CCIP Rules

Credential propagation payload:

```solidity
struct ComplianceMessageV1 {
    bytes32 ccid;
    bytes32 credentialType;
    bytes32 providerId;
    bytes32 evidenceHash;
    uint32 schemaVersion;
    uint16 jurisdictionCode;
    InvestorClass investorClass;
    CredentialStatus status;
    uint64 expiresAt;
    uint64 updatedAt;
    uint64 nonce;
}
```

Receivers must reject unknown router, unknown source chain, unknown source sender, unsupported payload type, stale nonce, unsupported credential type, unsupported schema version, or provider-paused updates unless the update is revocation.

## 8. Portal and SDK Requirements

SDK must expose:

```ts
async function getCredential(ccid: string, credentialType: string): Promise<ComplianceCredential>;
async function checkAccess(ccid: string, poolId: string, amount: bigint): Promise<AccessDecisionResult>;
async function getPolicy(poolId: string): Promise<PoolPolicy>;
```

Portal required views:

- Investor credential status, expiry, supported pools, and destination freshness.
- Issuer policy builder with preview and version history.
- Access-check simulator showing allow, deny, and review-required reason codes.
- Audit trail for policy changes, credential lifecycle, and access decisions.
- Privacy explanation showing what is and is not stored on-chain.

## 9. Test Plan

Required local commands once implementation exists:

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

- Fixture pass issues active credential.
- Fixture fail does not allow pool access.
- Manual review returns `ReviewRequired`, never `Allow`.
- Expired credential fails access.
- Suspended credential fails access.
- Revoked credential fails access and propagates.
- Jurisdiction block denies access.
- Investor class block denies access.
- Allocation cap denies excess amount.
- Policy version delay enforced.
- Wrong CCIP router/source/sender rejected.
- Stale nonce ignored.
- Destination freshness exposed.
- No raw PII appears in events, storage structs, public fixtures, or logs.

## 10. Implementation Milestones

1. Scaffold Foundry contracts, test harness, roles, and pause controls.
2. Implement `ProviderRegistry` and provider status tests.
3. Implement `CredentialRegistry` and lifecycle tests.
4. Implement `ComplianceGateway` with authorized workflow submitter.
5. Implement `PoolPolicyManager` and version-delay tests.
6. Implement `PoolComplianceModule` and reason-coded access checks.
7. Implement CCIP sender/receiver using Chainlink Local simulator.
8. Implement TypeScript mock provider workflow and renewal/revocation fixtures.
9. Implement SDK and `MockRwaPool` integration example.
10. Build portal and privacy/policy/runbook docs.

## 11. Deployment and Configuration

Required config keys:

```text
SOURCE_CHAIN_SELECTOR=
DESTINATION_CHAIN_SELECTOR=
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
```

Never commit private keys, provider credentials, raw PII, investor records, compliance documents, provider reports, or production pool data.

## 12. Definition of Done

The MVP is engineering-complete when:

- Mock provider can issue, renew, suspend, revoke, and expire credentials locally.
- Sample RWA pool enforces allow, deny, and review-required paths with reason codes.
- CCIP propagation updates destination credential state and rejects stale or spoofed messages.
- Portal shows credential status, policy state, access result, audit trail, and privacy model.
- No raw PII appears in storage, events, public fixtures, logs, or docs.
- Docs include setup, deploy, test, privacy, policy, security, and recovery instructions.
