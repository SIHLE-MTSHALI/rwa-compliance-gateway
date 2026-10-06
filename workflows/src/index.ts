/**
 * `@rwa-compliance/workflows`
 *
 * Chainlink CRE workflows for the RWA compliance gateway: verify a holder, watch for
 * expiries, confirm that revocations reached every destination, and report provider
 * health.
 *
 * ## The shape of every workflow here
 *
 * Each takes its dependencies as arguments - a provider, a chain, a clock, a log sink - and
 * returns a result. Nothing reaches the network unless a caller injects something that
 * does. That is what makes them testable, and a compliance workflow that cannot be tested is
 * one whose behaviour is whatever the last run happened to do.
 *
 * ## The rule every workflow follows
 *
 * The holder's identity attributes stay in the runtime. What crosses to the chain is a salted
 * commitment, a jurisdiction code, an investor class, and a hash of the provider's evidence.
 * {@link privacy} enforces the logging side of that boundary, and
 * {@link adapters/mock-provider} enforces that fixture evidence is identifiable as such.
 *
 * ## What these workflows do not do
 *
 * They do not establish that an investor is who they claim to be. A provider does that, and
 * the gateway checks only that the result is *coherent* - that the CCID reproduces from the
 * fields submitted, that the provider is trusted, and that the attributes are within their
 * permitted ranges. See `docs/threat-model.md`.
 *
 * They also do not talk to a real provider. The shipped adapter is a fixture, and the two
 * attestation transports are stubs that throw by design rather than return evidence they
 * cannot back up.
 */

export {
  complianceVerify,
  saltedCommitment,
  type ComplianceVerifyConfig,
  type ComplianceVerifyInput,
  type ComplianceVerifyResult,
  type ComplianceProvider,
  type CredentialChain,
  type VerificationSubmission,
  type VerifyFailure,
} from "./compliance-verify.js";

export {
  renewalCheck,
  shouldAttemptRenewal,
  renewalWouldChangeAnything,
  type ExpiringCredential,
  type ExpiryChain,
  type RenewalCandidate,
  type RenewalCheckConfig,
  type RenewalCheckResult,
} from "./renewal-check.js";

export {
  revocationCheck,
  classify,
  Status,
  type Divergence,
  type ReplicaState,
  type SourceCredentialState,
  type RevocationChain,
  type RevocationCheckConfig,
  type RevocationCheckResult,
} from "./revocation-check.js";

export {
  providerHealth,
  assessProvider,
  submitHeartbeats,
  shouldAttemptIssuance,
  providerStatusName,
  ProviderStatus,
  type ProviderHealth,
  type ProviderHealthChain,
  type ProviderHealthConfig,
  type ProviderHealthResult,
  type ProviderSnapshot,
} from "./provider-health.js";

export {
  FORBIDDEN_TOKENS,
  FORBIDDEN_WORDS,
  SENSITIVE_FIELD_NAMES,
  RedactionError,
  SensitiveRegistry,
  assertFieldNameIsSafe,
  assertRedacted,
  createSafeLogger,
  toSafeSummary,
  type LogRecord,
  type LogSink,
  type SafeDecisionSummary,
  type SafeLogger,
} from "./privacy.js";

export {
  FIXTURE_MARKER,
  FixtureEvidenceError,
  MockProviderAdapter,
  assertNotFixtureEvidence,
  fixtureJurisdictionOf,
  fixtureProfileNames,
  isFixtureEvidence,
  type VerificationRequest,
  type VerificationResult,
} from "./adapters/mock-provider.js";

export {
  ReclaimTransportNotConfiguredError,
  reclaimTransport,
  isTransportConfigured,
  type AttestedResponse,
  type ZkTlsTransport,
} from "./adapters/reclaim.js";

export {
  TlsNotaryTransportNotConfiguredError,
  tlsNotaryTransport,
  isNotaryConfigured,
  type TlsNotaryTransport,
} from "./adapters/tlsnotary.js";
