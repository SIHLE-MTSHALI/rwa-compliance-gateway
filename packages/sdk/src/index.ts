/**
 * `@rwa-compliance/sdk`
 *
 * A client for the RWA compliance gateway. The design goal throughout is that the
 * *reason* is never lost: every access decision carries a reason code, and the reason is
 * what an integrator should branch on.
 *
 * ```ts
 * const compliance = new ComplianceClient(publicClient, { addresses });
 *
 * const decision = await compliance.evaluate({
 *   ccid,
 *   poolId,
 *   requestedAmount: 10_000n,
 *   currentAllocation: 2_000n,
 * });
 *
 * if (decision.isAllowed) {
 *   // proceed
 * } else if (decision.requiresReview) {
 *   // route to a human; this is not a rejection
 * } else if (decision.isPoolConfigurationIssue) {
 *   // nothing is wrong with the holder - do not ask them to re-verify
 * } else {
 *   // decision.reasonLabel says why, and whether the holder can act on it
 * }
 * ```
 *
 * To also write the decision on chain, use `AccessRecorder` with a wallet client rather
 * than calling a write method here: the read client deliberately has none.
 *
 * ## What this package does not do
 *
 * - It does not verify identity. Everything about a holder arrives as an already-verified
 *   attestation; the chain checks that the attestation is coherent, not that it is true.
 * - It does not establish legal compliance. Nothing here is a regulatory determination;
 *   see `docs/audit-readiness.md` for what is missing before a pilot.
 * - It does not compute the subject commitment properly. `saltedSubjectCommitment` is a
 *   demonstration of the shape, not a production construction.
 */

export {
  Decision,
  CredentialStatus,
  InvestorClass,
  RevocationMode,
  REASONS,
  REASON_ORDER,
  UNRECOGNIZED,
  decisionName,
  credentialStatusName,
  investorClassName,
  isAllow,
  isReviewRequired,
  isPoolConfigurationReason,
  needsHolderAction,
} from "./reasons.js";
export type { ReasonLabel } from "./reasons.js";

export {
  CCID_DOMAIN,
  CCID_DOMAIN_LABEL,
  computeCcid,
  verifyCcid,
  validateCcidParts,
  saltedSubjectCommitment,
  labelToId,
} from "./ccid.js";
export type { CcidInput } from "./ccid.js";

export {
  ComplianceClient,
  AccessRecorder,
  classifyDecision,
  COMPLIANCE_MODULE_ABI,
  COMPLIANCE_REGISTRY_ABI,
  PROVIDER_REGISTRY_ABI,
  ProviderStatus,
  providerStatusName,
} from "./complianceClient.js";
export type {
  AccessDecision,
  AccessRequest,
  ComplianceClientAddresses,
  ComplianceClientOptions,
  CredentialRecord,
  PropagationState,
} from "./complianceClient.js";

export { PolicyClient, readOnlyPolicyClient, POLICY_MANAGER_ABI } from "./policyClient.js";
export type { PoolPolicy, PolicyInput } from "./policyClient.js";

export { IssuerClient, GATEWAY_ABI, REGISTRY_ABI, previewCcid } from "./issuerClient.js";
export type { CredentialResultInput } from "./issuerClient.js";
