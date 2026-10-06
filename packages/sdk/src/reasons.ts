/**
 * Reason codes, decisions, and the enums the on-chain schema uses.
 *
 * ## Why these live in the SDK and not only in Solidity
 *
 * `ComplianceTypes.reasonToString` is the chain's own mapping, and this file mirrors it.
 * The duplication is deliberate and the two are kept honest by `test/reasons.test.ts`,
 * which asserts that the label for every code here is a non-empty string and that
 * `OK` is the only allow.
 *
 * The chain remains authoritative. `describeReason` on `PoolComplianceModule` returns
 * `UNRECOGNIZED` for a code it does not know, which is what lets an older SDK keep
 * working against a newer contract: a new reason code shows up as a label the SDK does
 * not have a name for, rather than as a thrown error in a logging path.
 */

/** Outcome of an access check. Mirrors `ComplianceTypes.Decision`. */
export const Decision = {
  /** Every precondition held. The only decision that permits access. */
  Allow: 0,
  /** Refused. `reasonCode` says why. */
  Deny: 1,
  /**
   * Not refused, but not permitted either: the pool's policy requires a human to look
   * before any access.
   *
   * Kept distinct from `Deny` because an integrator routes on it. Collapsing the two
   * would make a policy's review requirement unenforceable, since integrators would
   * configure it and then treat the outcome as a rejection.
   */
  ReviewRequired: 2,
} as const;

export type Decision = (typeof Decision)[keyof typeof Decision];

export function decisionName(decision: Decision): string {
  switch (decision) {
    case Decision.Allow:
      return "Allow";
    case Decision.Deny:
      return "Deny";
    case Decision.ReviewRequired:
      return "ReviewRequired";
    default:
      return "Unrecognized";
  }
}

/** Lifecycle state of a compliance credential. Mirrors `ComplianceTypes.CredentialStatus`. */
export const CredentialStatus = {
  Unknown: 0,
  /**
   * Verification has started but has not finished.
   *
   * A denial, not a provisional allow. A credential whose verification is incomplete
   * cannot be relied on, and treating it as "probably fine" is the failure this whole
   * system exists to prevent.
   */
  Pending: 1,
  Valid: 2,
  Expired: 3,
  Suspended: 4,
  Revoked: 5,
} as const;

export type CredentialStatus = (typeof CredentialStatus)[keyof typeof CredentialStatus];

export function credentialStatusName(status: CredentialStatus): string {
  switch (status) {
    case CredentialStatus.Unknown:
      return "Unknown";
    case CredentialStatus.Pending:
      return "Pending";
    case CredentialStatus.Valid:
      return "Valid";
    case CredentialStatus.Expired:
      return "Expired";
    case CredentialStatus.Suspended:
      return "Suspended";
    case CredentialStatus.Revoked:
      return "Revoked";
    default:
      return "Unrecognized";
  }
}

/**
 * Coarse investor eligibility class. Mirrors `ComplianceTypes.InvestorClass`.
 *
 * Deliberately four values. Every additional class is another axis on which holders can
 * be correlated from public chain state, so the set is kept as small as real policy
 * permits. `Blocked` is a first-class value rather than an absent credential, so that a
 * denial is explainable to the holder it affects.
 */
export const InvestorClass = {
  Unknown: 0,
  USAccredited: 1,
  NonUSProfessional: 2,
  Blocked: 3,
} as const;

export type InvestorClass = (typeof InvestorClass)[keyof typeof InvestorClass];

export function investorClassName(cls: InvestorClass): string {
  switch (cls) {
    case InvestorClass.Unknown:
      return "Unknown";
    case InvestorClass.USAccredited:
      return "USAccredited";
    case InvestorClass.NonUSProfessional:
      return "NonUSProfessional";
    case InvestorClass.Blocked:
      return "Blocked";
    default:
      return "Unrecognized";
  }
}

/** Who may revoke, decided per policy version. Mirrors `ComplianceTypes.RevocationMode`. */
export const RevocationMode = {
  IssuerOnly: 0,
  HolderOrIssuer: 1,
  /**
   * Governance only.
   *
   * Deliberately excludes the issuer: a governance-scoped credential the issuer could
   * revoke unilaterally would not be governance-scoped.
   */
  GovernanceOnly: 2,
} as const;

export type RevocationMode = (typeof RevocationMode)[keyof typeof RevocationMode];

/**
 * The fourteen reason codes.
 *
 * Keys are the labels the chain returns, values are `keccak256` of the label - which is
 * exactly how `ComplianceTypes` derives them, so the two cannot drift in *value* even if
 * a label were renamed in one place.
 *
 * The codes are grouped below in the order the chain evaluates them, because that order
 * is the security argument: see `docs/architecture.md` and `PoolComplianceModule._evaluate`.
 */
export const REASONS = {
  /** Access granted. The only code that permits access. */
  OK: "OK",
  /** No credential exists for the presented CCID. */
  NO_CREDENTIAL: "NO_CREDENTIAL",
  /** Verification has not completed. A denial, not a provisional allow. */
  PENDING: "PENDING",
  /** Past `expiresAt`, or explicitly expired. */
  EXPIRED: "EXPIRED",
  /** Temporarily blocked by the issuer. */
  SUSPENDED: "SUSPENDED",
  /** Permanently withdrawn. */
  REVOKED: "REVOKED",
  /** The holder's jurisdiction is not accepted by this pool's policy. */
  JURISDICTION_BLOCKED: "JURISDICTION_BLOCKED",
  /** The holder's investor class is not accepted by this pool's policy. */
  INVESTOR_CLASS_BLOCKED: "INVESTOR_CLASS_BLOCKED",
  /** Replicated state is older than the pool tolerates. */
  STALE_DESTINATION: "STALE_DESTINATION",
  /** Requested or total allocation exceeds the pool's per-investor cap. */
  ALLOCATION_CAP_EXCEEDED: "ALLOCATION_CAP_EXCEEDED",
  /** Pool policy requires human review before any access. */
  MANUAL_REVIEW_REQUIRED: "MANUAL_REVIEW_REQUIRED",
  /** No policy has ever been registered for this pool. */
  POOL_NOT_REGISTERED: "POOL_NOT_REGISTERED",
  /** A policy exists but is not currently active. */
  POLICY_INACTIVE: "POLICY_INACTIVE",
  /** The attesting provider is not currently trusted. */
  PROVIDER_PAUSED: "PROVIDER_PAUSED",
  /** The system is paused; no decision can be trusted. */
  SYSTEM_PAUSED: "SYSTEM_PAUSED",
} as const;

export type ReasonLabel = (typeof REASONS)[keyof typeof REASONS];

/** Every reason label, in the chain's evaluation order. */
export const REASON_ORDER: readonly ReasonLabel[] = [
  REASONS.OK,
  REASONS.SYSTEM_PAUSED,
  REASONS.POOL_NOT_REGISTERED,
  REASONS.POLICY_INACTIVE,
  REASONS.NO_CREDENTIAL,
  REASONS.PENDING,
  REASONS.REVOKED,
  REASONS.SUSPENDED,
  REASONS.EXPIRED,
  REASONS.PROVIDER_PAUSED,
  REASONS.JURISDICTION_BLOCKED,
  REASONS.INVESTOR_CLASS_BLOCKED,
  REASONS.STALE_DESTINATION,
  REASONS.ALLOCATION_CAP_EXCEEDED,
  REASONS.MANUAL_REVIEW_REQUIRED,
];

/** Returned for a code this SDK does not know, mirroring the chain's behaviour. */
export const UNRECOGNIZED = "UNRECOGNIZED";

/**
 * True only for the single reason that permits access.
 *
 * The one correct way to branch on a decision. Comparing a status to `Valid` directly is
 * the mistake this function exists to prevent.
 */
export function isAllow(reason: string): boolean {
  return reason === REASONS.OK;
}

/**
 * True when a denial should be routed to a human rather than rejected.
 *
 * `MANUAL_REVIEW_REQUIRED` is the only one. Treating it as a hard deny makes a policy's
 * review requirement unenforceable, because integrators would configure it and then
 * ignore it.
 */
export function isReviewRequired(reason: string): boolean {
  return reason === REASONS.MANUAL_REVIEW_REQUIRED;
}

/**
 * True for a reason that is a property of the *pool*, not of the credential.
 *
 * Worth knowing when deciding whether to send a holder back through verification.
 * Being denied because a pool has no active policy says nothing about the holder's
 * credentials, and telling them to re-verify would be both wrong and alarming.
 */
export function isPoolConfigurationReason(reason: string): boolean {
  return (
    reason === REASONS.SYSTEM_PAUSED ||
    reason === REASONS.POOL_NOT_REGISTERED ||
    reason === REASONS.POLICY_INACTIVE ||
    reason === REASONS.STALE_DESTINATION
  );
}

/**
 * True for a reason the holder can act on by re-verifying or waiting.
 *
 * A denial that is none of these and not pool configuration is a credential or provider
 * problem, which is the case that genuinely needs a human.
 */
export function needsHolderAction(reason: string): boolean {
  return (
    reason === REASONS.EXPIRED ||
    reason === REASONS.PENDING ||
    reason === REASONS.NO_CREDENTIAL ||
    reason === REASONS.JURISDICTION_BLOCKED ||
    reason === REASONS.INVESTOR_CLASS_BLOCKED ||
    reason === REASONS.ALLOCATION_CAP_EXCEEDED
  );
}
