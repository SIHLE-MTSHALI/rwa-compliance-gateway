import { describe, expect, it } from "vitest";

import {
  CredentialStatus,
  Decision,
  InvestorClass,
  REASONS,
  REASON_ORDER,
  RevocationMode,
  UNRECOGNIZED,
  classifyDecision,
  credentialStatusName,
  decisionName,
  investorClassName,
  isAllow,
  isPoolConfigurationReason,
  isReviewRequired,
  needsHolderAction,
} from "../src/index.js";

/**
 * These mirror `ComplianceTypes` in Solidity. The two can drift, so every assertion here
 * is phrased as a *property* of the reason set rather than a restatement of it - a test
 * that copies the list would agree with a list that has lost an entry, which is exactly
 * what happened on chain once (`POOL_NOT_REGISTERED` was missing from `allReasons()`).
 */
describe("reason codes", () => {
  const labels = Object.values(REASONS);

  it("has fifteen codes", () => {
    expect(labels).toHaveLength(15);
  });

  it("has no duplicates", () => {
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("lists every code exactly once, in evaluation order", () => {
    expect(REASON_ORDER).toHaveLength(labels.length);
    expect(new Set(REASON_ORDER)).toEqual(new Set(labels));
  });

  it("starts the evaluation order with OK and ends with the review requirement", () => {
    // The order is the security argument - see PoolComplianceModule._evaluate - so its
    // endpoints are worth pinning.
    expect(REASON_ORDER[0]).toBe(REASONS.OK);
    expect(REASON_ORDER.at(-1)).toBe(REASONS.MANUAL_REVIEW_REQUIRED);
  });

  it("reports SYSTEM_PAUSED first among the denials", () => {
    // A paused system cannot trust its own state, so it outranks every credential-level
    // reason and is checked first.
    expect(REASON_ORDER[1]).toBe(REASONS.SYSTEM_PAUSED);
  });

  it("puts the review requirement last, so it never masks a real denial", () => {
    // If MANUAL_REVIEW_REQUIRED outranked SUSPENDED, an integrator routing on the reason
    // code would send a suspended credential to a review queue instead of rejecting it.
    const review = REASON_ORDER.indexOf(REASONS.MANUAL_REVIEW_REQUIRED);
    for (const code of [
      REASONS.SUSPENDED,
      REASONS.REVOKED,
      REASONS.EXPIRED,
      REASONS.PROVIDER_PAUSED,
      REASONS.ALLOCATION_CAP_EXCEEDED,
    ]) {
      expect(REASON_ORDER.indexOf(code), `${code} must outrank the review requirement`).toBeLessThan(review);
    }
  });

  it("treats only OK as an allow", () => {
    for (const label of labels) {
      expect(isAllow(label), `${label} allow-ness`).toBe(label === REASONS.OK);
    }
  });

  it("treats only MANUAL_REVIEW_REQUIRED as a review", () => {
    const reviews = labels.filter(isReviewRequired);
    expect(reviews).toEqual([REASONS.MANUAL_REVIEW_REQUIRED]);
  });

  it("separates pool configuration from holder-facing reasons", () => {
    // The distinction matters for what an integrator tells a holder: telling someone to
    // re-verify because their pool has no active policy is both wrong and alarming.
    expect(isPoolConfigurationReason(REASONS.SYSTEM_PAUSED)).toBe(true);
    expect(isPoolConfigurationReason(REASONS.POOL_NOT_REGISTERED)).toBe(true);
    expect(isPoolConfigurationReason(REASONS.POLICY_INACTIVE)).toBe(true);
    expect(isPoolConfigurationReason(REASONS.STALE_DESTINATION)).toBe(true);

    expect(isPoolConfigurationReason(REASONS.SUSPENDED)).toBe(false);
    expect(isPoolConfigurationReason(REASONS.EXPIRED)).toBe(false);
  });

  it("distinguishes never-configured from switched-off", () => {
    // Two codes rather than one, because they demand different responses: the first is an
    // integration bug, the second is a deliberate operational state that resolves itself.
    expect(REASONS.POOL_NOT_REGISTERED).not.toBe(REASONS.POLICY_INACTIVE);
    expect(isPoolConfigurationReason(REASONS.POOL_NOT_REGISTERED)).toBe(true);
    expect(isPoolConfigurationReason(REASONS.POLICY_INACTIVE)).toBe(true);
  });

  it("identifies reasons the holder can act on", () => {
    expect(needsHolderAction(REASONS.EXPIRED)).toBe(true);
    expect(needsHolderAction(REASONS.NO_CREDENTIAL)).toBe(true);
    expect(needsHolderAction(REASONS.ALLOCATION_CAP_EXCEEDED)).toBe(true);
    // Revocation and suspension are the issuer's decisions; a holder cannot resolve them.
    expect(needsHolderAction(REASONS.REVOKED)).toBe(false);
    expect(needsHolderAction(REASONS.SUSPENDED)).toBe(false);
    expect(needsHolderAction(REASONS.SYSTEM_PAUSED)).toBe(false);
  });

  it("never reports an allow and a review requirement together", () => {
    // Mutually exclusive by construction: an integrator branching on `isAllowed` and then
    // `requiresReview` must never fall into both arms.
    for (const label of labels) {
      expect(isAllow(label) && isReviewRequired(label)).toBe(false);
    }
  });

  it("exposes an explicit label for an unrecognised code", () => {
    expect(UNRECOGNIZED).toBe("UNRECOGNIZED");
  });
});

describe("enums", () => {
  it("names every decision", () => {
    expect(decisionName(Decision.Allow)).toBe("Allow");
    expect(decisionName(Decision.Deny)).toBe("Deny");
    expect(decisionName(Decision.ReviewRequired)).toBe("ReviewRequired");
  });

  it("reports an out-of-range decision rather than lying about it", () => {
    expect(decisionName(99 as Decision)).toBe("Unrecognized");
  });

  it("names every credential status", () => {
    for (const [status, name] of [
      [CredentialStatus.Unknown, "Unknown"],
      [CredentialStatus.Pending, "Pending"],
      [CredentialStatus.Valid, "Valid"],
      [CredentialStatus.Expired, "Expired"],
      [CredentialStatus.Suspended, "Suspended"],
      [CredentialStatus.Revoked, "Revoked"],
    ] as const) {
      expect(credentialStatusName(status)).toBe(name);
    }
    expect(credentialStatusName(99 as CredentialStatus)).toBe("Unrecognized");
  });

  it("keeps the investor class set to four values", () => {
    // Deliberately small: every additional class is another axis on which holders can be
    // correlated from public chain state.
    expect(Object.keys(InvestorClass)).toHaveLength(4);
    expect(investorClassName(InvestorClass.Blocked)).toBe("Blocked");
  });

  it("keeps GovernanceOnly distinct from the modes that admit an issuer", () => {
    // A governance-scoped credential the issuer could revoke unilaterally would not be
    // governance-scoped, so the enum value has to exist and be distinguishable.
    expect(RevocationMode.GovernanceOnly).not.toBe(RevocationMode.IssuerOnly);
    expect(RevocationMode.HolderOrIssuer).not.toBe(RevocationMode.IssuerOnly);
  });
});

describe("classifyDecision", () => {
  const ccid = `0x${"11".repeat(32)}` as `0x${string}`;

  it("marks an allow as allowed and nothing else", () => {
    const decision = classifyDecision(Decision.Allow, ccid, REASONS.OK);
    expect(decision.isAllowed).toBe(true);
    expect(decision.requiresReview).toBe(false);
    expect(decision.isPoolConfigurationIssue).toBe(false);
    expect(decision.holderCanAct).toBe(false);
  });

  it("marks a review requirement as a review, not a denial", () => {
    const decision = classifyDecision(Decision.ReviewRequired, ccid, REASONS.MANUAL_REVIEW_REQUIRED);
    expect(decision.isAllowed).toBe(false);
    expect(decision.requiresReview).toBe(true);
  });

  it("surfaces a pool problem as a configuration issue", () => {
    const decision = classifyDecision(Decision.Deny, ccid, REASONS.POLICY_INACTIVE);
    expect(decision.isPoolConfigurationIssue).toBe(true);
    expect(decision.holderCanAct).toBe(false);
  });

  it("surfaces a lapsed credential as something the holder can act on", () => {
    const decision = classifyDecision(Decision.Deny, ccid, REASONS.EXPIRED);
    expect(decision.holderCanAct).toBe(true);
    expect(decision.isPoolConfigurationIssue).toBe(false);
  });

  it("carries an unrecognised reason through without inventing an allow", () => {
    // The reason code comes from the chain, which may be newer than this SDK. An unknown
    // label must not be treated as permission.
    const decision = classifyDecision(Decision.Allow, ccid, UNRECOGNIZED);
    expect(decision.reasonLabel).toBe(UNRECOGNIZED);
    expect(decision.isAllowed).toBe(false);
  });

  it("does not grant access when the chain says Allow but the label is not OK", () => {
    // Defence in depth against a mistranslated code. `isAllowed` is derived from the
    // label the chain returned rather than from the numeric decision.
    const decision = classifyDecision(Decision.Allow, ccid, REASONS.SUSPENDED);
    expect(decision.isAllowed).toBe(false);
  });

  it("passes the reason code through untouched for audit correlation", () => {
    const decision = classifyDecision(Decision.Deny, ccid, REASONS.REVOKED);
    expect(decision.reasonCode).toBe(ccid);
    expect(decision.decision).toBe(Decision.Deny);
  });
});
