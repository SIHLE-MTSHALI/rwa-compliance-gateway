import type { Hex } from "viem";

import type { ComplianceProvider } from "./compliance-verify.js";
import { assertNotFixtureEvidence } from "./adapters/mock-provider.js";
import { createSafeLogger } from "./privacy.js";
import type { LogSink, SensitiveRegistry } from "./privacy.js";

/**
 * Renewal monitoring: which credentials are approaching expiry.
 *
 * ## Why a sweeper is not what enforces expiry
 *
 * The registry denies a credential the moment `expiresAt` passes, with no keeper involved.
 * That is deliberate: a system whose expiry depended on a sweeper being alive would **fail
 * open** the moment the sweeper stalled, which is the one unacceptable direction for a
 * compliance control.
 *
 * So this workflow exists to *nudge*, not to protect. It finds credentials close enough to
 * expiry that a renewal is worth starting, and hands them back to a caller who re-verifies
 * through the normal path. A stalled sweeper means some credentials lapse - a real cost to
 * the holder - but it never means an expired credential keeps working.
 *
 * ## What it does not do
 *
 * It does not renew anything itself. A renewal must satisfy every issuance check on the
 * gateway, which means a fresh provider attestation; a sweeper that could extend a
 * credential from a timer would be exactly the "stale or forged result extending a
 * credential's life" failure the gateway's validation sequence exists to stop.
 */

/** A credential as the sweeper needs to see it. */
export interface ExpiringCredential {
  readonly ccid: Hex;
  readonly credentialType: Hex;
  readonly providerId: Hex;
  readonly jurisdictionCode: number;
  readonly investorClass: number;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
  readonly nonce: bigint;
  /** How many times this credential has already been renewed. */
  readonly renewals: number;
}

/** The chain operations the sweeper needs. */
export interface ExpiryChain {
  /** Credentials whose `expiresAt` is within `withinSeconds`. */
  findExpiring(withinSeconds: bigint, limit: number): Promise<readonly ExpiringCredential[]>;
  /** The current chain time. Read from the chain, not the runtime's clock. */
  currentTimestamp(): Promise<bigint>;
}

export interface RenewalCheckConfig {
  /**
   * How far ahead to look. Defaults to 30 days.
   *
   * Long enough that a verification round trip, a human queue, and a renewal transaction
   * all fit inside it; short enough that the list stays worth reading.
   */
  readonly lookaheadSeconds: bigint;
  /** Max credentials to return in one run. Bounded so one run cannot blow its budget. */
  readonly limit: number;
  /**
   * Skip credentials renewed at least this many times.
   *
   * A holder who re-verifies every cycle is usually not going to pass on the next one, and
   * an unbounded retry list buries the credentials that will actually renew.
   */
  readonly maxRenewals: number;
}

const DEFAULT_CONFIG: Omit<RenewalCheckConfig, "limit"> = {
  lookaheadSeconds: 30n * 24n * 60n * 60n,
  maxRenewals: 3,
};

/** A credential that is worth renewing. */
export interface RenewalCandidate {
  readonly ccid: Hex;
  readonly expiresAt: bigint;
  readonly secondsRemaining: bigint;
  readonly renewals: number;
  /** True when the window is inside `urgentSeconds`, so a holder needs telling now. */
  readonly urgent: boolean;
}

export interface RenewalCheckResult {
  readonly candidates: readonly RenewalCandidate[];
  /** Counters, so a run that finds nothing can be told from one that did not look. */
  readonly scanned: number;
  readonly skippedExhausted: number;
  readonly now: bigint;
}

/**
 * Find credentials worth renewing.
 *
 * ## The clock comes from the chain
 *
 * `ExpiryChain.currentTimestamp()` rather than the runtime's own clock. A CRE runtime's
 * wall clock is not the chain's, and using it would mean a credential appearing to have
 * more time left than it does - which is precisely the direction that fails open.
 */
export async function renewalCheck(options: {
  chain: ExpiryChain;
  registry: SensitiveRegistry;
  sink: LogSink;
  config?: Partial<RenewalCheckConfig>;
  urgentSeconds?: bigint;
}): Promise<RenewalCheckResult> {
  const { chain, registry, sink } = options;
  const log = createSafeLogger(sink, registry);
  const config: RenewalCheckConfig = {
    lookaheadSeconds: options.config?.lookaheadSeconds ?? DEFAULT_CONFIG.lookaheadSeconds,
    maxRenewals: options.config?.maxRenewals ?? DEFAULT_CONFIG.maxRenewals,
    limit: options.config?.limit ?? 100,
  };
  const urgentSeconds = options.urgentSeconds ?? 7n * 24n * 60n * 60n;

  const now = await chain.currentTimestamp();
  const found = await chain.findExpiring(config.lookaheadSeconds, config.limit);

  const candidates: RenewalCandidate[] = [];
  let skippedExhausted = 0;

  for (const credential of found) {
    if (credential.renewals >= config.maxRenewals) {
      ++skippedExhausted;
      continue;
    }
    const secondsRemaining = credential.expiresAt - now;
    if (secondsRemaining <= 0n) {
      // Already lapsed. The registry denies it without help, so there is nothing to nudge
      // about - only to report.
      log("renewal.already_expired", {
        ccid: credential.ccid,
        expiresAt: credential.expiresAt.toString(),
      });
      continue;
    }

    candidates.push({
      ccid: credential.ccid,
      expiresAt: credential.expiresAt,
      secondsRemaining,
      renewals: credential.renewals,
      urgent: secondsRemaining <= urgentSeconds,
    });
  }

  candidates.sort((a, b) => (a.secondsRemaining < b.secondsRemaining ? -1 : 1));

  log("renewal.check_completed", {
    scanned: found.length,
    candidates: candidates.length,
    urgent: candidates.filter((c) => c.urgent).length,
    skippedExhausted,
    now: now.toString(),
  });

  // The registry is accepted for symmetry with the other workflows and so a caller can
  // pass one uniformly, but nothing here reads a holder attribute - and touching it
  // would be a false claim that this workflow handled one.
  void registry;

  return { candidates, scanned: found.length, skippedExhausted, now };
}

/**
 * Decide whether a renewal should be attempted.
 *
 * Split out from the scan so the policy is testable on its own: it is a rule about a single
 * credential, and it is the rule that decides whether a holder gets another chance or a
 * message telling them to re-verify.
 */
export function shouldAttemptRenewal(
  credential: Pick<ExpiringCredential, "renewals" | "expiresAt">,
  options: { now: bigint; maxRenewals: number; providerAvailable: boolean },
): { attempt: true } | { attempt: false; reason: "already-expired" | "renewal-budget-exhausted" | "provider-unavailable" } {
  if (options.providerAvailable === false) {
    // Refused rather than attempted: a renewal cannot succeed without a fresh attestation,
    // and attempting one anyway would produce a failed transaction per credential.
    return { attempt: false, reason: "provider-unavailable" };
  }
  if (credential.expiresAt <= options.now) {
    return { attempt: false, reason: "already-expired" };
  }
  if (credential.renewals >= options.maxRenewals) {
    return { attempt: false, reason: "renewal-budget-exhausted" };
  }
  return { attempt: true };
}

/**
 * Whether a re-verification is worth submitting.
 *
 * Separate because a renewal that would not change anything should not be submitted: the
 * gateway would reject it on the expiry check, and a failed transaction is a cost to
 * whoever holds the key.
 *
 * Any difference counts, including a *shorter* expiry. If a provider has decided a
 * credential should now lapse sooner than the chain says, leaving the longer expiry in
 * force is precisely the outcome a compliance control must not permit - the shorter term
 * is the new information, and submitting nothing would preserve the stale, more
 * permissive one.
 */
export function renewalWouldChangeAnything(
  previous: Pick<ExpiringCredential, "expiresAt" | "jurisdictionCode" | "investorClass">,
  next: { jurisdictionCode: number; investorClass: number; expiresAt: bigint },
): boolean {
  return (
    next.expiresAt !== previous.expiresAt ||
    next.jurisdictionCode !== previous.jurisdictionCode ||
    next.investorClass !== previous.investorClass
  );
}

/** Re-exported so a caller wiring this in needs one import for the whole decision. */
export type { ComplianceProvider };
export { assertNotFixtureEvidence };
