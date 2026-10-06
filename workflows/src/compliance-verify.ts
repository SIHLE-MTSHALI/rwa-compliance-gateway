import { computeCcid, labelToId, type CcidInput } from "@rwa-compliance/sdk";
import { keccak256, stringToHex, type Hex } from "viem";

import type { VerificationRequest, VerificationResult } from "./adapters/mock-provider.js";
import { assertNotFixtureEvidence } from "./adapters/mock-provider.js";
import { createSafeLogger, toSafeSummary } from "./privacy.js";
import type { LogSink, SafeDecisionSummary, SensitiveRegistry } from "./privacy.js";

/**
 * Compliance verification: turn a holder's attributes into a credential result.
 *
 * ## The shape of a workflow here
 *
 * Every function in this package is pure with respect to the chain: it takes a provider, a
 * clock, a log sink and a registry, and returns a decision. Nothing reaches the network
 * unless a caller injects something that does.
 *
 * That is deliberate. A workflow that talks to a chain directly cannot be tested without
 * one, and a compliance workflow that cannot be tested is a compliance workflow whose
 * behaviour is whatever the last run happened to do.
 */

/** The chain-facing operations a workflow needs. Injected, so tests supply a fake. */
export interface CredentialChain {
  /** Open a credential in `Pending`. */
  beginVerification(params: { ccid: Hex; credentialType: Hex; schemaVersion: number; ttlSeconds: bigint }): Promise<Hex>;
  /** Submit a verified result. */
  submitResult(params: VerificationSubmission): Promise<Hex>;
}

/** What a workflow submits. Mirrors `ComplianceTypes.CredentialResult`. */
export interface VerificationSubmission {
  readonly ccid: Hex;
  readonly credentialType: Hex;
  readonly providerId: Hex;
  /** Never stored; the gateway verifies the CCID against it and then discards it. */
  readonly subjectCommitment: Hex;
  readonly evidenceHash: Hex;
  readonly schemaVersion: number;
  readonly jurisdictionCode: number;
  readonly investorClass: number;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
  readonly nonce: bigint;
  readonly destinationChainSelectors: readonly bigint[];
}

/** A verification provider. The real one attests; the fixture does not. */
export interface ComplianceProvider {
  verify(request: VerificationRequest, now: bigint): Promise<VerificationResult>;
  readonly failNext?: number;
}

/** Configuration, all explicit. */
export interface ComplianceVerifyConfig {
  readonly poolId: Hex;
  readonly credentialType: Hex;
  readonly providerId: Hex;
  readonly schemaVersion: number;
  /** How long a credential is valid, in seconds. */
  readonly ttlSeconds: bigint;
  /** How long the `Pending` window stays open, in seconds. */
  readonly pendingTtlSeconds: bigint;
  /** CCIP chain selectors to propagate to. */
  readonly destinations: readonly bigint[];
  /**
   * Refuse evidence produced by the fixture adapter.
   *
   * Defaults to true, and is configurable only so a *test* of this workflow can opt out.
   * A fixture credential reaching a deployment is the failure this guards against, and it
   * is invisible once written: it would pass every policy check.
   */
  readonly allowFixtureEvidence?: boolean;
}

/** What the caller supplied to verify. */
export interface ComplianceVerifyInput {
  /**
   * The holder's verified attribute.
   *
   * Learn it into the registry before passing it in - the workflow cannot do that for the
   * caller, and once it is inside this function a leak becomes much harder to trace.
   */
  readonly attribute: string;
  /** Salt for the subject commitment. Never sent to the chain, and never logged. */
  readonly salt: string;
  readonly nonce: bigint;
  /** Only used by the fixture adapter; ignored by a real provider. */
  readonly fixtureProfile?: string;
  readonly now: bigint;
}

/** The result of a verification run. */
export interface ComplianceVerifyResult {
  /** Present when a credential was produced. Absent on any failure. */
  readonly summary?: SafeDecisionSummary;
  /** True when the run ended without a credential. */
  readonly failed: boolean;
  /** Why. Safe to show a holder - never contains an attribute. */
  readonly reason?: string;
}

export type VerifyFailure =
  | "provider-unavailable"
  | "provider-rejected"
  | "fixture-evidence-rejected"
  | "unknown-jurisdiction"
  | "unknown-class"
  | "chain-write-failed";

/**
 * Verify a holder and submit a credential.
 *
 * ## Order of operations, and why
 *
 * 1. **Compute the CCID first.** It depends on the provider's *result*, not on the input, so
 *    this happens after verification - but the `Pending` record is opened before
 *    submission so a holder can see a check is running rather than observing
 *    `NO_CREDENTIAL` and being unable to tell "not requested" from "requested, still
 *    running".
 * 2. **Learn the attribute before it can reach a log.** The registry is populated at the
 *    top, so even an exception path cannot log the value.
 * 3. **Submit last**, so a credential is only ever written after a provider has attested.
 * 4. **Never log the commitment's preimage**, only the CCID it derives.
 */
export async function complianceVerify(options: {
  chain: CredentialChain;
  provider: ComplianceProvider;
  config: ComplianceVerifyConfig;
  registry: SensitiveRegistry;
  sink: LogSink;
  input: ComplianceVerifyInput;
}): Promise<ComplianceVerifyResult> {
  const { chain, provider, config, registry, sink, input } = options;
  // Bound here rather than accepted as a ready-made logger, so there is no call site at
  // which this workflow can log without the registry that holds the holder's values.
  const log = createSafeLogger(sink, registry);

  // First, so any later throw still cannot leak the attribute.
  registry.learn(input.attribute);
  registry.learn(input.salt);

  let verification: VerificationResult;
  try {
    verification = await provider.verify(
      {
        attribute: input.attribute,
        requested: ["jurisdiction", "investorClass"],
        ...(input.fixtureProfile === undefined ? {} : { fixtureProfile: input.fixtureProfile }),
      },
      input.now,
    );
  } catch (error) {
    log("compliance.verify.provider_failed", { error: describeError(error) });
    return { failed: true, reason: "provider-unavailable" satisfies VerifyFailure };
  }

  if (verification.jurisdictionCode === 0 || verification.investorClass === 0) {
    // The provider declined to answer something it was asked for. Treated as a refusal,
    // not a partial result: a credential asserting an unset attribute is a credential that
    // would fail policy later, for a reason the holder could not act on.
    log("compliance.verify.provider_declined", {
      jurisdictionCode: verification.jurisdictionCode,
      investorClass: verification.investorClass,
    });
    return { failed: true, reason: "provider-rejected" satisfies VerifyFailure };
  }

  if (config.allowFixtureEvidence !== true) {
    try {
      assertNotFixtureEvidence(verification.evidenceHash);
    } catch {
      log("compliance.verify.fixture_evidence_rejected", {});
      return { failed: true, reason: "fixture-evidence-rejected" satisfies VerifyFailure };
    }
  }

  // The commitment is derived here and never leaves the runtime in plaintext. Only the
  // CCID - a hash of it, among other things - reaches the chain.
  const subjectCommitment = saltedCommitment(input.salt, input.attribute);

  const ccidInput: CcidInput = {
    credentialType: config.credentialType,
    schemaVersion: config.schemaVersion,
    providerId: config.providerId,
    jurisdictionCode: verification.jurisdictionCode,
    investorClass: verification.investorClass as CcidInput["investorClass"],
    subjectCommitment,
  };
  const ccid = computeCcid(ccidInput);

  const issuedAt = input.now;
  const expiresAt = input.now + config.ttlSeconds;

  try {
    await chain.beginVerification({
      ccid,
      credentialType: config.credentialType,
      schemaVersion: config.schemaVersion,
      ttlSeconds: config.pendingTtlSeconds,
    });

    await chain.submitResult({
      ccid,
      credentialType: config.credentialType,
      providerId: config.providerId,
      subjectCommitment,
      evidenceHash: verification.evidenceHash,
      schemaVersion: config.schemaVersion,
      jurisdictionCode: verification.jurisdictionCode,
      investorClass: verification.investorClass,
      issuedAt,
      expiresAt,
      nonce: input.nonce,
      destinationChainSelectors: [...config.destinations],
    });
  } catch (error) {
    log("compliance.verify.chain_write_failed", { error: describeError(error), ccid });
    return { failed: true, reason: "chain-write-failed" satisfies VerifyFailure };
  }

  const summary = toSafeSummary({
    ccid,
    status: "Valid",
    reason: "OK",
    nonce: input.nonce,
    providerId: config.providerId,
  });

  log("compliance.verify.succeeded", {
    ccid: summary.ccid,
    status: summary.status,
    reason: summary.reason,
    nonce: summary.nonce,
    providerId: summary.providerId,
    jurisdictionCode: verification.jurisdictionCode,
    investorClass: verification.investorClass,
    destinations: config.destinations.length,
  });

  return { failed: false, summary };
}

/**
 * Derive the holder's subject commitment.
 *
 * Exported so a renewal or revocation workflow can recognise a commitment it previously
 * produced without recomputing it from the attribute it no longer holds.
 *
 * ## This is the privacy boundary
 *
 * The salt is what makes the commitment unlinkable across issuers, and it must never
 * reach the chain or a log. The workflow holds the attribute and the salt, derives this,
 * and sends only the result. Nothing downstream - the gateway, a destination chain, an
 * auditor - can recover the attribute from it.
 *
 * ## What this is not
 *
 * `keccak(salt || attribute)` is the *shape* of a salted commitment, not a production
 * construction. A salt of this kind is not a secret: if the attribute is guessable - and a
 * passport number is not - then an attacker holding both the salt and the commitment can
 * confirm a guess. A real workflow should use a keyed commitment, or an HMAC whose key
 * lives in the runtime's secret store and never in code or configuration.
 *
 * See `ccid.ts`'s `saltedSubjectCommitment`, which carries the same warning, and
 * `docs/privacy-model.md`.
 */
export function saltedCommitment(salt: string, attribute: string): Hex {
  return keccak256(`${stringToHex(salt)}${stringToHex(attribute)}` as Hex);
}

/** A short, safe description of an error. Never its input. */
function describeError(error: unknown): string {
  if (error instanceof Error) {
    // Only the name and a truncated message. A provider error can echo the request, and
    // the request carries the attribute.
    return `${error.name}: ${error.message.slice(0, 120)}`;
  }
  return "unknown error";
}

export { labelToId };
