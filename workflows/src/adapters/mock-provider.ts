import type { Hex } from "viem";

import { keccak256, stringToHex } from "viem";

/**
 * A stand-in verification provider, for tests and local development only.
 *
 * ## The marker is load-bearing
 *
 * Every evidence hash this adapter produces carries
 * {@link FIXTURE_MARKER}. It is there so a fixture can never be mistaken for a real
 * attestation: if a value carrying this marker ever reaches a production deployment, it is
 * greppable, and an auditor reading the audit trail can see at a glance which records came
 * from a mock.
 *
 * That marker is also what {@link assertNotFixtureEvidence} checks. A mock adapter that
 * quietly produced unmarked output would be the most dangerous kind of test double - the
 * one whose output looks exactly like the real thing.
 *
 * ## What it does not do
 *
 * It verifies nothing. It derives a jurisdiction and a class from a label the caller
 * supplies, because there is no identity document to check. See
 * `docs/provider-adapter-guide.md` for what a real adapter has to do instead.
 */

/** Present in every `evidenceHash` this adapter produces. Greppable, and asserted on. */
export const FIXTURE_MARKER = "fixture-only-mock-provider";

/** Thrown if a fixture's evidence is submitted where real evidence is required. */
export class FixtureEvidenceError extends Error {
  constructor(evidenceHash: string) {
    super(
      `refusing to use fixture evidence (${evidenceHash.slice(0, 18)}...) in a non-fixture path. ` +
        `${FIXTURE_MARKER} output must never reach a deployment.`,
    );
    this.name = "FixtureEvidenceError";
  }
}

/** True when an evidence hash came from {@link MockProviderAdapter}. */
export function isFixtureEvidence(evidenceHash: Hex | string): boolean {
  return tryDecodeMarker(evidenceHash) !== null;
}

/** The jurisdiction this adapter reported, if it reported one. */
export function fixtureJurisdictionOf(evidenceHash: Hex | string): number | null {
  const decoded = tryDecodeMarker(evidenceHash);
  return decoded === null ? null : decoded.jurisdictionCode;
}

/**
 * Decode a fixture evidence hash.
 *
 * Layout: `keccak256(utf8(marker) | utf8(jurisdiction) | utf8(investorClass))`, so the
 * marker is recoverable from the commitment without keeping the evidence around.
 */
function tryDecodeMarker(evidenceHash: Hex | string): { jurisdictionCode: number; investorClass: number } | null {
  const raw = evidenceHash.startsWith("0x") ? evidenceHash.slice(2) : evidenceHash;
  if (raw.length !== 64) return null;

  // The marker is not recoverable from the hash itself - that is what a hash is for. So
  // the marker is carried as a *prefix* instead: `markerTag` occupies the first bytes and
  // the rest carries the jurisdiction and class in plain view.
  //
  // Deliberately not a hash of the marker. A mock whose output was indistinguishable from
  // a real attestation could not be identified after the fact, and "did this credential
  // come from a test double?" is a question that must stay answerable.
  const tag = raw.slice(0, 16);
  if (tag !== FIXTURE_TAG) return null;

  const jurisdiction = Number.parseInt(raw.slice(16, 24), 16);
  const investorClass = Number.parseInt(raw.slice(24, 32), 16);
  if (!Number.isInteger(jurisdiction) || !Number.isInteger(investorClass)) return null;

  return { jurisdictionCode: jurisdiction, investorClass };
}

/** First 16 hex characters of the keccak of the marker label. */
const FIXTURE_TAG = keccak256(stringToHex(FIXTURE_MARKER)).slice(2, 18);

/** What a provider is asked to attest. */
export interface VerificationRequest {
  /**
   * The holder's verified attribute. In a real adapter this is a document number, a
   * passport MRZ, or similar.
   *
   * In this adapter it is only hashed, never stored - and the workflow must pass it
   * through {@link SensitiveRegistry.learn} first so it can never be logged.
   */
  readonly attribute: string;
  /** What the provider is being asked to determine. */
  readonly requested: ("jurisdiction" | "investorClass" | "both")[];
  /** A label the fixture maps to a jurisdiction and class. Ignored by a real adapter. */
  readonly fixtureProfile?: string;
}

/** What a provider reports back. */
export interface VerificationResult {
  readonly jurisdictionCode: number;
  readonly investorClass: number;
  /** A commitment to the evidence, carrying {@link FIXTURE_MARKER}. Never the evidence. */
  readonly evidenceHash: Hex;
  readonly verifiedAt: bigint;
}

/**
 * Fixture profiles, keyed by label.
 *
 * Small and explicit: a fixture whose behaviour depended on a heuristic would make a test
 * failure hard to read, because the profile would have to be inferred from the output.
 */
const PROFILES: Readonly<Record<string, { jurisdictionCode: number; investorClass: number }>> = {
  "us-accredited": { jurisdictionCode: 840, investorClass: 1 },
  "us-non-professional": { jurisdictionCode: 840, investorClass: 2 },
  "uk-non-professional": { jurisdictionCode: 826, investorClass: 2 },
  "jp-non-professional": { jurisdictionCode: 392, investorClass: 2 },
  "blocked": { jurisdictionCode: 840, investorClass: 3 },
};

export function fixtureProfileNames(): string[] {
  return Object.keys(PROFILES);
}

/**
 * A provider adapter that resolves fixtures instead of verifying anything.
 *
 * Deterministic and offline. `failNext` exists so a workflow's error path can be exercised
 * without a network, and `latencyMs` so retry behaviour can be tested.
 */
export class MockProviderAdapter {
  /** Set to make the next `n` calls throw, for retry and failure-path testing. */
  failNext = 0;

  /** Simulated latency. Does not actually sleep; it is read by the caller. */
  latencyMs = 0;

  /** Every request this adapter has seen. Useful for asserting what was *not* logged. */
  readonly requests: VerificationRequest[] = [];

  async verify(request: VerificationRequest, now: bigint): Promise<VerificationResult> {
    this.requests.push(request);

    if (this.failNext > 0) {
      this.failNext -= 1;
      throw new Error("fixture provider failure (simulated)");
    }

    const profileName = request.fixtureProfile ?? "us-accredited";
    const profile = PROFILES[profileName];
    if (profile === undefined) {
      throw new Error(
        `unknown fixture profile "${profileName}"; available: ${fixtureProfileNames().join(", ")}`,
      );
    }

    const wantsJurisdiction = request.requested.includes("jurisdiction") || request.requested.includes("both");
    const wantsClass = request.requested.includes("investorClass") || request.requested.includes("both");

    if (!wantsJurisdiction && !wantsClass) {
      throw new Error("nothing was requested: a verification must ask for at least one attribute");
    }

    return {
      jurisdictionCode: wantsJurisdiction ? profile.jurisdictionCode : 0,
      investorClass: wantsClass ? profile.investorClass : 0,
      evidenceHash: this.encodeEvidence(profile, request.attribute),
      verifiedAt: now,
    };
  }

  /**
   * Encode the evidence commitment as `tag | jurisdiction | class`.
   *
   * The attribute is hashed alongside them, so two verifications of the same attribute
   * under the same profile produce the same commitment - which is what lets a fixture test
   * assert a specific CCID.
   */
  private encodeEvidence(
    profile: { jurisdictionCode: number; investorClass: number },
    attribute: string,
  ): Hex {
    const jurisdiction = profile.jurisdictionCode.toString(16).padStart(8, "0");
    const investorClass = profile.investorClass.toString(16).padStart(8, "0");
    const digest = keccak256(stringToHex(attribute)).slice(2);
    // tag (16) + jurisdiction (8) + class (8) + digest tail (32) = 64 characters.
    return `0x${FIXTURE_TAG}${jurisdiction}${investorClass}${digest.slice(-32)}`;
  }
}

/**
 * Refuse evidence that came from a fixture.
 *
 * To be called on any path where a real attestation is required. The guard exists because
 * the failure it prevents is otherwise invisible: a fixture credential would be
 * indistinguishable from a verified one at every layer above the adapter.
 */
export function assertNotFixtureEvidence(evidenceHash: Hex | string): void {
  if (isFixtureEvidence(evidenceHash)) {
    throw new FixtureEvidenceError(evidenceHash);
  }
}
