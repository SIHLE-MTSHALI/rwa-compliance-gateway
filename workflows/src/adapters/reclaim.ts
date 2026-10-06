import type { VerificationRequest, VerificationResult } from "./mock-provider.js";
import type { Hex } from "viem";

/**
 * Reclaim zkTLS transport - **not implemented**.
 *
 * ## Why this throws rather than shipping a partial client
 *
 * A zkTLS adapter is the mechanism that makes an off-chain provider's response provable:
 * the HTTP transcript is attested so a workflow can claim "the provider said this" rather
 * than "something said this".
 *
 * An adapter that constructs the right types but does not actually attest the transcript
 * is worse than no adapter at all, and the failure is silent. Every caller would work, the
 * workflow would produce evidence hashes, and those hashes would carry an implication of
 * attestation that nothing in the code backs up. The one component whose whole job is to
 * be trusted is the one that must refuse to run.
 *
 * So this module exists with the right interface and throws a named error. An integrator
 * swaps in a real implementation; nothing else in the workflow changes.
 *
 * See `docs/provider-adapter-guide.md` for what implementing this actually requires.
 */

/** Thrown by every method. Named so a caller can catch it specifically. */
export class ReclaimTransportNotConfiguredError extends Error {
  constructor(method: string) {
    super(
      `ReclaimTransport.${method} is not implemented in this repository. ` +
        `This repository ships no zkTLS transport: an adapter that returns evidence without ` +
        `attesting the HTTP transcript would let a caller believe it had a proof it does not. ` +
        `Implement this interface against a real zkTLS provider, or use MockProviderAdapter for tests.`,
    );
    this.name = "ReclaimTransportNotConfiguredError";
  }
}

/**
 * The interface a real transport must satisfy.
 *
 * Exported so an integrator can implement against it without reading this file's prose.
 */
export interface ZkTlsTransport {
  /** Fetch and attest a JSON response. */
  fetchAttestedJson(url: string, options?: { timeoutMs?: number }): Promise<AttestedResponse>;
  /** Verify an attestation produced by this transport. */
  verifyAttestation(attestation: Hex): Promise<boolean>;
}

/** What an attested fetch returns. */
export interface AttestedResponse {
  readonly statusCode: number;
  readonly body: string;
  /** The attestation over the transcript. */
  readonly attestation: Hex;
  /** Where the transcript was signed. */
  readonly signer: string;
}

/**
 * A placeholder transport. Every method rejects.
 *
 * Exported so a workflow's dependency-injection wiring typechecks out of the box, and so
 * the failure a caller sees is a named one rather than a missing import.
 *
 * The methods are `async` and therefore *reject* rather than throwing synchronously. A
 * method declared to return a promise that throws before the promise exists is a footgun:
 * `transport.fetchAttestedJson(url).catch(handle)` never reaches `handle`, and the
 * workflow dies somewhere further up with an error that no longer names the real cause.
 */
export const reclaimTransport: ZkTlsTransport = {
  async fetchAttestedJson(_url: string, _options?: { timeoutMs?: number }): Promise<AttestedResponse> {
    throw new ReclaimTransportNotConfiguredError("fetchAttestedJson");
  },
  async verifyAttestation(_attestation: Hex): Promise<boolean> {
    throw new ReclaimTransportNotConfiguredError("verifyAttestation");
  },
};

/**
 * Whether a transport is usable.
 *
 * Lets a workflow fail its readiness check before it starts doing work, rather than on the
 * first credential it was asked to verify.
 */
export function isTransportConfigured(transport: ZkTlsTransport): boolean {
  return transport !== reclaimTransport;
}

/** Re-exported so a caller wiring this in needs only one import. */
export type { VerificationRequest, VerificationResult };
