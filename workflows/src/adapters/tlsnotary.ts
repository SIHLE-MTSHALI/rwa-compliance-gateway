import type { AttestedResponse } from "./reclaim.js";
import type { Hex } from "viem";

/**
 * TLSNotary transport - **not implemented**.
 *
 * ## Why this throws rather than shipping a partial client
 *
 * Same reasoning as {@link module:adapters/reclaim}, and worth restating because the
 * temptation is strongest precisely here.
 *
 * A notary transport's purpose is to turn "an HTTPS request returned this" into something
 * a smart contract can rely on. The trust is entirely in the attestation. An implementation
 * that fetches over TLS and returns a body with a structurally plausible attestation would
 * let a workflow report a verified result it never verified - and unlike a UI bug, that
 * result becomes a credential that passes a compliance check.
 *
 * So: the interface and the named error, no implementation.
 */

/** Thrown by every method. Named so a caller can catch it specifically. */
export class TlsNotaryTransportNotConfiguredError extends Error {
  constructor(method: string) {
    super(
      `TlsNotaryTransport.${method} is not implemented in this repository. ` +
        `No notary attestation is produced here, and an unbacked attestation would let a ` +
        `workflow report a verification it never performed. Implement this interface against a ` +
        `real notary provider, or use MockProviderAdapter for tests.`,
    );
    this.name = "TlsNotaryTransportNotConfiguredError";
  }
}

/** The interface a real notary transport must satisfy. */
export interface TlsNotaryTransport {
  fetchNotarized(url: string, options?: { timeoutMs?: number }): Promise<AttestedResponse>;
  verifyNotarization(attestation: Hex): Promise<boolean>;
}

/**
 * A placeholder transport. Every method rejects.
 *
 * `async` so the failure surfaces through the promise chain. A method that throws
 * synchronously while declaring a promise return type escapes `.catch()`, which turns a
 * named, actionable error into an unhandled rejection with no cause attached.
 */
export const tlsNotaryTransport: TlsNotaryTransport = {
  async fetchNotarized(_url: string, _options?: { timeoutMs?: number }): Promise<AttestedResponse> {
    throw new TlsNotaryTransportNotConfiguredError("fetchNotarized");
  },
  async verifyNotarization(_attestation: Hex): Promise<boolean> {
    throw new TlsNotaryTransportNotConfiguredError("verifyNotarization");
  },
};

/** Whether a transport is usable, so a workflow can refuse to start with a placeholder. */
export function isNotaryConfigured(transport: TlsNotaryTransport): boolean {
  return transport !== tlsNotaryTransport;
}
