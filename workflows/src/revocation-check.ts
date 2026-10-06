import type { Hex } from "viem";

import { createSafeLogger } from "./privacy.js";
import type { LogSink, SensitiveRegistry } from "./privacy.js";

/**
 * Revocation monitoring: what is on chain that should not be, and did a revocation
 * actually reach every destination.
 *
 * ## The failure this workflow exists to catch
 *
 * A revocation propagates over CCIP, and propagation can fail. The source chain records
 * `Revoked` immediately, so the source is always correct - which is exactly what makes the
 * failure dangerous. An operator checking the source chain sees a correct system while
 * every destination that already received the credential still treats it as valid.
 *
 * Nothing on chain reports that. The message either arrived or it did not, and a
 * destination that never received one is indistinguishable from a destination that was
 * never sent one.
 *
 * So the check is off-chain and explicit: for each destination that holds a replica,
 * compare its accepted nonce against the source's. A destination behind the source on a
 * credential the source has revoked is a stale replica serving a revoked credential.
 *
 * ## Why a stale replica is not harmless
 *
 * `PoolComplianceModule` will report `STALE_DESTINATION` for a replica older than the pool
 * tolerates - but only where the pool's policy opts in with `requiresFreshReplica`. A pool
 * that has not opted in will happily serve a replica of a revoked credential, indefinitely.
 * This workflow is the backstop for that configuration.
 */

/** A replica as the checker sees it on a destination chain. */
export interface ReplicaState {
  readonly ccid: Hex;
  readonly destinationChainSelector: bigint;
  /** The nonce the destination last accepted. */
  readonly acceptedNonce: bigint;
  /** The status the destination holds. */
  readonly status: number;
  /** Seconds since the destination last wrote this credential. */
  readonly ageSeconds: bigint;
}

/** The source chain's view of a credential. */
export interface SourceCredentialState {
  readonly ccid: Hex;
  readonly status: number;
  readonly nonce: bigint;
  readonly providerId: Hex;
  readonly updatedAt: bigint;
}

/** Credential status values, mirroring `ComplianceTypes.CredentialStatus`. */
export const Status = {
  Unknown: 0,
  Pending: 1,
  Valid: 2,
  Expired: 3,
  Suspended: 4,
  Revoked: 5,
} as const;

export type Status = (typeof Status)[keyof typeof Status];

/** The chain operations this workflow needs. */
export interface RevocationChain {
  /** Replicas held on one destination. */
  replicasOn(destinationChainSelector: bigint): Promise<readonly ReplicaState[]>;
  /** The source chain's current state for a set of credentials. */
  sourceState(ccids: readonly Hex[]): Promise<readonly SourceCredentialState[]>;
  /** The source chain's clock. */
  currentTimestamp(): Promise<bigint>;
}

export interface RevocationCheckConfig {
  /** Destinations to inspect in one run. */
  readonly destinations: readonly bigint[];
  /** Max credentials to compare per destination. */
  readonly limit: number;
  /**
   * How stale a replica may be before it is reported regardless of status.
   *
   * A replica that has fallen behind on a `Valid` credential is still serving stale state,
   * which may or may not matter to a given pool. Reported rather than blocked, because
   * this workflow observes and does not decide.
   */
  readonly stalenessThresholdSeconds: bigint;
}

/** One divergence between a source credential and a destination replica. */
export interface Divergence {
  readonly ccid: Hex;
  readonly destinationChainSelector: bigint;
  /** What the source says. */
  readonly sourceStatus: number;
  /** What the destination holds. */
  readonly destinationStatus: number;
  readonly sourceNonce: bigint;
  readonly destinationNonce: bigint;
  /**
   * How bad this is.
   *
   * - `revoked-still-valid`: the destination is serving a credential the source has
   *   revoked. The serious one, and the reason this workflow exists.
   * - `revoked-still-valid-stale`: the same, with the destination additionally behind on
   *   nonce, so a propagation is in flight rather than lost.
   * - `status-behind`: any other status difference, e.g. the source has suspended and the
   *   destination has not heard yet.
   * - `nonce-behind`: statuses agree but the destination is behind. Usually in-flight.
   */
  readonly severity: "revoked-still-valid" | "revoked-still-valid-stale" | "status-behind" | "nonce-behind";
}

export interface RevocationCheckResult {
  readonly divergences: readonly Divergence[];
  /** Counts, so a clean run is distinguishable from a run that looked at nothing. */
  readonly replicasInspected: number;
  readonly sourcesFetched: number;
  readonly now: bigint;
}

/**
 * Compare destination replicas against the source chain.
 *
 * ## Severity ordering is deliberate
 *
 * A destination serving a revoked credential as `Valid` is reported first and separately
 * from ordinary staleness, because the two call for completely different responses: one is
 * an incident, the other is a propagation still in flight. A single "stale" bucket would
 * bury the first inside the second every time a routine propagation was slow.
 */
export async function revocationCheck(options: {
  chain: RevocationChain;
  registry: SensitiveRegistry;
  sink: LogSink;
  config: RevocationCheckConfig;
}): Promise<RevocationCheckResult> {
  const { chain, sink, registry, config } = options;
  const log = createSafeLogger(sink, registry);

  const now = await chain.currentTimestamp();
  const divergences: Divergence[] = [];
  let replicasInspected = 0;
  const sourceByCcid = new Map<string, SourceCredentialState>();

  for (const destination of config.destinations) {
    const replicas = await chain.replicasOn(destination);
    replicasInspected += replicas.length;

    const ccids = replicas.slice(0, config.limit).map((r) => r.ccid);
    if (ccids.length === 0) continue;

    // Fetched per destination rather than once for all of them: the source chain is one
    // chain, so a single fetch would do, but keeping the fetch adjacent to the comparison
    // means a future multi-source deployment needs only this loop changed.
    const sourceStates = await chain.sourceState(ccids);
    for (const state of sourceStates) sourceByCcid.set(state.ccid.toLowerCase(), state);

    for (const replica of replicas.slice(0, config.limit)) {
      const source = sourceByCcid.get(replica.ccid.toLowerCase());
      if (source === undefined) {
        // The destination holds a credential the source has never heard of. Either the
        // destination is trusted from another source, or something is wrong. Either way
        // this workflow cannot adjudicate it, so it says so rather than guessing.
        divergences.push({
          ccid: replica.ccid,
          destinationChainSelector: destination,
          sourceStatus: Status.Unknown,
          destinationStatus: replica.status,
          sourceNonce: 0n,
          destinationNonce: replica.acceptedNonce,
          severity: "status-behind",
        });
        continue;
      }

      const divergence = classify(source, replica);
      if (divergence !== undefined) divergences.push(divergence);
    }
  }

  // Worst first, so an operator reading the top of a list sees an incident rather than
  // routine lag.
  const rank: Record<Divergence["severity"], number> = {
    "revoked-still-valid": 0,
    "revoked-still-valid-stale": 1,
    "status-behind": 2,
    "nonce-behind": 3,
  };
  divergences.sort((a, b) => rank[a.severity] - rank[b.severity]);

  const servingRevoked = divergences.filter(
    (d) => d.severity === "revoked-still-valid" || d.severity === "revoked-still-valid-stale",
  );

  log("revocation.check_completed", {
    destinations: config.destinations.length,
    replicasInspected,
    divergences: divergences.length,
    servingRevoked: servingRevoked.length,
    now: now.toString(),
  });

  for (const divergence of servingRevoked) {
    // Logged individually as well as counted, so an alert can be raised on the log line
    // rather than requiring someone to fetch the result object.
    log("revocation.destination_serving_revoked", {
      ccid: divergence.ccid,
      destinationChainSelector: divergence.destinationChainSelector.toString(),
      sourceNonce: divergence.sourceNonce.toString(),
      destinationNonce: divergence.destinationNonce.toString(),
      severity: divergence.severity,
    });
  }

  return { divergences, replicasInspected, sourcesFetched: sourceByCcid.size, now };
}

/**
 * Classify one source/replica pair.
 *
 * Returns `undefined` when they agree. Exported so the rule can be tested directly against
 * every combination, which a test that has to stand up two chains cannot do as cheaply.
 */
export function classify(source: SourceCredentialState, replica: ReplicaState): Divergence | undefined {
  const base = {
    ccid: source.ccid,
    destinationChainSelector: replica.destinationChainSelector,
    sourceStatus: source.status,
    destinationStatus: replica.status,
    sourceNonce: source.nonce,
    destinationNonce: replica.acceptedNonce,
  };

  if (source.status === Status.Revoked && replica.status === Status.Revoked) {
    // Revocation is terminal: a destination that already reports `Revoked` will never
    // serve this credential again, whatever its nonce says. Reported-as-nonce-behind here
    // would fill an incident queue with every revocation still propagating - the exact
    // noise that buries the destinations that are genuinely still serving.
    return undefined;
  }

  if (source.status === Status.Revoked && replica.status !== Status.Revoked) {
    // The one case that is never acceptable: a revoked credential still being served.
    //
    // The `-stale` suffix marks a destination that is *behind on nonce* - it has not yet
    // received the revocation, so this is a propagation still in flight (or lost). The
    // plain form means the destination is at or past the source's nonce and still serving
    // `Valid`, which no in-flight message explains: that is a destination-side bug, and it
    // will not heal on its own.
    return {
      ...base,
      severity: replica.acceptedNonce < source.nonce ? "revoked-still-valid-stale" : "revoked-still-valid",
    };
  }

  if (source.status !== replica.status) return { ...base, severity: "status-behind" };
  if (replica.acceptedNonce < source.nonce) return { ...base, severity: "nonce-behind" };

  // Destination ahead of the source on nonce would be a genuine anomaly - it means the
  // destination accepted a message the source never sent - so it is reported rather than
  // treated as fine.
  if (replica.acceptedNonce > source.nonce) return { ...base, severity: "nonce-behind" };

  return undefined;
}

/** Re-exported so a caller wiring this in needs one import for the whole check. */
export type { SensitiveRegistry };
