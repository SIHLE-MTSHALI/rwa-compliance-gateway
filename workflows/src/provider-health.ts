import type { Hex } from "viem";

import { createSafeLogger } from "./privacy.js";
import type { LogSink, SensitiveRegistry } from "./privacy.js";

/**
 * Provider health: report on adapters without letting liveness gate access.
 *
 * ## The rule this module exists to protect
 *
 * **A stale heartbeat must never deny access.** Denying on liveness would let a missed
 * heartbeat - a monitoring outage, a paused job, a dropped packet - become a denial of
 * service against every holder served by that provider.
 *
 * So health is computed and reported here, and the access path never reads it.
 * {ProviderRegistry.isProviderHealthy} is a monitoring view; {PoolComplianceModule}
 * consults {ProviderRegistry.backsExistingCredentials} instead, which is a statement about
 * trust rather than about liveness.
 *
 * The one health input that *does* affect access is a reported failure - but that is
 * reported by an operator through `ProviderRegistry.reportFailure`, not inferred here.
 *
 * See `docs/provider-adapter-guide.md`.
 */

/** Provider status values, mirroring `ProviderRegistry.ProviderStatus`. */
export const ProviderStatus = {
  Unknown: 0,
  Paused: 1,
  Active: 2,
  Deprecated: 3,
  Revoked: 4,
} as const;

export type ProviderStatus = (typeof ProviderStatus)[keyof typeof ProviderStatus];

export function providerStatusName(status: ProviderStatus): string {
  switch (status) {
    case ProviderStatus.Unknown:
      return "Unknown";
    case ProviderStatus.Paused:
      return "Paused";
    case ProviderStatus.Active:
      return "Active";
    case ProviderStatus.Deprecated:
      return "Deprecated";
    case ProviderStatus.Revoked:
      return "Revoked";
    default:
      return "Unrecognized";
  }
}

/** A provider as this workflow sees it. */
export interface ProviderSnapshot {
  readonly providerId: Hex;
  readonly status: ProviderStatus;
  /** Last heartbeat, or 0 if never recorded. */
  readonly lastHeartbeat: bigint;
  /** Consecutive failures an operator has reported. */
  readonly failureCount: bigint;
  readonly registered: boolean;
}

/** The chain operations this workflow needs. */
export interface ProviderHealthChain {
  /** Every registered provider. */
  providers(): Promise<readonly ProviderSnapshot[]>;
  /** Record a heartbeat. */
  heartbeat(providerId: Hex): Promise<void>;
  /** Record an adapter failure. */
  reportFailure(providerId: Hex): Promise<void>;
  /** The source chain's clock. */
  currentTimestamp(): Promise<bigint>;
}

export interface ProviderHealthConfig {
  /**
   * How old a heartbeat may be before the provider is reported unhealthy.
   *
   * Must match `ProviderRegistry.HEARTBEAT_STALENESS_SECONDS`. Read from the contract
   * where possible rather than configured here, because a divergence means this workflow
   * and the contract disagree about what "healthy" means - and the contract is the one
   * that matters.
   */
  readonly stalenessSeconds: bigint;
  /** Provider ids to check. Empty means every registered provider. */
  readonly only?: readonly Hex[];
}

/** One provider's assessed state. */
export interface ProviderHealth {
  readonly providerId: Hex;
  readonly status: ProviderStatus;
  readonly statusName: string;
  readonly healthy: boolean;
  readonly heartbeatAgeSeconds: bigint | null;
  /**
   * Whether the provider still backs credentials that already exist.
   *
   * `Deprecated` returns true, and this is the field an operator should read before
   * deciding a provider is in trouble: a deprecated provider is winding down by design,
   * while a paused one is not.
   */
  readonly backsExistingCredentials: boolean;
  /** Whether new issuance is possible. */
  readonly canIssue: boolean;
  /** Whether the provider is registered at all. */
  readonly registered: boolean;
  /** Consecutive failures an operator has reported. */
  readonly failureCount: bigint;
  readonly reason?: string;
}

export interface ProviderHealthResult {
  readonly providers: readonly ProviderHealth[];
  readonly unhealthyCount: number;
  readonly now: bigint;
}

/**
 * Assess every provider's health.
 *
 * Reports; does not act. The one exception is {@link submitHeartbeats}, which records
 * liveness - and even that cannot affect access, because the registry only uses heartbeats
 * for monitoring.
 */
export async function providerHealth(options: {
  chain: ProviderHealthChain;
  registry: SensitiveRegistry;
  sink: LogSink;
  config: ProviderHealthConfig;
}): Promise<ProviderHealthResult> {
  const { chain, sink, registry, config } = options;
  const log = createSafeLogger(sink, registry);

  const now = await chain.currentTimestamp();
  const snapshots = await chain.providers();
  const only = config.only === undefined ? null : new Set(config.only.map((p) => p.toLowerCase()));

  const assessed: ProviderHealth[] = [];

  for (const snapshot of snapshots) {
    if (only !== null && !only.has(snapshot.providerId.toLowerCase())) continue;
    assessed.push(assessProvider(snapshot, now, config.stalenessSeconds));
  }

  const unhealthyCount = assessed.filter((p) => !p.healthy).length;

  log("provider.health_completed", {
    providers: assessed.length,
    unhealthy: unhealthyCount,
    now: now.toString(),
  });

  for (const provider of assessed) {
    if (provider.healthy) continue;
    log("provider.unhealthy", {
      providerId: provider.providerId,
      status: provider.statusName,
      heartbeatAgeSeconds: provider.heartbeatAgeSeconds === null ? "never" : provider.heartbeatAgeSeconds.toString(),
      failureCount: provider.failureCount,
      reason: provider.reason ?? "unknown",
    });
  }

  return { providers: assessed, unhealthyCount, now };
}

/**
 * Assess one provider.
 *
 * Exported so every combination of status, heartbeat and failure count can be tested
 * directly - which is the whole point, because the combinations are where the
 * `Deprecated` distinction lives and where a mistake silently denies a pool's investors.
 */
export function assessProvider(snapshot: ProviderSnapshot, now: bigint, stalenessSeconds: bigint): ProviderHealth {
  const heartbeatAgeSeconds = snapshot.lastHeartbeat === 0n ? null : now - snapshot.lastHeartbeat;
  const canIssue = snapshot.registered && snapshot.status === ProviderStatus.Active;
  const backsExistingCredentials =
    snapshot.registered &&
    (snapshot.status === ProviderStatus.Active || snapshot.status === ProviderStatus.Deprecated);

  let healthy: boolean;
  let reason: string | undefined;

  if (!snapshot.registered) {
    healthy = false;
    reason = "not-registered";
  } else if (snapshot.status === ProviderStatus.Revoked) {
    healthy = false;
    reason = "revoked";
  } else if (snapshot.status === ProviderStatus.Paused) {
    healthy = false;
    reason = "paused";
  } else if (snapshot.failureCount > 0n) {
    healthy = false;
    reason = "unresolved-failures";
  } else if (snapshot.status !== ProviderStatus.Active) {
    // `Deprecated` is healthy *as an adapter* - it is working exactly as configured. It is
    // winding down, which is a plan, not a fault. Reporting it as unhealthy would train
    // operators to ignore this signal.
    healthy = snapshot.status === ProviderStatus.Deprecated;
    reason = healthy ? undefined : "not-active";
  } else if (heartbeatAgeSeconds === null) {
    healthy = false;
    reason = "never-heartbeated";
  } else {
    healthy = heartbeatAgeSeconds <= stalenessSeconds;
    reason = healthy ? undefined : "stale-heartbeat";
  }

  return {
    providerId: snapshot.providerId,
    status: snapshot.status,
    statusName: providerStatusName(snapshot.status),
    healthy,
    heartbeatAgeSeconds,
    backsExistingCredentials,
    canIssue,
    registered: snapshot.registered,
    failureCount: snapshot.failureCount,
    ...(reason === undefined ? {} : { reason }),
  };
}

/**
 * Record a heartbeat for each provider.
 *
 * Deliberately the *only* thing this workflow writes. It cannot change a provider's status,
 * cannot revoke a credential, and cannot touch a policy - so a bug here degrades monitoring
 * and nothing else.
 */
export async function submitHeartbeats(options: {
  chain: ProviderHealthChain;
  providers: readonly Hex[];
}): Promise<{ submitted: number; failed: number }> {
  let submitted = 0;
  let failed = 0;

  for (const providerId of options.providers) {
    try {
      await options.chain.heartbeat(providerId);
      ++submitted;
    } catch {
      // A failed heartbeat is not itself worth stopping for - that would make the health
      // reporter the cause of the staleness it exists to report.
      ++failed;
    }
  }

  return { submitted, failed };
}

/**
 * Whether a provider's state should stop new issuance from being attempted.
 *
 * Distinct from health on purpose. A provider can be unhealthy - stale heartbeat, reported
 * failure - and still be the only one for a schema, so refusing to issue against it may be
 * worse than issuing. Only `Revoked` and `Paused` are states where the registry itself will
 * reject the issuance anyway.
 */
export function shouldAttemptIssuance(provider: Pick<ProviderHealth, "status" | "registered">): boolean {
  return provider.registered && provider.status === ProviderStatus.Active;
}

/** Re-exported so a caller wiring this in needs one import. */
export type { SensitiveRegistry };
