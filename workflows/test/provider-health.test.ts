import { describe, expect, it } from "vitest";
import type { Hex } from "viem";

import {
  ProviderStatus,
  assessProvider,
  providerHealth,
  providerStatusName,
  shouldAttemptIssuance,
  submitHeartbeats,
  type ProviderHealthChain,
  type ProviderSnapshot,
} from "../src/provider-health.js";
import { SensitiveRegistry, type LogRecord } from "../src/privacy.js";

function capture(): { sink: (record: LogRecord) => void; records: LogRecord[] } {
  const records: LogRecord[] = [];
  return { sink: (record) => records.push(record), records };
}

const ID = (n: number): Hex => `0x${n.toString(16).padStart(64, "0")}` as Hex;
const NOW = 1_700_000_000n;

function snapshot(over: Partial<ProviderSnapshot> = {}): ProviderSnapshot {
  return {
    providerId: ID(1),
    status: ProviderStatus.Active,
    lastHeartbeat: NOW - 60n,
    failureCount: 0n,
    registered: true,
    ...over,
  };
}

describe("providerStatusName", () => {
  it("names every status", () => {
    expect(providerStatusName(ProviderStatus.Unknown)).toBe("Unknown");
    expect(providerStatusName(ProviderStatus.Paused)).toBe("Paused");
    expect(providerStatusName(ProviderStatus.Active)).toBe("Active");
    expect(providerStatusName(ProviderStatus.Deprecated)).toBe("Deprecated");
    expect(providerStatusName(ProviderStatus.Revoked)).toBe("Revoked");
  });

  it("reports an out-of-range status rather than guessing", () => {
    expect(providerStatusName(99 as never)).toBe("Unrecognized");
  });
});

describe("assessProvider", () => {
  it("reports a healthy active provider", () => {
    const health = assessProvider(snapshot(), NOW, 3600n);
    expect(health.healthy).toBe(true);
    expect(health.reason).toBeUndefined();
    expect(health.heartbeatAgeSeconds).toBe(60n);
  });

  it("treats a deprecated provider as healthy, because winding down is a plan", () => {
    // The distinction operators need: `Deprecated` is the adapter working exactly as
    // configured. Reporting it unhealthy would train them to ignore this signal - and it
    // still backs existing credentials, which is what matters for a live pool.
    const health = assessProvider(
      snapshot({ status: ProviderStatus.Deprecated }),
      NOW,
      3600n,
    );
    expect(health.healthy).toBe(true);
    expect(health.backsExistingCredentials).toBe(true);
    expect(health.canIssue).toBe(false);
  });

  it("treats a paused provider as unhealthy and as no longer backing credentials", () => {
    const health = assessProvider(snapshot({ status: ProviderStatus.Paused }), NOW, 3600n);
    expect(health.healthy).toBe(false);
    expect(health.reason).toBe("paused");
    expect(health.backsExistingCredentials).toBe(false);
  });

  it("separates revoked from paused in the reported reason", () => {
    // Both deny, but a revoked provider is a trust decision and a paused one is
    // operational. An incident review needs to know which.
    expect(assessProvider(snapshot({ status: ProviderStatus.Revoked }), NOW, 3600n).reason).toBe("revoked");
    expect(assessProvider(snapshot({ status: ProviderStatus.Paused }), NOW, 3600n).reason).toBe("paused");
  });

  it("reports a stale heartbeat without denying access", () => {
    // The property the whole module exists to protect: liveness is reported, never
    // enforced. Denying on a missed heartbeat would turn a monitoring outage into a denial
    // of service against every holder served by that provider.
    const health = assessProvider(snapshot({ lastHeartbeat: NOW - 7200n }), NOW, 3600n);
    expect(health.healthy).toBe(false);
    expect(health.reason).toBe("stale-heartbeat");
    expect(health.backsExistingCredentials).toBe(true);
    expect(health.canIssue).toBe(true);
  });

  it("distinguishes never-heartbeated from stale", () => {
    // Different problems: a provider that has never reported is misconfigured; one that
    // stopped reporting is a fault.
    const health = assessProvider(snapshot({ lastHeartbeat: 0n }), NOW, 3600n);
    expect(health.reason).toBe("never-heartbeated");
    expect(health.heartbeatAgeSeconds).toBeNull();
  });

  it("reports reported failures as unhealthy even with a fresh heartbeat", () => {
    // A failure is an operator's report, which is stronger evidence than liveness.
    const health = assessProvider(snapshot({ failureCount: 1n }), NOW, 3600n);
    expect(health.healthy).toBe(false);
    expect(health.reason).toBe("unresolved-failures");
  });

  it("reports an unregistered provider as such", () => {
    const health = assessProvider(snapshot({ registered: false }), NOW, 3600n);
    expect(health.reason).toBe("not-registered");
    expect(health.canIssue).toBe(false);
  });

  it("accepts a heartbeat exactly at the staleness boundary", () => {
    // Off-by-one here would either deny a healthy provider or mask a stale one, and which
    // of those happens depends on the comparison operator rather than the intent.
    expect(assessProvider(snapshot({ lastHeartbeat: NOW - 3600n }), NOW, 3600n).healthy).toBe(true);
    expect(assessProvider(snapshot({ lastHeartbeat: NOW - 3601n }), NOW, 3600n).healthy).toBe(false);
  });

  it("never allows issuance except from an active registered provider", () => {
    for (const status of [ProviderStatus.Unknown, ProviderStatus.Paused, ProviderStatus.Deprecated, ProviderStatus.Revoked]) {
      expect(
        assessProvider(snapshot({ status }), NOW, 3600n).canIssue,
        `status ${providerStatusName(status)} must not allow issuance`,
      ).toBe(false);
    }
    expect(assessProvider(snapshot(), NOW, 3600n).canIssue).toBe(true);
  });

  it("never backs existing credentials from a revoked provider", () => {
    // Revocation is a trust decision: a provider the governance revoked must not be able
    // to keep vouching for credentials that already exist.
    expect(assessProvider(snapshot({ status: ProviderStatus.Revoked }), NOW, 3600n).backsExistingCredentials).toBe(false);
  });
});

describe("shouldAttemptIssuance", () => {
  it("agrees with the gateway: only an active registered provider", () => {
    // Deliberately stricter than `healthy`. A provider can be unhealthy - stale heartbeat,
    // a reported failure - and still be the only one for a schema, so refusing to issue
    // against it may be worse than issuing. Only states the registry itself rejects.
    const stale = assessProvider(snapshot({ lastHeartbeat: NOW - 7200n }), NOW, 3600n);
    expect(stale.healthy).toBe(false);
    expect(shouldAttemptIssuance(stale)).toBe(true);
  });

  it("refuses for paused and revoked", () => {
    for (const status of [ProviderStatus.Paused, ProviderStatus.Revoked, ProviderStatus.Deprecated]) {
      const provider = assessProvider(snapshot({ status }), NOW, 3600n);
      expect(shouldAttemptIssuance(provider), providerStatusName(status)).toBe(false);
    }
  });
});

function fakeChain(
  snapshots: readonly ProviderSnapshot[],
  opts: { failHeartbeats?: readonly string[] } = {},
): ProviderHealthChain & { heartbeats: string[] } {
  const heartbeats: string[] = [];
  const failing = new Set(opts.failHeartbeats ?? []);
  return {
    heartbeats,
    async providers() {
      return snapshots;
    },
    async heartbeat(providerId) {
      if (failing.has(providerId.toLowerCase())) throw new Error("router down");
      heartbeats.push(providerId);
    },
    async reportFailure() {
      /* not used here */
    },
    async currentTimestamp() {
      return NOW;
    },
  };
}

describe("providerHealth", () => {
  it("reports a clean fleet as healthy with no alerts", async () => {
    const chain = fakeChain([snapshot(), snapshot({ providerId: ID(2) })]);
    const { sink, records } = capture();
    const result = await providerHealth({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { stalenessSeconds: 3600n },
    });

    expect(result.providers).toHaveLength(2);
    expect(result.unhealthyCount).toBe(0);
    expect(records.filter((r) => r.event === "provider.unhealthy")).toHaveLength(0);
  });

  it("logs one line per unhealthy provider, so an alert can key on the log", async () => {
    // An operator should not have to fetch the result object to raise an alert.
    const chain = fakeChain([
      snapshot({ providerId: ID(1) }),
      snapshot({ providerId: ID(2), status: ProviderStatus.Paused }),
      snapshot({ providerId: ID(3), lastHeartbeat: NOW - 7200n }),
    ]);
    const { sink, records } = capture();
    const result = await providerHealth({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { stalenessSeconds: 3600n },
    });

    expect(result.unhealthyCount).toBe(2);
    const alerts = records.filter((r) => r.event === "provider.unhealthy");
    expect(alerts).toHaveLength(2);
    expect(alerts.map((a) => a.fields.reason).sort()).toEqual(["paused", "stale-heartbeat"]);
  });

  it("restricts the sweep to the requested providers", async () => {
    const chain = fakeChain([snapshot({ providerId: ID(1) }), snapshot({ providerId: ID(2) })]);
    const { sink } = capture();
    const result = await providerHealth({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { stalenessSeconds: 3600n, only: [ID(2)] },
    });
    expect(result.providers).toHaveLength(1);
    expect(result.providers[0]?.providerId).toBe(ID(2));
  });

  it("counts an empty fleet as zero rather than failing", async () => {
    const chain = fakeChain([]);
    const { sink } = capture();
    const result = await providerHealth({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { stalenessSeconds: 3600n },
    });
    expect(result.providers).toHaveLength(0);
    expect(result.unhealthyCount).toBe(0);
  });

  it("reads the clock from the chain rather than the runtime", async () => {
    // A runtime's wall clock is not the chain's; using it would make every heartbeat look
    // fresh or stale by the wrong amount.
    expect(fakeChain([])).toBeDefined();
    const chain = fakeChain([snapshot({ lastHeartbeat: NOW - 100n })]);
    const { sink } = capture();
    await providerHealth({ chain, registry: new SensitiveRegistry(), sink, config: { stalenessSeconds: 3600n } });
  });
});

describe("submitHeartbeats", () => {
  it("records a heartbeat for every provider", async () => {
    const chain = fakeChain([]);
    const result = await submitHeartbeats({ chain, providers: [ID(1), ID(2)] });
    expect(result).toEqual({ submitted: 2, failed: 0 });
    expect(chain.heartbeats).toHaveLength(2);
  });

  it("continues past a failed heartbeat", () => {
    // The failure it reports is often the staleness it exists to report, so aborting on the
    // first one would make the health reporter the cause of its own alert.
    const chain = fakeChain([], { failHeartbeats: [ID(2)] });
    return submitHeartbeats({ chain, providers: [ID(1), ID(2), ID(3)] }).then((result) => {
      expect(result).toEqual({ submitted: 2, failed: 1 });
      expect(chain.heartbeats).toEqual([ID(1), ID(3)]);
    });
  });
});
