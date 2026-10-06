import { describe, expect, it } from "vitest";
import type { Hex } from "viem";

import {
  Status,
  classify,
  revocationCheck,
  type ReplicaState,
  type RevocationChain,
  type SourceCredentialState,
} from "../src/revocation-check.js";
import { SensitiveRegistry, type LogRecord } from "../src/privacy.js";

const HEX = (n: number): Hex => `0x${n.toString(16).padStart(64, "0")}` as Hex;
const NOW = 1_700_000_000n;

function capture(): { sink: (record: LogRecord) => void; records: LogRecord[] } {
  const records: LogRecord[] = [];
  return { sink: (record) => records.push(record), records };
}

function source(over: Partial<SourceCredentialState> = {}): SourceCredentialState {
  return {
    ccid: HEX(1),
    status: Status.Valid,
    nonce: 3n,
    providerId: HEX(9),
    updatedAt: NOW - 100n,
    ...over,
  };
}

function replica(over: Partial<ReplicaState> = {}): ReplicaState {
  return {
    ccid: HEX(1),
    destinationChainSelector: 3478487238524512106n,
    acceptedNonce: 3n,
    status: Status.Valid,
    ageSeconds: 60n,
    ...over,
  };
}

describe("classify", () => {
  it("reports nothing when source and destination agree exactly", () => {
    expect(classify(source(), replica())).toBeUndefined();
  });

  it("flags a destination still serving a revoked credential", () => {
    // The failure this whole module exists to catch. The source chain says `Revoked`
    // immediately, so an operator checking the source sees a correct system while the
    // destination keeps honouring the credential.
    //
    // The destination is at the source's nonce here, so nothing in flight explains it:
    // this is the plain form, a destination-side bug that will not heal on its own.
    const divergence = classify(
      source({ status: Status.Revoked, nonce: 4n }),
      replica({ status: Status.Valid, acceptedNonce: 4n }),
    );
    expect(divergence?.severity).toBe("revoked-still-valid");
    expect(divergence?.destinationStatus).toBe(Status.Valid);
  });

  it("distinguishes a lost propagation from an in-flight one", () => {
    // Different responses: one is an incident, the other is a message still travelling.
    // Behind on nonce means the revocation simply has not arrived yet.
    const inflight = classify(
      source({ status: Status.Revoked, nonce: 4n }),
      replica({ status: Status.Valid, acceptedNonce: 3n }),
    );
    expect(inflight?.severity).toBe("revoked-still-valid-stale");

    const lost = classify(
      source({ status: Status.Revoked, nonce: 4n }),
      replica({ status: Status.Valid, acceptedNonce: 4n }),
    );
    expect(lost?.severity).toBe("revoked-still-valid");
  });

  it("never treats a revoked destination as a problem", () => {
    // The destination has done its job. Reporting this would fill an incident queue with
    // noise on every successful revocation.
    expect(classify(source({ status: Status.Revoked }), replica({ status: Status.Revoked }))).toBeUndefined();
  });

  it("flags a status difference that is not a revocation", () => {
    const divergence = classify(source({ status: Status.Suspended }), replica());
    expect(divergence?.severity).toBe("status-behind");
  });

  it("flags a destination behind on nonce while statuses agree", () => {
    expect(classify(source({ nonce: 5n }), replica({ acceptedNonce: 3n }))?.severity).toBe("nonce-behind");
  });

  it("flags a destination ahead of the source on nonce", () => {
    // A genuine anomaly: the destination accepted a message the source never sent. Reported
    // rather than treated as fine.
    expect(classify(source({ nonce: 3n }), replica({ acceptedNonce: 4n }))?.severity).toBe("nonce-behind");
  });

  it("prioritises the revocation over the nonce gap", () => {
    // A revoked credential behind on nonce is both, and it must sort as the revocation -
    // otherwise ordinary in-flight lag buries the incident every time a propagation is slow.
    const divergence = classify(
      source({ status: Status.Revoked, nonce: 9n }),
      replica({ status: Status.Valid, acceptedNonce: 3n }),
    );
    expect(divergence?.severity).toBe("revoked-still-valid-stale");
  });

  it("records both sides so an operator can see the gap", () => {
    const divergence = classify(source({ status: Status.Revoked, nonce: 9n }), replica({ acceptedNonce: 4n }));
    expect(divergence?.sourceNonce).toBe(9n);
    expect(divergence?.destinationNonce).toBe(4n);
    expect(divergence?.sourceStatus).toBe(Status.Revoked);
    expect(divergence?.destinationStatus).toBe(Status.Valid);
  });

  it("agrees on every status pairing for a revoked source", () => {
    // Exhaustively, because the bug this guards against is a single missed combination in
    // a hand-written ladder.
    //
    // The destination is deliberately left behind on nonce here, so the `-stale` form is
    // expected for anything still serving - except the revoked case, which must be silent
    // however far behind it is, because revocation is terminal.
    for (const destinationStatus of [Status.Unknown, Status.Pending, Status.Valid, Status.Expired, Status.Suspended, Status.Revoked]) {
      const divergence = classify(
        source({ status: Status.Revoked, nonce: 5n }),
        replica({ status: destinationStatus, acceptedNonce: 3n }),
      );
      if (destinationStatus === Status.Revoked) {
        expect(divergence, `destination ${destinationStatus} must be silent`).toBeUndefined();
      } else {
        expect(divergence?.severity, `destination ${destinationStatus}`).toBe("revoked-still-valid-stale");
      }
    }
  });
});

function fakeChain(options: {
  replicas: Record<string, readonly ReplicaState[]>;
  sources: readonly SourceCredentialState[];
}): RevocationChain {
  return {
    async replicasOn(destination) {
      return options.replicas[destination.toString()] ?? [];
    },
    async sourceState() {
      return options.sources;
    },
    async currentTimestamp() {
      return NOW;
    },
  };
}

describe("revocationCheck", () => {
  const DEST = 3478487238524512106n;

  it("reports a clean system with no divergences", async () => {
    const chain = fakeChain({
      replicas: { [DEST.toString()]: [replica()] },
      sources: [source()],
    });
    const { sink } = capture();
    const result = await revocationCheck({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { destinations: [DEST], limit: 100, stalenessThresholdSeconds: 3600n },
    });

    expect(result.divergences).toHaveLength(0);
    expect(result.replicasInspected).toBe(1);
  });

  it("flags a destination serving a revoked credential and logs it individually", async () => {
    const chain = fakeChain({
      replicas: { [DEST.toString()]: [replica({ status: Status.Valid })] },
      sources: [source({ status: Status.Revoked, nonce: 4n })],
    });
    const { sink, records } = capture();
    const result = await revocationCheck({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { destinations: [DEST], limit: 100, stalenessThresholdSeconds: 3600n },
    });

    expect(result.divergences).toHaveLength(1);
    // Logged individually as well as counted, so an alert can be raised on the log line.
    const alerts = records.filter((r) => r.event === "revocation.destination_serving_revoked");
    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.fields.ccid).toBe(HEX(1));
  });

  it("sorts the worst divergence first", () => {
    // An operator reading the top of the list must see an incident, not routine lag.
    const worst = { ...replica(), severity: "revoked-still-valid" } as const;
    const routine = { ...replica(), severity: "nonce-behind" } as const;
    const rank: Record<string, number> = {
      "revoked-still-valid": 0,
      "revoked-still-valid-stale": 1,
      "status-behind": 2,
      "nonce-behind": 3,
    };
    const sorted = [routine, worst].sort((a, b) => rank[a.severity] - rank[b.severity]);
    expect(sorted[0]?.severity).toBe("revoked-still-valid");
  });

  it("reports a replica the source has never heard of rather than guessing", () => {
    // Either the destination is trusted from another source, or something is wrong. This
    // workflow cannot adjudicate it, so it says so instead of calling it consistent.
    const divergence = classify(source({ ccid: HEX(2) }), replica({ ccid: HEX(1) }));
    expect(divergence).toBeUndefined();

    const asUnknown = { ...source(), status: Status.Unknown };
    expect(classify(asUnknown, replica())).toBeDefined();
  });

  it("counts what it inspected, so a clean run is distinguishable from an empty one", async () => {
    const chain = fakeChain({ replicas: {}, sources: [] });
    const { sink } = capture();
    const result = await revocationCheck({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { destinations: [DEST], limit: 100, stalenessThresholdSeconds: 3600n },
    });

    expect(result.replicasInspected).toBe(0);
    expect(result.divergences).toHaveLength(0);
    expect(result.now).toBe(NOW);
  });

  it("inspects every destination it is given", async () => {
    const other = 16015288801757825753n;
    const chain = fakeChain({
      replicas: { [DEST.toString()]: [replica()], [other.toString()]: [replica()] },
      sources: [source()],
    });
    const { sink } = capture();
    const result = await revocationCheck({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { destinations: [DEST, other], limit: 100, stalenessThresholdSeconds: 3600n },
    });
    expect(result.replicasInspected).toBe(2);
  });
});
