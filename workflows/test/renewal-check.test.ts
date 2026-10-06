import { describe, expect, it } from "vitest";
import type { Hex } from "viem";

import {
  renewalCheck,
  renewalWouldChangeAnything,
  shouldAttemptRenewal,
  type ExpiringCredential,
  type ExpiryChain,
} from "../src/renewal-check.js";
import { SensitiveRegistry, type LogRecord } from "../src/privacy.js";

const HEX = (n: number): Hex => `0x${n.toString(16).padStart(64, "0")}` as Hex;
const NOW = 1_700_000_000n;
const DAY = 24n * 60n * 60n;

function capture(): { sink: (record: LogRecord) => void; records: LogRecord[] } {
  const records: LogRecord[] = [];
  return { sink: (record) => records.push(record), records };
}

function credential(over: Partial<ExpiringCredential> = {}): ExpiringCredential {
  return {
    ccid: HEX(1),
    credentialType: HEX(2),
    providerId: HEX(3),
    jurisdictionCode: 840,
    investorClass: 1,
    issuedAt: NOW - 300n * DAY,
    expiresAt: NOW + 60n * DAY,
    nonce: 1n,
    renewals: 0,
    ...over,
  };
}

function fakeChain(
  found: readonly ExpiringCredential[],
  now: bigint = NOW,
): ExpiryChain & { lookaheads: bigint[] } {
  const lookaheads: bigint[] = [];
  return {
    lookaheads,
    async findExpiring(withinSeconds) {
      lookaheads.push(withinSeconds);
      return found.filter((c) => c.expiresAt - now <= withinSeconds);
    },
    async currentTimestamp() {
      return now;
    },
  };
}

describe("renewalCheck", () => {
  it("returns nothing for an empty fleet", async () => {
    const chain = fakeChain([]);
    const { sink } = capture();
    const result = await renewalCheck({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { limit: 100 },
    });
    expect(result.candidates).toHaveLength(0);
    expect(result.scanned).toBe(0);
  });

  it("finds a credential inside the lookahead window", async () => {
    const chain = fakeChain([credential({ expiresAt: NOW + 20n * DAY })]);
    const { sink } = capture();
    const result = await renewalCheck({ chain, registry: new SensitiveRegistry(), sink, config: { limit: 100 } });

    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]?.secondsRemaining).toBe(20n * DAY);
  });

  it("excludes a credential beyond the lookahead window", async () => {
    // A year-long credential renewed on a 30-day horizon would put every holder in the
    // queue permanently, which is how a renewal list stops being read.
    const chain = fakeChain([credential({ expiresAt: NOW + 365n * DAY })]);
    const { sink } = capture();
    const result = await renewalCheck({ chain, registry: new SensitiveRegistry(), sink, config: { limit: 100 } });
    expect(result.candidates).toHaveLength(0);
  });

  it("sorts by how soon the credential expires", async () => {
    // The holder closest to losing access needs telling first.
    const chain = fakeChain([
      credential({ ccid: HEX(1), expiresAt: NOW + 20n * DAY }),
      credential({ ccid: HEX(2), expiresAt: NOW + 5n * DAY }),
      credential({ ccid: HEX(3), expiresAt: NOW + 12n * DAY }),
    ]);
    const { sink } = capture();
    const result = await renewalCheck({ chain, registry: new SensitiveRegistry(), sink, config: { limit: 100 } });

    expect(result.candidates.map((c) => c.ccid)).toEqual([HEX(2), HEX(3), HEX(1)]);
  });

  it("marks the urgent ones so a holder can be told now", async () => {
    // Both credentials sit inside the default 30-day lookahead, so the only thing that
    // differs between them is the urgency threshold. A fixture outside the window would be
    // filtered by the chain before this rule ever ran.
    const chain = fakeChain([
      credential({ ccid: HEX(1), expiresAt: NOW + 2n * DAY }),
      credential({ ccid: HEX(2), expiresAt: NOW + 20n * DAY }),
    ]);
    const { sink } = capture();
    const result = await renewalCheck({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { limit: 100 },
      urgentSeconds: 7n * DAY,
    });

    expect(result.candidates.map((c) => c.urgent)).toEqual([true, false]);
  });

  it("skips a credential that has exhausted its renewal budget", async () => {
    // A holder who re-verifies every cycle is usually not going to pass on the next one,
    // and an unbounded retry list buries the credentials that will renew.
    const chain = fakeChain([credential({ renewals: 5, expiresAt: NOW + 10n * DAY })]);
    const { sink } = capture();
    const result = await renewalCheck({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { limit: 100, maxRenewals: 3 },
    });

    expect(result.candidates).toHaveLength(0);
    expect(result.skippedExhausted).toBe(1);
    expect(result.scanned).toBe(1);
  });

  it("reports an already-lapsed credential without treating it as a candidate", async () => {
    // The registry denies it with no keeper involved - a sweeper that protected expiry
    // would fail open the moment it stalled. So there is nothing to nudge about.
    const chain = fakeChain([credential({ expiresAt: NOW - DAY })], NOW);
    const { sink } = capture();
    const result = await renewalCheck({ chain, registry: new SensitiveRegistry(), sink, config: { limit: 100 } });

    expect(result.candidates).toHaveLength(0);
  });

  it("reads the clock from the chain rather than the runtime", async () => {
    // Using the runtime's wall clock would report more time remaining than there is, which
    // is the direction that fails open.
    const chain = fakeChain([credential({ expiresAt: NOW + 5n * DAY })], NOW);
    const { sink } = capture();
    const result = await renewalCheck({ chain, registry: new SensitiveRegistry(), sink, config: { limit: 100 } });
    expect(result.now).toBe(NOW);
    expect(result.candidates[0]?.secondsRemaining).toBe(5n * DAY);
  });

  it("logs a completion line with counts", async () => {
    const chain = fakeChain([credential({ ccid: HEX(1), expiresAt: NOW + 2n * DAY })]);
    const { sink, records } = capture();
    await renewalCheck({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { limit: 100 },
      urgentSeconds: 7n * DAY,
    });

    const completion = records.find((r) => r.event === "renewal.check_completed");
    expect(completion?.fields.scanned).toBe(1);
    expect(completion?.fields.candidates).toBe(1);
    expect(completion?.fields.urgent).toBe(1);
  });

  it("passes the configured lookahead to the chain", async () => {
    const chain = fakeChain([]);
    const { sink } = capture();
    await renewalCheck({
      chain,
      registry: new SensitiveRegistry(),
      sink,
      config: { limit: 100, lookaheadSeconds: 7n * DAY },
    });
    expect(chain.lookaheads).toEqual([7n * DAY]);
  });
});

describe("shouldAttemptRenewal", () => {
  const OK = { now: NOW, maxRenewals: 3, providerAvailable: true };

  it("attempts a renewal for a healthy credential", () => {
    expect(shouldAttemptRenewal({ renewals: 0, expiresAt: NOW + DAY }, OK)).toEqual({ attempt: true });
  });

  it("refuses when the provider is unavailable", () => {
    // A renewal needs a fresh attestation; attempting without one produces a failed
    // transaction per credential for no chance of success.
    expect(
      shouldAttemptRenewal({ renewals: 0, expiresAt: NOW + DAY }, { ...OK, providerAvailable: false }),
    ).toEqual({ attempt: false, reason: "provider-unavailable" });
  });

  it("checks the provider before anything else", () => {
    // A credential that is both expired and blocked by an unavailable provider should
    // report the provider, because that is the condition an operator can act on.
    expect(
      shouldAttemptRenewal({ renewals: 9, expiresAt: NOW - DAY }, { ...OK, providerAvailable: false }),
    ).toEqual({ attempt: false, reason: "provider-unavailable" });
  });

  it("refuses an already-expired credential", () => {
    expect(shouldAttemptRenewal({ renewals: 0, expiresAt: NOW }, OK)).toEqual({
      attempt: false,
      reason: "already-expired",
    });
  });

  it("refuses at the renewal budget boundary", () => {
    expect(shouldAttemptRenewal({ renewals: 3, expiresAt: NOW + DAY }, OK)).toEqual({
      attempt: false,
      reason: "renewal-budget-exhausted",
    });
    expect(shouldAttemptRenewal({ renewals: 2, expiresAt: NOW + DAY }, OK)).toEqual({ attempt: true });
  });
});

describe("renewalWouldChangeAnything", () => {
  const previous = { expiresAt: NOW + DAY, jurisdictionCode: 840, investorClass: 1 };

  it("sees a later expiry as a change", () => {
    expect(
      renewalWouldChangeAnything(previous, { expiresAt: NOW + 2n * DAY, jurisdictionCode: 840, investorClass: 1 }),
    ).toBe(true);
  });

  it("sees a re-classification as a change", () => {
    // The holder's investor class changed. Submitting nothing would leave the old class in
    // force for another term, which is the outcome a compliance pool must not allow.
    expect(
      renewalWouldChangeAnything(previous, { expiresAt: NOW + DAY, jurisdictionCode: 840, investorClass: 2 }),
    ).toBe(true);
  });

  it("sees a jurisdiction change as a change", () => {
    expect(
      renewalWouldChangeAnything(previous, { expiresAt: NOW + DAY, jurisdictionCode: 826, investorClass: 1 }),
    ).toBe(true);
  });

  it("sees an identical result as no change", () => {
    // A renewal that would not change anything should not be submitted: the gateway would
    // reject it, and a failed transaction costs the holder gas for nothing.
    expect(
      renewalWouldChangeAnything(previous, { expiresAt: NOW + DAY, jurisdictionCode: 840, investorClass: 1 }),
    ).toBe(false);
  });

  it("treats a shorter expiry as a change", () => {
    // The case worth being explicit about. If a provider decides a credential should now
    // lapse sooner, submitting nothing would leave the longer - more permissive - expiry in
    // force for another term. The shorter term is the new information.
    expect(
      renewalWouldChangeAnything(previous, { expiresAt: NOW - DAY, jurisdictionCode: 840, investorClass: 1 }),
    ).toBe(true);
  });
});
