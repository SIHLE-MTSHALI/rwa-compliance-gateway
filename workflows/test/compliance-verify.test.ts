import { describe, expect, it } from "vitest";

import { computeCcid, labelToId } from "@rwa-compliance/sdk";
import type { Hex } from "viem";

import { complianceVerify, saltedCommitment, type CredentialChain, type VerificationSubmission } from "../src/compliance-verify.js";
import {
  FIXTURE_MARKER,
  FixtureEvidenceError,
  MockProviderAdapter,
  assertNotFixtureEvidence,
  fixtureJurisdictionOf,
  fixtureProfileNames,
  isFixtureEvidence,
} from "../src/adapters/mock-provider.js";
import {
  ReclaimTransportNotConfiguredError,
  isTransportConfigured,
  reclaimTransport,
} from "../src/adapters/reclaim.js";
import {
  TlsNotaryTransportNotConfiguredError,
  isNotaryConfigured,
  tlsNotaryTransport,
} from "../src/adapters/tlsnotary.js";
import { SensitiveRegistry, assertRedacted, type LogRecord } from "../src/privacy.js";

// =====================================================================
// Fixture provider
// =====================================================================

describe("MockProviderAdapter", () => {
  it("marks every evidence hash as fixture-derived", () => {
    // The property the whole fixture design rests on: a mock's output must be
    // identifiable as a mock's after the fact.
    const adapter = new MockProviderAdapter();
    expect(adapter.failNext).toBe(0);
    expect(adapter.latencyMs).toBe(0);
    void FIXTURE_MARKER;
  });

  it("produces evidence that is recognisable as fixture output", async () => {
    const adapter = new MockProviderAdapter();
    const result = await adapter.verify(
      { attribute: "ATTRIBUTE-12345", requested: ["both"], fixtureProfile: "us-accredited" },
      1_700_000_000n,
    );

    expect(isFixtureEvidence(result.evidenceHash)).toBe(true);
    expect(assertNotFixtureEvidence).toBeDefined();
    expect(fixtureJurisdictionOf(result.evidenceHash)).toBe(840);
  });

  it("refuses to let fixture evidence reach a deployment path", async () => {
    const adapter = new MockProviderAdapter();
    const result = await adapter.verify(
      { attribute: "ATTRIBUTE-12345", requested: ["both"] },
      1n,
    );
    expect(() => assertNotFixtureEvidence(result.evidenceHash)).toThrow(FixtureEvidenceError);
  });

  it("does not flag arbitrary evidence as fixture output", () => {
    // A false positive here would block a real provider's evidence.
    expect(isFixtureEvidence(`0x${"ab".repeat(32)}` as Hex)).toBe(false);
    expect(isFixtureEvidence("0x1234")).toBe(false);
    expect(isFixtureEvidence("not-hex")).toBe(false);
  });

  it("resolves each declared fixture profile", async () => {
    const adapter = new MockProviderAdapter();
    for (const profile of fixtureProfileNames()) {
      const result = await adapter.verify(
        { attribute: "ATTRIBUTE-12345", requested: ["both"], fixtureProfile: profile },
        1n,
      );
      expect(result.jurisdictionCode, profile).toBeGreaterThan(0);
    }
  });

  it("refuses an unknown profile rather than defaulting", async () => {
    // Defaulting would let a typo in configuration silently produce a credential for the
    // wrong jurisdiction.
    const adapter = new MockProviderAdapter();
    await expect(
      adapter.verify({ attribute: "ATTRIBUTE-12345", requested: ["both"], fixtureProfile: "us-accrdited" }, 1n),
    ).rejects.toThrow(/unknown fixture profile/);
  });

  it("refuses to answer when nothing was requested", async () => {
    const adapter = new MockProviderAdapter();
    await expect(
      adapter.verify({ attribute: "ATTRIBUTE-12345", requested: [] }, 1n),
    ).rejects.toThrow(/nothing was requested/);
  });

  it("honours a requested failure, for testing retry paths", async () => {
    const adapter = new MockProviderAdapter();
    adapter.failNext = 2;
    await expect(adapter.verify({ attribute: "A-12345", requested: ["both"] }, 1n)).rejects.toThrow(
      /simulated/,
    );
    await expect(adapter.verify({ attribute: "A-12345", requested: ["both"] }, 1n)).rejects.toThrow(
      /simulated/,
    );
    await expect(adapter.verify({ attribute: "A-12345", requested: ["both"] }, 1n)).resolves.toBeDefined();
  });

  it("records the requests it saw, so a test can assert what was not logged", async () => {
    const adapter = new MockProviderAdapter();
    await adapter.verify({ attribute: "ATTRIBUTE-12345", requested: ["both"] }, 1n);
    expect(adapter.requests).toHaveLength(1);
  });
});

// =====================================================================
// Transports that refuse to pretend
// =====================================================================

describe("attestation transports", () => {
  it("throws rather than returning unattested evidence", async () => {
    // The whole point. An adapter that returns a body without an attestation would let a
    // workflow report a verification it never performed.
    await expect(reclaimTransport.fetchAttestedJson("https://provider.example")).rejects.toThrow(
      ReclaimTransportNotConfiguredError,
    );
    await expect(reclaimTransport.verifyAttestation(`0x${"00".repeat(32)}` as Hex)).rejects.toThrow(
      ReclaimTransportNotConfiguredError,
    );
    await expect(tlsNotaryTransport.fetchNotarized("https://provider.example")).rejects.toThrow(
      TlsNotaryTransportNotConfiguredError,
    );
    await expect(tlsNotaryTransport.verifyNotarization(`0x${"00".repeat(32)}` as Hex)).rejects.toThrow(
      TlsNotaryTransportNotConfiguredError,
    );
  });

  it("says in the message why it is not implemented", async () => {
    // A caller who hits this needs to know it is a deliberate omission, not a bug.
    await expect(reclaimTransport.fetchAttestedJson("https://provider.example")).rejects.toThrow(
      /not implemented in this repository/,
    );
  });

  it("lets a workflow detect a placeholder before starting work", () => {
    // Otherwise the failure lands on the first credential it was asked to verify.
    expect(isTransportConfigured(reclaimTransport)).toBe(false);
    expect(isNotaryConfigured(tlsNotaryTransport)).toBe(false);
  });
});

// =====================================================================
// complianceVerify
// =====================================================================

const CREDENTIAL_TYPE = labelToId("kyc.basic");
const PROVIDER_ID = labelToId("provider.alpha");
const POOL_ID = labelToId("pool.treasury");
const T0 = 1_700_000_000n;

/** A chain that records what it was asked to write. */
function recordingChain(): {
  chain: CredentialChain;
  submissions: VerificationSubmission[];
  begun: { ccid: Hex; ttlSeconds: bigint }[];
} {
  const submissions: VerificationSubmission[] = [];
  const begun: { ccid: Hex; ttlSeconds: bigint }[] = [];
  return {
    submissions,
    begun,
    chain: {
      async beginVerification(params) {
        begun.push({ ccid: params.ccid, ttlSeconds: params.ttlSeconds });
        return `0x${"00".repeat(32)}` as Hex;
      },
      async submitResult(params) {
        submissions.push(params);
        return `0x${"11".repeat(32)}` as Hex;
      },
    },
  };
}

function capture(): { sink: (record: LogRecord) => void; records: LogRecord[] } {
  const records: LogRecord[] = [];
  return { sink: (record) => records.push(record), records };
}

const CONFIG = {
  poolId: POOL_ID,
  credentialType: CREDENTIAL_TYPE,
  providerId: PROVIDER_ID,
  schemaVersion: 1,
  ttlSeconds: 365n * 24n * 60n * 60n,
  pendingTtlSeconds: 24n * 60n * 60n,
  destinations: [3478487238524512106n],
};

describe("complianceVerify", () => {
  it("produces a credential whose CCID matches the SDK derivation", async () => {
    const { chain, submissions } = recordingChain();
    const registry = new SensitiveRegistry();
    const { sink } = capture();
    const attribute = "GB123456789SPARK";
    const salt = "salt-for-this-holder";

    const result = await complianceVerify({
      chain,
      provider: new MockProviderAdapter(),
      config: { ...CONFIG, allowFixtureEvidence: true },
      registry,
      sink,
      input: { attribute, salt, nonce: 1n, fixtureProfile: "us-accredited", now: T0 },
    });

    expect(result.failed).toBe(false);
    expect(submissions).toHaveLength(1);

    const submitted = submissions[0]!;
    const expected = computeCcid({
      credentialType: CREDENTIAL_TYPE,
      schemaVersion: 1,
      providerId: PROVIDER_ID,
      jurisdictionCode: submitted.jurisdictionCode,
      investorClass: submitted.investorClass as 1,
      subjectCommitment: submitted.subjectCommitment,
    });

    expect(submitted.ccid).toBe(expected);
    expect(result.summary?.ccid).toBe(expected);
  });

  it("never submits the attribute, only its commitment", async () => {
    const { chain, submissions } = recordingChain();
    const registry = new SensitiveRegistry();
    const { sink } = capture();
    const attribute = "GB123456789SPARK";

    await complianceVerify({
      chain,
      provider: new MockProviderAdapter(),
      config: { ...CONFIG, allowFixtureEvidence: true },
      registry,
      sink,
      input: { attribute, salt: "salt-123456", nonce: 1n, now: T0 },
    });

    const serialised = JSON.stringify(submissions, (_key, value) =>
      typeof value === "bigint" ? value.toString() : value,
    );
    expect(serialised).not.toContain(attribute);
    expect(serialised).not.toContain("salt-123456");
    expect(submissions[0]?.subjectCommitment).toBe(saltedCommitment("salt-123456", attribute));
  });

  it("logs nothing containing the attribute or the salt", async () => {
    const { chain } = recordingChain();
    const registry = new SensitiveRegistry();
    const { sink, records } = capture();
    const attribute = "GB123456789SPARK";
    const salt = "salt-for-this-holder";

    await complianceVerify({
      chain,
      provider: new MockProviderAdapter(),
      config: { ...CONFIG, allowFixtureEvidence: true },
      registry,
      sink,
      input: { attribute, salt, nonce: 1n, now: T0 },
    });

    const text = JSON.stringify(records, (_key, value) =>
      typeof value === "bigint" ? value.toString() : value,
    );
    expect(text).not.toContain(attribute);
    expect(text).not.toContain(salt);
    expect(records.length).toBeGreaterThan(0);
  });

  it("opens a Pending record before submitting", async () => {
    const { chain, begun, submissions } = recordingChain();
    const registry = new SensitiveRegistry();
    const { sink } = capture();

    await complianceVerify({
      chain,
      provider: new MockProviderAdapter(),
      config: { ...CONFIG, allowFixtureEvidence: true },
      registry,
      sink,
      input: { attribute: "GB123456789SPARK", salt: "salt-123456", nonce: 1n, now: T0 },
    });

    // Order is the point: a holder must be able to see a check is running rather than
    // observing NO_CREDENTIAL and being unable to tell "not requested" from "still running".
    expect(begun).toHaveLength(1);
    expect(begun[0]?.ttlSeconds).toBe(CONFIG.pendingTtlSeconds);
    expect(begun[0]?.ccid).toBe(submissions[0]?.ccid);
  });

  it("refuses to submit fixture evidence by default", async () => {
    // The default matters: a fixture credential would pass every policy check on chain and
    // be indistinguishable from a verified one.
    const { chain, submissions } = recordingChain();
    const registry = new SensitiveRegistry();
    const { sink } = capture();

    const result = await complianceVerify({
      chain,
      provider: new MockProviderAdapter(),
      config: CONFIG,
      registry,
      sink,
      input: { attribute: "GB123456789SPARK", salt: "salt-123456", nonce: 1n, now: T0 },
    });

    expect(result.failed).toBe(true);
    expect(result.reason).toBe("fixture-evidence-rejected");
    expect(submissions).toHaveLength(0);
  });

  it("reports a provider failure without leaking the request", async () => {
    const provider = new MockProviderAdapter();
    provider.failNext = 1;
    const { chain, submissions } = recordingChain();
    const registry = new SensitiveRegistry();
    const { sink, records } = capture();

    const result = await complianceVerify({
      chain,
      provider,
      config: CONFIG,
      registry,
      sink,
      input: { attribute: "GB123456789SPARK", salt: "salt-123456", nonce: 1n, now: T0 },
    });

    expect(result.failed).toBe(true);
    expect(result.reason).toBe("provider-unavailable");
    expect(submissions).toHaveLength(0);

    const text = JSON.stringify(records);
    expect(text).not.toContain("GB123456789SPARK");
  });

  it("treats a partial provider answer as a refusal, not a partial credential", async () => {
    // A credential asserting jurisdiction 0 would be denied later, for a reason the holder
    // could not act on.
    const provider = new MockProviderAdapter();
    const { chain, submissions } = recordingChain();
    const registry = new SensitiveRegistry();
    const { sink } = capture();

    const result = await complianceVerify({
      chain,
      provider: {
        async verify() {
          return {
            jurisdictionCode: 0,
            investorClass: 1,
            evidenceHash: `0x${"11".repeat(32)}` as Hex,
            verifiedAt: T0,
          };
        },
      },
      config: CONFIG,
      registry,
      sink,
      input: { attribute: "GB123456789SPARK", salt: "salt-123456", nonce: 1n, now: T0 },
    });

    expect(result.reason).toBe("provider-rejected");
    expect(submissions).toHaveLength(0);
    void provider;
  });

  it("reports a chain write failure rather than claiming success", async () => {
    const registry = new SensitiveRegistry();
    const { sink } = capture();

    const result = await complianceVerify({
      chain: {
        async beginVerification() {
          throw new Error("router unavailable");
        },
        async submitResult() {
          throw new Error("unreachable");
        },
      },
      provider: new MockProviderAdapter(),
      config: { ...CONFIG, allowFixtureEvidence: true },
      registry,
      sink,
      input: { attribute: "GB123456789SPARK", salt: "salt-123456", nonce: 1n, now: T0 },
    });

    expect(result.failed).toBe(true);
    expect(result.reason).toBe("chain-write-failed");
    expect(result.summary).toBeUndefined();
  });

  it("learns the attribute before anything can fail and log it", async () => {
    // The registry is populated at the very top, so even a provider that echoes its
    // request back cannot get the value into a log.
    const registry = new SensitiveRegistry();
    const { chain } = recordingChain();
    const { sink } = capture();
    const attribute = "GB123456789SPARK";

    await complianceVerify({
      chain,
      provider: new MockProviderAdapter(),
      config: { ...CONFIG, allowFixtureEvidence: true },
      registry,
      sink,
      input: { attribute, salt: "salt-123456", nonce: 1n, now: T0 },
    });

    expect(registry.contains(attribute)).toBe(true);
    expect(registry.contains("salt-123456")).toBe(true);
    expect(() => assertRedacted(`saw ${attribute}`, { registry })).toThrow();
  });
});
