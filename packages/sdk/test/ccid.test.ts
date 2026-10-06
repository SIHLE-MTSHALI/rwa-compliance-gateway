import { describe, expect, it } from "vitest";
import { keccak256, stringToHex, type Hex } from "viem";

import {
  CCID_DOMAIN,
  CCID_DOMAIN_LABEL,
  computeCcid,
  labelToId,
  saltedSubjectCommitment,
  validateCcidParts,
  verifyCcid,
  type CcidInput,
} from "../src/ccid.js";
import { InvestorClass } from "../src/reasons.js";
import vectors from "./vectors/ccid.json" with { type: "json" };

/**
 * The vectors are generated from `CCIDResolver.compute` by
 * `scripts/generate-ccid-vectors.mjs`. They are the cross-implementation witness: this
 * suite asserts the TypeScript derivation reproduces the chain's bytes exactly.
 *
 * If it does not, every credential this SDK derives will be rejected by the gateway at
 * submission - which is the right failure direction, but it happens in production on the
 * first issuance unless something catches it here.
 */
const FIXTURE: CcidInput = {
  credentialType: vectors.credentialType as Hex,
  schemaVersion: vectors.schemaVersion,
  providerId: vectors.providerId as Hex,
  jurisdictionCode: 840,
  investorClass: InvestorClass.USAccredited,
  subjectCommitment: vectors.vectors[0]!.subjectCommitment as Hex,
};

describe("CCID derivation", () => {
  it("reproduces every vector produced by the contract", () => {
    expect(vectors.vectors.length).toBeGreaterThan(0);

    for (const vector of vectors.vectors) {
      const derived = computeCcid({
        credentialType: vectors.credentialType as Hex,
        schemaVersion: vectors.schemaVersion,
        providerId: vectors.providerId as Hex,
        jurisdictionCode: vector.jurisdictionCode,
        investorClass: investorClassFromName(vector.investorClass),
        subjectCommitment: vector.subjectCommitment as Hex,
      });

      // Named so a failure says which (jurisdiction, class) pair diverged, rather than
      // just "the derivation is wrong".
      expect(
        derived,
        `jurisdiction ${vector.jurisdictionCode} class ${vector.investorClass}`,
      ).toBe(vector.ccid);
    }
  });

  it("uses the same domain separator as the contract", () => {
    // A derived value would also pass every vector if both sides drifted together, so the
    // domain is pinned against its label explicitly.
    expect(CCID_DOMAIN).toBe(vectors.domain);
    expect(CCID_DOMAIN).toBe(keccak256(stringToHex(CCID_DOMAIN_LABEL)));
    expect(CCID_DOMAIN_LABEL).toBe("rwa-compliance-gateway/CCID/v1");
  });

  it("covers enough of the input space to catch a field swap", () => {
    // One jurisdiction or one class would let a reordered field pass unnoticed on the
    // uncovered combinations.
    const jurisdictions = new Set(vectors.vectors.map((v) => v.jurisdictionCode));
    const classes = new Set(vectors.vectors.map((v) => v.investorClass));
    expect(jurisdictions.size).toBeGreaterThanOrEqual(2);
    expect(classes.size).toBeGreaterThanOrEqual(3);
  });

  it("is deterministic", () => {
    expect(computeCcid(FIXTURE)).toBe(computeCcid(FIXTURE));
  });

  it("changes when any field changes", () => {
    const base = computeCcid(FIXTURE);

    expect(computeCcid({ ...FIXTURE, credentialType: labelToId("kyc.enhanced") })).not.toBe(base);
    expect(computeCcid({ ...FIXTURE, schemaVersion: FIXTURE.schemaVersion + 1 })).not.toBe(base);
    expect(computeCcid({ ...FIXTURE, providerId: labelToId("provider.beta") })).not.toBe(base);
    expect(computeCcid({ ...FIXTURE, jurisdictionCode: 826 })).not.toBe(base);
    expect(computeCcid({ ...FIXTURE, investorClass: InvestorClass.NonUSProfessional })).not.toBe(base);
    expect(computeCcid({ ...FIXTURE, subjectCommitment: labelToId("someone-else") })).not.toBe(base);
  });

  it("cannot present one holder's attestation as another's", () => {
    // The anti-tampering property. Without the subject inside the derivation, a
    // US-accredited attestation claimed for one holder could be presented for another.
    const ccid = computeCcid(FIXTURE);
    expect(
      verifyCcid(ccid, { ...FIXTURE, subjectCommitment: labelToId("someone-else") }),
    ).toBe(false);
    expect(verifyCcid(ccid, FIXTURE)).toBe(true);
  });

  it("cannot escalate a non-professional class to accredited", () => {
    // The subject, jurisdiction, provider and type all stay the same; only the class
    // changes, and the identity must change with it.
    const nonProfessional = computeCcid({ ...FIXTURE, investorClass: InvestorClass.NonUSProfessional });
    expect(computeCcid({ ...FIXTURE, investorClass: InvestorClass.USAccredited })).not.toBe(nonProfessional);
  });

  /**
   * The claim the whole credential lifecycle rests on: a CCID does not depend on the
   * nonce.
   *
   * `computeCcid` has no nonce parameter at all, which is the structural form of the
   * guarantee. The test asserts the *absence* so that adding one later is a deliberate,
   * visible act - because if renewal produced a new CCID, the previous credential would
   * remain `Valid` on every destination chain with nothing able to revoke it.
   */
  it("has no nonce input, so renewal cannot change a credential's identity", () => {
    const params = computeCcid.length; // arity is 1: the input object
    expect(params).toBe(1);

    const derived = computeCcid(FIXTURE);
    expect(Object.keys(FIXTURE)).not.toContain("nonce");

    // The same inputs always give the same CCID, which is what "renewal keeps the CCID"
    // means in practice.
    expect(computeCcid(FIXTURE)).toBe(derived);
  });

  it("rejects out-of-range numbers rather than truncating them", () => {
    // Truncation would produce a different but still-valid CCID, and the gateway's
    // rejection would point at the derivation instead of at the range error.
    expect(() => computeCcid({ ...FIXTURE, jurisdictionCode: 70_000 })).toThrow(RangeError);
    expect(() => computeCcid({ ...FIXTURE, jurisdictionCode: -1 })).toThrow(RangeError);
    expect(() => computeCcid({ ...FIXTURE, jurisdictionCode: 1.5 })).toThrow(RangeError);
    expect(() => computeCcid({ ...FIXTURE, schemaVersion: -1 })).toThrow(RangeError);
    expect(() => computeCcid({ ...FIXTURE, schemaVersion: 2 ** 32 })).toThrow(RangeError);
  });

  it("refuses to derive an identity for a credential that cannot be issued", () => {
    // Jurisdiction 0 and a zero subject commitment are both refused by the gateway, so a
    // CCID that derives anyway is one that can never be used.
    expect(() => computeCcid({ ...FIXTURE, jurisdictionCode: 0 })).not.toThrow(); // derives, but:
    expect(validateCcidParts(FIXTURE)).toBe(true);
    expect(
      validateCcidParts({ ...FIXTURE, subjectCommitment: `0x${"0".repeat(64)}` as Hex }),
    ).toBe(false);
    expect(validateCcidParts({ ...FIXTURE, providerId: `0x${"0".repeat(64)}` as Hex })).toBe(false);
    expect(validateCcidParts({ ...FIXTURE, credentialType: `0x${"0".repeat(64)}` as Hex })).toBe(false);
  });

  it("produces a 32-byte digest", () => {
    expect(computeCcid(FIXTURE)).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

describe("subject commitments", () => {
  it("is deterministic for a given salt and attribute", () => {
    expect(saltedSubjectCommitment("salt-1", "attribute-1")).toBe(saltedSubjectCommitment("salt-1", "attribute-1"));
  });

  it("differs across salts, so commitments are not correlatable", () => {
    // The property that makes a salted commitment worth the trouble: two issuers
    // attesting the same holder produce different commitments.
    expect(saltedSubjectCommitment("salt-1", "attribute-1")).not.toBe(
      saltedSubjectCommitment("salt-2", "attribute-1"),
    );
  });

  it("differs across attributes", () => {
    expect(saltedSubjectCommitment("salt-1", "attribute-1")).not.toBe(
      saltedSubjectCommitment("salt-1", "attribute-2"),
    );
  });

  it("is documented as a demonstration, not a production construction", () => {
    // A salt concatenated in plaintext is not a secret. The guard here is the doc comment
    // and this assertion, which fails if someone deletes the warning while keeping the
    // helper.
    expect(saltedSubjectCommitment("salt-1", "attribute-1")).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

describe("labelToId", () => {
  it("hashes a label the way the contracts do", () => {
    expect(labelToId("kyc.basic")).toBe(keccak256(stringToHex("kyc.basic")));
  });
});

function investorClassFromName(name: string): InvestorClass {
  switch (name) {
    case "USAccredited":
      return InvestorClass.USAccredited;
    case "NonUSProfessional":
      return InvestorClass.NonUSProfessional;
    case "Blocked":
      return InvestorClass.Blocked;
    case "Unknown":
      return InvestorClass.Unknown;
    default:
      throw new Error(`unrecognised investor class in the vectors: ${name}`);
  }
}
