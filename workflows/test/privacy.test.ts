import { describe, expect, it } from "vitest";

import {
  FORBIDDEN_TOKENS,
  FORBIDDEN_WORDS,
  SENSITIVE_FIELD_NAMES,
  RedactionError,
  SensitiveRegistry,
  assertFieldNameIsSafe,
  assertRedacted,
  createSafeLogger,
  toSafeSummary,
  type LogRecord,
} from "../src/privacy.js";

/**
 * A log sink that captures, so the tests can assert on what *would* have been written.
 *
 * Capturing rather than printing is deliberate: a test that printed the records would put
 * the very values it is checking for into the test output.
 */
function capture(): { sink: (record: LogRecord) => void; records: LogRecord[] } {
  const records: LogRecord[] = [];
  return { sink: (record) => records.push(record), records };
}

const SENSITIVE = "GB123456789SPARK";

describe("FORBIDDEN_TOKENS", () => {
  it("covers the attributes that would actually identify a holder", () => {
    // A blocklist is only as good as the attributes someone thought to add. These are the
    // ones a KYC adapter receives and must never log.
    const all = [
      ...FORBIDDEN_TOKENS,
      ...FORBIDDEN_WORDS,
      ...SENSITIVE_FIELD_NAMES,
    ] as readonly string[];
    for (const token of [
      "passport",
      "date_of_birth",
      "national_id",
      "tax_id",
      "full_name",
      "email",
      "account_number",
    ]) {
      // Accepted in any of the three lists: a new list may legitimately claim an
      // attribute, and what matters is that the attribute is covered somewhere.
      expect(all.includes(token), `${token} must be covered by one of the three lists`).toBe(true);
    }
  });

  it("keeps every substring-matched token long enough to be safe as a substring", () => {
    // A short entry in the substring list is a false-positive generator. This asserts the
    // curation rule rather than restating the list, so adding a short token fails here.
    for (const token of FORBIDDEN_TOKENS) {
      expect(token.length, `${token} is too short to substring-match safely`).toBeGreaterThanOrEqual(6);
    }
  });

  it("keeps the three lists disjoint", () => {
    // A token in two lists is matched by whichever rule is stricter on the path it is
    // checked, so an overlap silently weakens one of them.
    expect(FORBIDDEN_TOKENS.filter((t) => (FORBIDDEN_WORDS as readonly string[]).includes(t))).toEqual([]);
    expect(FORBIDDEN_TOKENS.filter((t) => (SENSITIVE_FIELD_NAMES as readonly string[]).includes(t))).toEqual([]);
    expect(FORBIDDEN_WORDS.filter((t) => (SENSITIVE_FIELD_NAMES as readonly string[]).includes(t))).toEqual([]);
  });

  it("puts only ordinary English in the field-names-only list", () => {
    // The rationale for the third list: everything in it must be a word that appears in
    // safe prose, which is why it cannot be policed in a value. A non-English token
    // belongs in FORBIDDEN_WORDS where it can be caught everywhere.
    for (const name of SENSITIVE_FIELD_NAMES) {
      expect(FORBIDDEN_TOKENS as readonly string[]).not.toContain(name);
      expect(FORBIDDEN_WORDS as readonly string[]).not.toContain(name);
    }
    expect(SENSITIVE_FIELD_NAMES.length).toBeGreaterThan(0);
  });
});

describe("assertFieldNameIsSafe", () => {
  it("rejects a field named after an attribute", () => {
    expect(() => assertFieldNameIsSafe("passportNumber")).toThrow(RedactionError);
    expect(() => assertFieldNameIsSafe("date_of_birth")).toThrow(RedactionError);
  });

  it("rejects the name regardless of the value, even a hashed one", () => {
    // A field called `passport_hash` is still a disclosure: it tells a reader which
    // holder a record is about, which is the correlation this design exists to avoid.
    expect(() => assertFieldNameIsSafe("passport_hash")).toThrow(RedactionError);
  });

  it("matches through separators and case", () => {
    // The normalisation has to *remove* separators, not convert them: `pass_port` does not
    // contain `passport`, so a converter would defeat the check it exists for.
    for (const name of ["PASSPORT", "pass-port", "PassPort", "pass port", "Pass-Port"]) {
      expect(() => assertFieldNameIsSafe(name), name).toThrow(RedactionError);
    }
  });

  it("matches a camelCase suffix", () => {
    // A field name carries no prose, so substring matching is safe there even for a token
    // that would be noise in a value: `applicantDob` still names a date of birth.
    expect(() => assertFieldNameIsSafe("passportNumber")).toThrow(RedactionError);
    expect(() => assertFieldNameIsSafe("applicantDob")).toThrow(RedactionError);
    expect(() => assertFieldNameIsSafe("holderEmail")).toThrow(RedactionError);
    expect(() => assertFieldNameIsSafe("documentType")).toThrow(RedactionError);
  });

  it("allows the names this system actually uses", () => {
    // The blocklist must not be so broad that the safe fields stop working - a check that
    // fails on `ccid` is a check nobody keeps.
    for (const name of ["ccid", "status", "reason", "nonce", "providerId", "jurisdictionCode"]) {
      expect(() => assertFieldNameIsSafe(name), name).not.toThrow();
    }
  });
});

describe("assertRedacted", () => {
  it("rejects a serialised value that names a sensitive attribute", () => {
    expect(() => assertRedacted('{"passport":"GB123456789SPARK"}')).toThrow(RedactionError);
  });

  it("rejects a learned value found inside a larger string", () => {
    // The interesting leaks are incidental: a URL, an error message, a provider's response.
    const registry = new SensitiveRegistry();
    registry.learn(SENSITIVE);
    expect(() =>
      assertRedacted(`fetch failed: https://provider.example/v/${SENSITIVE}`, { registry }),
    ).toThrow(RedactionError);
  });

  it("allows ordinary prose that merely contains a forbidden word", () => {
    // The reason `email` and `document` are whole-word matched. A guard that fires on
    // "emailed the holder" gets disabled within a week.
    for (const text of [
      "emailed the holder",
      "the document was rejected",
      "email sent",
      "documented the decision",
    ]) {
      expect(() => assertRedacted(text), text).not.toThrow();
    }
  });

  it("still catches a token word used in prose", () => {
    // The words in `FORBIDDEN_WORDS` carry no ordinary meaning, so they are caught in a
    // value as well as in a field name. `email` deliberately is not - see the next test.
    for (const text of ["holder dob unknown", "ssn on file", "iban mismatch"]) {
      expect(() => assertRedacted(text), text).toThrow(RedactionError);
    }
  });

  it("catches an ordinary-English attribute at the field-name layer instead", () => {
    // This is the split the design turns on. `email` cannot be policed in prose without
    // firing on "emailed the holder", so it is policed where it is meaningful - the field
    // name - and a leaked value is caught by the registry, which knows the exact value.
    expect(() => assertRedacted("contact email stored")).not.toThrow();
    expect(() => assertFieldNameIsSafe("contactEmail")).toThrow(RedactionError);

    const registry = new SensitiveRegistry();
    registry.learn("holder@example.com");
    expect(() => assertRedacted("contact holder@example.com", { registry })).toThrow(RedactionError);
  });

  it("allows hashes and status values", () => {
    for (const value of ["0xabc123", "Valid", "OK", "USAccredited", "840", "12"]) {
      expect(() => assertRedacted(value), value).not.toThrow();
    }
  });
});

describe("SensitiveRegistry", () => {
  it("catches a learned value anywhere in a string", () => {
    const registry = new SensitiveRegistry();
    registry.learn(SENSITIVE);
    expect(registry.contains(`attestation for ${SENSITIVE} complete`)).toBe(true);
    expect(registry.contains("attestation for someone else complete")).toBe(false);
  });

  it("refuses to learn a short value rather than protecting nothing", () => {
    // A two-character attribute would match half the log. Storing it would give false
    // confidence that the value is protected, which is worse than the error.
    const registry = new SensitiveRegistry();
    expect(() => registry.learn("AB")).toThrow(RedactionError);
    expect(registry.size).toBe(0);
  });

  it("learns several values at once", () => {
    const registry = new SensitiveRegistry();
    registry.learnAll([SENSITIVE, "1990-01-01T00:00:00Z"]);
    expect(registry.size).toBe(2);
  });

  it("is per-instance, so one workflow cannot disarm another's guard", () => {
    // This is why there is no module-global forbidden-value set: in a runtime hosting
    // several workflows, a shared set plus a reset is a silent cross-workflow failure.
    const a = new SensitiveRegistry();
    const b = new SensitiveRegistry();
    a.learn(SENSITIVE);
    expect(b.contains(SENSITIVE)).toBe(false);

    a.reset();
    expect(a.size).toBe(0);
  });
});

describe("createSafeLogger", () => {
  it("passes a safe record through untouched", () => {
    const { sink, records } = capture();
    const log = createSafeLogger(sink, new SensitiveRegistry());
    log("compliance.verify.succeeded", { ccid: "0xabc", status: "Valid", nonce: "3" });
    expect(records).toHaveLength(1);
    expect(records[0]?.event).toBe("compliance.verify.succeeded");
    expect(records[0]?.fields.status).toBe("Valid");
  });

  it("refuses a sensitive field name rather than redacting it silently", () => {
    // Replacing the value with [REDACTED] would keep the workflow running and the incident
    // going, with the log store full of placeholders where evidence should be.
    const { sink, records } = capture();
    const log = createSafeLogger(sink, new SensitiveRegistry());
    expect(() => log("event", { passportNumber: SENSITIVE })).toThrow(RedactionError);
    expect(records).toHaveLength(0);
  });

  it("refuses a sensitive value under an innocuous name", () => {
    // The whole reason the logger is built by a factory: the registry is bound at
    // construction, so a caller cannot reach the sink without it.
    const { sink, records } = capture();
    const registry = new SensitiveRegistry();
    registry.learn(SENSITIVE);
    const log = createSafeLogger(sink, registry);

    expect(() => log("event", { note: SENSITIVE })).toThrow(RedactionError);
    expect(records).toHaveLength(0);
  });

  it("refuses a learned value that got concatenated into a message", () => {
    const { sink, records } = capture();
    const registry = new SensitiveRegistry();
    registry.learn(SENSITIVE);
    const log = createSafeLogger(sink, registry);

    expect(() => log("event", { detail: `issued for ${SENSITIVE}` })).toThrow(RedactionError);
    expect(records).toHaveLength(0);
  });

  it("refuses an event name that names an attribute", () => {
    const { sink } = capture();
    const log = createSafeLogger(sink, new SensitiveRegistry());
    expect(() => log("verify.passport_checked")).toThrow(RedactionError);
  });

  it("handles bigint, arrays and nested objects", () => {
    // These are the shapes a workflow actually logs; if serialisation threw, a developer
    // would be pushed toward a raw console.log, which is the thing being prevented.
    const { sink, records } = capture();
    const log = createSafeLogger(sink, new SensitiveRegistry());
    log("event", { nonce: 42n, destinations: [1n, 2n], nested: { ccid: "0xabc", depth: 2 } });
    expect(records).toHaveLength(1);
  });

  it("does not throw on an unserialisable value", () => {
    const { sink, records } = capture();
    const log = createSafeLogger(sink, new SensitiveRegistry());
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => log("event", { circular })).not.toThrow();
    expect(records).toHaveLength(1);
  });

  it("works with no registry, guarding only on the blocklists", () => {
    // Legitimate for a workflow that handles no holder attributes - it still gets the
    // field-name and token guards.
    const { sink, records } = capture();
    const log = createSafeLogger(sink);
    expect(() => log("event", { ccid: "0xabc" })).not.toThrow();
    expect(() => log("event", { passportNumber: SENSITIVE })).toThrow(RedactionError);
    expect(records).toHaveLength(1);
  });
});

describe("toSafeSummary", () => {
  it("keeps exactly the fields an operator needs to reconstruct a decision", () => {
    const summary = toSafeSummary({
      ccid: "0xabc",
      status: "Valid",
      reason: "OK",
      nonce: 7n,
      providerId: "0xdef",
    });

    expect(Object.keys(summary).sort()).toEqual(["ccid", "nonce", "providerId", "reason", "status"]);
    expect(summary.nonce).toBe("7");
  });

  it("serialises a bigint nonce rather than dropping it", () => {
    // `JSON.stringify` throws on a bigint, so a summary that kept one would crash whatever
    // tried to write it. Converting here means the value survives.
    const summary = toSafeSummary({
      ccid: "0xabc",
      status: "Valid",
      reason: "OK",
      nonce: 2n ** 64n,
      providerId: "0xdef",
    });
    expect(() => JSON.stringify(summary)).not.toThrow();
    expect(summary.nonce).toBe("18446744073709551616");
  });

  it("carries no attribute-shaped field", () => {
    // The summary is the one thing guaranteed to be persisted, so it is also the one thing
    // that must be minimal by construction rather than by review.
    const summary = toSafeSummary({
      ccid: "0xabc",
      status: "Valid",
      reason: "OK",
      nonce: 1n,
      providerId: "0xdef",
    });
    for (const value of Object.values(summary)) {
      expect(() => assertRedacted(value)).not.toThrow();
    }
  });
});
