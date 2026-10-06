import { describe, expect, it } from "vitest";

import { findClaims } from "../../scripts/check-docs-claims.mjs";

/**
 * The classifier's whole reason for existing is that a naive grep cannot tell an assertion
 * from its own denial. These tests are the evidence that a denied claim is allowed and an
 * asserted one is not.
 */
describe("findClaims", () => {
  it("flags an affirmative audit claim", () => {
    expect(findClaims("The contracts have been audited by a third party.")).toHaveLength(1);
    expect(findClaims("The gateway is formally verified.")).toHaveLength(1);
  });

  it("allows the negations a careful README actually uses", () => {
    // Every one of these is a sentence the repository needs to be able to write. A check
    // that fired on any of them would pressure someone into deleting the disclaimer.
    for (const text of [
      "There is no external audit.",
      "This has not been audited.",
      "The contracts have never been audited.",
      "There is no deployed environment.",
      "This is not production-ready.",
      "No audit has been completed.",
      "This code is unaudited.",
    ]) {
      expect(findClaims(text), text).toHaveLength(0);
    }
  });

  it("allows a claim in a code span", () => {
    // A bash command naming an audit directory is not an assertion about the project.
    expect(findClaims("Run `make audited-check` to verify.")).toHaveLength(0);
    expect(findClaims("```\nforge test --match audited\n```")).toHaveLength(0);
  });

  it("does not let a negation in one sentence excuse a claim in the next", () => {
    // The reason this is sentence-scoped rather than line- or paragraph-scoped: a
    // disclaimer immediately before a real claim must not launder it.
    const findings = findClaims("This is not audited. The contracts were audited by Acme.");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.sentence).toContain("The contracts were audited by Acme");
  });

  it("exempts a whole sentence that mixes a denial with an assertion", () => {
    // A pinned limitation, not an endorsement. The classifier is sentence-scoped, so a
    // sentence containing *any* negation marker is exempt - and a sentence that both denies
    // an audit and asserts one therefore passes.
    //
    // This is deliberate. Clause-scoped negation detection produces false positives on
    // ordinary prose, and a check that cries wolf on correct sentences gets switched off.
    // Contradictory prose like the sentence below is a writing bug that review catches, not
    // the routine accidental claim this check exists for.
    //
    // Pinned so nobody later reads this check as stronger than it is.
    expect(
      findClaims("The audit is pending: the contracts were audited by Acme, though not formally."),
    ).toHaveLength(0);
  });

  it("flags each deployment claim", () => {
    expect(findClaims("This is production-ready.")).toHaveLength(1);
    expect(findClaims("The system is mainnet live.")).toHaveLength(1);
    expect(findClaims("The gateway is deployed to mainnet.")).toHaveLength(1);
    expect(findClaims("Our auditors have signed off.")).toHaveLength(1);
  });

  it("leaves ordinary technical prose alone", () => {
    // A check that fires on normal writing gets switched off, and a switched-off claims
    // check is worse than none: it looks like protection.
    for (const text of [
      "The audit trail records every issuance decision.",
      "Run the audit log exporter for the deployment dashboard.",
      "A production deployment of the registry is required before issuance.",
      "See docs/audit-readiness.md for the audit scope.",
      "The revoke path emits an audit event.",
    ]) {
      expect(findClaims(text), text).toHaveLength(0);
    }
  });

  it("reports a usable line number", () => {
    const text = ["# Title", "", "Intro paragraph.", "", "This has been audited by Acme."].join("\n");
    const findings = findClaims(text);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.line).toBe(5);
  });

  it("reports the phrase so the failure says what to change", () => {
    const findings = findClaims("This has been audited by Acme.");
    expect(findings[0]?.phrase).toContain("audited");
  });

  it("handles an empty document", () => {
    expect(findClaims("")).toHaveLength(0);
  });
});
