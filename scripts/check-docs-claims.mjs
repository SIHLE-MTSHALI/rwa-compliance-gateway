#!/usr/bin/env node
/**
 * Refuse documentation that claims an audit, a deployment, or production readiness that
 * this repository does not have.
 *
 * ## Why this is a build step
 *
 * The repository has no audit and no deployment. Documentation that implies otherwise is
 * the fastest way to mislead a reader, and the fastest way to lose someone's trust - and
 * the failure is invisible in review, because a plausible sentence reads normally whether
 * or not it is true. It has to be checked mechanically.
 *
 * ## The hard part: negated claims
 *
 * The naive version of this check greps for "audited" and fails, which means it also fails
 * on "no external audit" and "has never been audited" - and a check that punishes honesty
 * is a check that gets deleted. So this classifies per *sentence* rather than per line,
 * and a sentence containing a negation marker is exempt.
 *
 * Sentence-scoped rather than line-scoped deliberately: a negation two lines earlier in the
 * same paragraph is not in the same claim, and treating it as one would let "This is not
 * audited. The SDK is audited." pass on the strength of the first sentence.
 *
 * ## What this cannot check
 *
 * It cannot tell whether a *non-negated* claim is true. It only enforces that an
 * affirmative claim about audit or deployment exists nowhere in the docs. A sentence like
 * "we audited the CCID derivation" would pass; that is what review is for. This narrows the
 * accident, it does not replace the reader.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, extname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");

/**
 * Phrases that assert something the repository cannot back up.
 *
 * Every pattern requires an *actor* ("audited by"), a *qualifier* ("formally",
 * "externally"), or a *completion* claim ("audit is complete"). The bare adjective
 * "audited" is deliberately not matched: this project has an internal audit trail, and
 * "access decisions are reason-coded and audited" is accurate, ordinary English about that
 * trail. Matching the bare word would flag correct sentences in five of the eight documents
 * and teach everyone to route around the check.
 *
 * The deliberate gap: "this project is audited" with no actor or qualifier passes. That is
 * the cost of not punishing correct prose, and it is a cost worth paying here - review
 * catches the unqualified claim, this catches the routine one.
 */
const CLAIM_PATTERNS = [
  /\b(?:has been|have been|was|were|is|are|been) audited by\b/gi,
  /\b(?:externally|formally|independently|third[- ]party|professionally) audited\b/gi,
  /\bsecurity audits? (?:is |are |has been |have been |was |were )?(?:complete|completed|passed|done)\b/gi,
  /\bproduction[- ]ready\b/gi,
  /\bmainnet (?:is |has been )?(?:live|deployed)\b/gi,
  /\bdeployed to (?:ethereum )?mainnet\b/gi,
  /\b(?:auditor|auditors) (?:have |has )?(?:signed off|approved|certified)\b/gi,
  /\bformally verified\b/gi,
  /\bfully (?:audited|verified|certified)\b/gi,
];

/**
 * Markers that make a claim a negation rather than an assertion.
 *
 * `no` alone is risky - it would exempt "no audit was performed, but the code is audited"
 * - which is why the classifier requires *all* of a claim's sentence to be free of markers
 * rather than exempting per-clause.
 */
const NEGATION_MARKERS =
  /\b(?:not|no|never|without|neither|nor|cannot|can't|isn't|aren't|hasn't|haven't|has not|have not|pre-release|unverified|pending|outstanding|before|await|requires?|if|would|could)\b/i;

/** Code spans and fenced blocks: `audited` in a bash command is not a claim. */
const CODE = /(```[\s\S]*?```|`[^`\n]*`|\bhttps?:\/\/\S+|\b0x[0-9a-fA-F]{8,}\b)/g;

/** A sentence boundary. Deliberately simple; this is a heuristic, not a parser. */
const SENTENCE = /[^.!?\n]*[.!?]|\S[^.!?\n]*$/g;

function stripCode(text) {
  // Replaced with spaces rather than removed, so offsets stay comparable and a line number
  // derived from the stripped text still points at the right line.
  return text.replace(CODE, (match) => " ".repeat(match.length));
}

function* sentences(text) {
  for (const match of text.matchAll(SENTENCE)) {
    yield match[0];
  }
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

/** Every unnegated claim in one document. */
export function findClaims(text) {
  const stripped = stripCode(text);
  const findings = [];

  for (const sentence of sentences(stripped)) {
    if (sentence.trim().length === 0) continue;
    if (NEGATION_MARKERS.test(sentence)) continue;

    for (const pattern of CLAIM_PATTERNS) {
      // Fresh lastIndex per sentence: these are global patterns.
      pattern.lastIndex = 0;
      for (const hit of sentence.matchAll(pattern)) {
        findings.push({
          line: lineOf(stripped, stripped.indexOf(sentence) + (hit.index ?? 0)),
          phrase: hit[0].trim(),
          sentence: sentence.trim().replace(/\s+/g, " ").slice(0, 160),
        });
      }
    }
  }

  return findings;
}

/** Every `.md` file under `dir`, skipping `.git` and dependency trees. */
export function markdownFiles(dir) {
  const SKIP = new Set([".git", "node_modules", "out", "cache", "lib", "dist"]);
  const found = [];

  const walk = (current) => {
    for (const entry of readdirSync(current)) {
      if (SKIP.has(entry)) continue;
      const full = join(current, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (extname(entry) === ".md") {
        found.push(full);
      }
    }
  };

  walk(dir);
  return found;
}

function main() {
  const targets = process.argv.slice(2);
  const files = targets.length > 0
    ? targets.map((t) => join(root, t))
    : markdownFiles(root);

  let total = 0;
  const asJson = process.env.CI === "true";

  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const finding of findClaims(text)) {
      total += 1;
      const where = `${relative(root, file)}:${finding.line}`;
      if (asJson) {
        process.stdout.write(`::error file=${relative(root, file)},line=${finding.line}::${finding.phrase}\n`);
      } else {
        process.stdout.write(`${where}  "${finding.phrase}"  ${finding.sentence}\n`);
      }
    }
  }

  if (total > 0) {
    process.stderr.write(
      `\n${total} unnegated audit/deployment claim(s) in documentation.\n` +
        `This repository has no audit and no deployment. Either add a negation\n` +
        `(e.g. "not audited", "no external audit") or delete the claim.\n` +
        `If a claim is genuinely true now, add it to CLAIM_PATTERNS in\n` +
        `scripts/check-docs-claims.mjs and explain why in a comment there.\n`,
    );
    process.exit(1);
  }

  process.stdout.write(`docs claims: clean across ${files.length} file(s)\n`);
}

// `import.meta.url` guard: the module is imported by its own test.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/").split("/").pop())) {
  main();
}
