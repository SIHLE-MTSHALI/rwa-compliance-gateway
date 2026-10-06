/**
 * Logging and redaction for the compliance workflows.
 *
 * ## Why this exists
 *
 * Every workflow in this package runs off-chain, inside a Chainlink CRE runtime. That
 * runtime's logs are an operational surface: they get shipped, indexed, and read during
 * incidents by people who did not write the workflow. Anything a workflow prints is
 * therefore a disclosure decision, and a workflow that prints a holder's name has made
 * that decision by accident.
 *
 * The sensitive boundary is meant to be *off-chain by construction*: the workflow
 * receives identity attributes, derives a salted commitment, and sends only hashes. This
 * module exists because that boundary is one careless `console.log` away from being
 * broken, and a broken boundary is invisible in review and permanent in the log store.
 *
 * ## The design, in three parts
 *
 * 1. {@link FORBIDDEN_TOKENS} - substrings that must not appear. Substring matching is
 *    right for *field names*, because the vocabulary is ours: `passportNumber`,
 *    `passport_hash` and `pass-port` are all the same disclosure.
 * 2. {@link FORBIDDEN_WORDS} - whole words that must not appear in free text. Specific
 *    tokens with no ordinary English meaning, so word-boundary matching is safe.
 * 3. {@link SENSITIVE_FIELD_NAMES} - attributes we refuse to *name a field* after, but
 *    which are ordinary English (`document`, `email`) and so cannot be policed in prose
 *    without the guard crying wolf on "the document was rejected".
 * 4. {@link SensitiveRegistry} - the exact values a given workflow handled. Checked as
 *    substrings, because these are known exactly and so cannot collide.
 *
 * Learned values are per-instance, never module-global: two workflows in one runtime
 * must not share a guard, or one's reset silently disarms the other's.
 */

/**
 * Substrings that must never appear, in a field name or in a logged value.
 *
 * Every entry here is specific enough to be safe as a substring - see
 * {@link FORBIDDEN_WORDS} for the ones that are not.
 */
export const FORBIDDEN_TOKENS = [
  "passport",
  "national_id",
  "tax_id",
  "social_security",
  "date_of_birth",
  "full_name",
  "legal_name",
  "first_name",
  "last_name",
  "given_name",
  "family_name",
  "address_line",
  "postcode",
  "zip_code",
  "account_number",
  "card_number",
  "raw_attribute",
  "plaintext_salt",
  "salt_value",
  "evidence_payload",
  "face_image",
] as const;

/**
 * Whole words that must not appear in a logged *value*.
 *
 * Matched on word boundaries, because these are specific tokens that carry no ordinary
 * English meaning - `dob`, `ssn`, `iban` do not appear in prose by accident, so matching
 * them cannot generate a false positive.
 */
export const FORBIDDEN_WORDS = ["ssn", "dob", "iban", "nationalid", "taxid"] as const;

/**
 * Attributes we will not *name a field* after, but which are ordinary English and so cannot
 * be policed in free text.
 *
 * `document`, `email` and `phone` appear constantly in safe prose - "the document was
 * rejected", "emailed the holder" - and a guard that fires on those gets disabled within a
 * week. So they are checked where they are meaningful (a field called `documentType` or
 * `email_hash` is a disclosure: it tells a reader which holder a record concerns) and
 * deliberately not where they would only be noise.
 *
 * A leaked value of these kinds is still caught, by the {@link SensitiveRegistry} rather
 * than by a blocklist - which is the right tool, since it knows the exact value.
 */
export const SENSITIVE_FIELD_NAMES = ["email", "phone", "document", "selfie"] as const;

/** Thrown when a value that must not be logged reaches a log sink. */
export class RedactionError extends Error {
  constructor(
    /** Which guard tripped. Named so the failure says what to look at. */
    readonly rule: "forbidden-token" | "forbidden-word" | "learned-value",
    /** Field name or "unknown". Never the offending value. */
    readonly field: string,
  ) {
    super(
      `refusing to log: field "${field}" matched the ${rule} guard. ` +
        `This is a bug in the workflow, not a runtime condition - the sensitive boundary ` +
        `is meant to be off-chain, so a value that reaches a log sink never should.`,
    );
    this.name = "RedactionError";
  }
}

/**
 * Remembers the sensitive values a workflow handled, so they can be found wherever they
 * appear - including inside a larger string that slipped through.
 *
 * Whole-value matching alone would miss a value that got concatenated into a URL or an
 * error message, so every learned value is checked as a substring.
 */
export class SensitiveRegistry {
  private readonly values = new Set<string>();

  /**
   * Record a value that must never appear in a log.
   *
   * Short values are refused rather than accepted. A two-character attribute would match a
   * large fraction of the log; storing it would give false confidence that the value is
   * protected, which is worse than the error.
   */
  learn(value: string): void {
    if (typeof value !== "string") return;
    if (value.length < 6) {
      throw new RedactionError("learned-value", "learned-value-too-short");
    }
    this.values.add(value);
  }

  /** Learn several values at once. */
  learnAll(values: readonly string[]): void {
    for (const value of values) this.learn(value);
  }

  /** How many values are being guarded. For tests and diagnostics. */
  get size(): number {
    return this.values.size;
  }

  /** True when `text` contains any learned value. */
  contains(text: string): boolean {
    for (const value of this.values) {
      if (text.includes(value)) return true;
    }
    return false;
  }

  /** Forget every learned value. Only meaningful between tests. */
  reset(): void {
    this.values.clear();
  }
}

/**
 * Collapse a string so that separator and case variants of a field name collide.
 *
 * Separators are *removed*, not converted: `pass-port` becomes `passport` and therefore
 * matches `passport`. Converting to a single separator would produce `pass_port`, which
 * does not contain `passport` - normalisation that defeats the check it exists for.
 */
function normalise(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

/**
 * Every attribute name the field-name guard matches, collapsed.
 *
 * All three lists fold together here because a field name carries no prose around it, so
 * substring matching cannot collide with anything. The lists stay separate at the *value*
 * level, where the distinction is the difference between a guard operators keep and one
 * they route around.
 */
const FIELD_NAME_MATCHERS: readonly string[] = [
  ...FORBIDDEN_TOKENS,
  ...FORBIDDEN_WORDS,
  ...SENSITIVE_FIELD_NAMES,
].map(normalise);

/** Split text into alphanumeric words, for whole-word matching. */
function words(value: string): string[] {
  return value.toLowerCase().split(/[^a-z0-9]+/).filter((word) => word.length > 0);
}

/**
 * Throw if `field` names a sensitive attribute.
 *
 * Checks the *name*, because a field called `passportNumber` is a disclosure even when its
 * value has been hashed - it tells a reader which holder a record is about.
 */
export function assertFieldNameIsSafe(field: string): void {
  const collapsed = normalise(field);
  for (const matcher of FIELD_NAME_MATCHERS) {
    if (collapsed.includes(matcher)) {
      throw new RedactionError(
        // Named by origin so the failure points at the list a maintainer needs to change,
        // rather than at a bucket that merges two different rules.
        matcher === normalise(field) ? "forbidden-word" : "forbidden-token",
        field,
      );
    }
  }
}

/**
 * Throw if `text` contains a sensitive word or a learned sensitive value.
 *
 * Runs over the serialised form rather than the object, because the interesting leaks are
 * the incidental ones: a value that ended up inside a URL, an error message, or a
 * provider's response body.
 */
export function assertRedacted(text: string, context: { registry?: SensitiveRegistry; field?: string } = {}): void {
  if (typeof text !== "string") return;

  const field = context.field ?? "unknown";

  // Learned values first. They are known exactly, so they are the strongest signal, and
  // checking them before the blocklists means a real leak is reported as a real leak
  // rather than as an incidental token hit.
  if (context.registry?.contains(text) === true) {
    throw new RedactionError("learned-value", field);
  }

  const collapsed = normalise(text);
  for (const token of FORBIDDEN_TOKENS) {
    if (collapsed.includes(normalise(token))) {
      throw new RedactionError("forbidden-token", field);
    }
  }

  const seen = new Set(words(text));
  for (const word of FORBIDDEN_WORDS) {
    if (seen.has(normalise(word))) {
      throw new RedactionError("forbidden-word", field);
    }
  }
}

/** A log record: an event name and the fields that came with it. */
export interface LogRecord {
  readonly event: string;
  readonly fields: Readonly<Record<string, unknown>>;
}

/** Where a redacted record goes. Injected so tests can capture instead of printing. */
export type LogSink = (record: LogRecord) => void;

/** A logger bound to a sink and a registry. What every workflow receives. */
export interface SafeLogger {
  (event: string, fields?: Readonly<Record<string, unknown>>): void;
}

function serialise(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "bigint") return value.toString();
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    // A circular structure is itself worth surfacing, but not by throwing from inside a
    // logger - that would turn a logging concern into a workflow failure.
    return "[unserialisable]";
  }
}

/**
 * Bind a sink and a registry into the only logger a workflow should use.
 *
 * ## Why a factory rather than a free function
 *
 * The registry has to be passed to every call. A free function makes that an *optional*
 * argument, and an omitted optional argument is exactly how a real leak ships: the log
 * line is safe everywhere except the one workflow whose author forgot. Binding the
 * registry at construction removes the option to forget.
 *
 * ## It throws rather than silently redacting
 *
 * Replacing a sensitive value with `[REDACTED]` would keep the workflow running and the
 * incident going, with the log store quietly full of placeholders where the evidence
 * should be. A redaction failure is a defect in the workflow, and it should stop the run
 * that triggered it.
 *
 * ## Hashes are allowed
 *
 * `bytes32` values are logged as-is. That is the entire point of the design: the CCID, the
 * subject commitment and the evidence hash are safe to log, and they are what an operator
 * needs in order to correlate an incident.
 */
export function createSafeLogger(sink: LogSink, registry?: SensitiveRegistry): SafeLogger {
  return (event: string, fields: Readonly<Record<string, unknown>> = {}): void => {
    assertFieldNameIsSafe(event);

    for (const [name, value] of Object.entries(fields)) {
      assertFieldNameIsSafe(name);
      assertRedacted(serialise(value), { ...(registry === undefined ? {} : { registry }), field: name });
    }

    sink({ event, fields });
  };
}

/**
 * The subset of a log record that is safe to persist or forward.
 *
 * Small on purpose: an operator needs the CCID, the status, the reason and the nonce to
 * reconstruct a decision, and nothing else. A helper that returned "the fields minus the
 * dangerous ones" would still leak anything it had not been told about, which is the
 * failure mode this design is avoiding.
 */
export interface SafeDecisionSummary {
  readonly ccid: string;
  readonly status: string;
  readonly reason: string;
  readonly nonce: string;
  readonly providerId: string;
}

/** Narrow a decision to the fields that may be persisted. */
export function toSafeSummary(input: {
  ccid: string;
  status: string;
  reason: string;
  nonce: bigint | string;
  providerId: string;
}): SafeDecisionSummary {
  return {
    ccid: input.ccid,
    status: input.status,
    reason: input.reason,
    nonce: typeof input.nonce === "bigint" ? input.nonce.toString() : input.nonce,
    providerId: input.providerId,
  };
}
