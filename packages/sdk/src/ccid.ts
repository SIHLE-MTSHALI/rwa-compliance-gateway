import { encodeAbiParameters, keccak256, parseAbiParameters, stringToHex, type Hex } from "viem";

import { InvestorClass } from "./reasons.js";

/**
 * Off-chain CCID derivation, byte-for-byte identical to `CCIDResolver.compute`.
 *
 * ## What a CCID is
 *
 * A credential's **identity binding**: "this attestation of these attributes, by this
 * provider, under this schema, for this jurisdiction and eligibility class, belongs to
 * this holder".
 *
 * ## Why the nonce is not part of it
 *
 * This is the single most consequential decision in the data model, so it is stated
 * rather than implied.
 *
 * A CCID is what integrators and holders store, and what propagates across chains. If
 * renewal produced a new CCID, then every renewal would strand the previous credential
 * on every destination chain as a dangling record that is still `Valid` - and that no
 * revocation could ever reach, because nothing would know its new name. The damage would
 * be silent and permanent.
 *
 * Replay protection is the `nonce`, which lives on the record and must strictly
 * increase. Keeping the two concerns separate is what makes both correct.
 *
 * ## Why the salt never comes here
 *
 * `subjectCommitment` is computed off-chain as a *salted* commitment. The salt stays in
 * the workflow and never reaches the chain, so the commitment is neither reversible nor
 * correlatable across issuers that choose different salts. There is deliberately no
 * function in this file - or in the contract - that accepts a name, email, or document:
 * the sensitive boundary is off-chain by construction, not by policy.
 */

/**
 * Domain separator, versioned so future rules cannot collide.
 *
 * Protocol constant. Changing it invalidates every existing credential, so it is frozen
 * alongside the field order. `contracts/script/GenerateCcidVectors.s.sol` emits this
 * value from the contract, and `test/ccid.test.ts` asserts the two agree.
 */
export const CCID_DOMAIN_LABEL = "rwa-compliance-gateway/CCID/v1";

export const CCID_DOMAIN = keccak256(stringToHex(CCID_DOMAIN_LABEL)) as Hex;

/**
 * The derivation's parameter types, in the exact order `CCIDResolver.compute` uses.
 *
 * The explicit `uint256`/`uint8` widenings below are not incidental. Solidity's
 * `abi.encode` widens every integer to 32 bytes, and `encodePacked` would not - so a
 * hand-rolled encoder that packed the fields would produce a *different, still-valid*
 * hash that the gateway would reject on submission. Getting this wrong does not fail
 * loudly; it fails on chain, in production, on the first issuance.
 */
const CCID_PARAMETERS = parseAbiParameters(
  "bytes32 domain, bytes32 credentialType, uint256 schemaVersion, bytes32 providerId, uint256 jurisdictionCode, uint8 investorClass, bytes32 subjectCommitment",
);

/** The inputs that determine a credential's identity. */
export interface CcidInput {
  /** Policy family, e.g. `keccak256("kyc.basic")`. */
  readonly credentialType: Hex;
  /** Version of the policy schema applied at issuance. */
  readonly schemaVersion: number;
  /** Verifying provider. */
  readonly providerId: Hex;
  /**
   * ISO 3166-1 numeric code of the holder's jurisdiction. A country, not a person:
   * 840 is the United States.
   *
   * 0 is rejected by the gateway, so it is rejected here too rather than producing a
   * CCID that can never be issued.
   */
  readonly jurisdictionCode: number;
  /** Coarse eligibility bucket. */
  readonly investorClass: InvestorClass;
  /**
   * The holder's salted commitment, computed off-chain. Never a name, address, or
   * document.
   */
  readonly subjectCommitment: Hex;
}

function assertUint16(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError(`${field} must be an integer in [0, 65535], got ${value}`);
  }
}

/**
 * Derive a credential's CCID.
 *
 * @throws RangeError if a numeric field is out of range. Thrown rather than truncated,
 *   because a silently truncated jurisdiction would produce a *different, valid* CCID
 *   that the gateway then rejects - and the rejection would point at the derivation
 *   rather than at the range error that actually caused it.
 */
export function computeCcid(input: CcidInput): Hex {
  assertUint16(input.jurisdictionCode, "jurisdictionCode");
  if (!Number.isInteger(input.schemaVersion) || input.schemaVersion < 0 || input.schemaVersion > 0xffffffff) {
    throw new RangeError(`schemaVersion must be an integer in [0, 4294967295], got ${input.schemaVersion}`);
  }
  if (input.investorClass < 0 || input.investorClass > 0xff) {
    throw new RangeError(`investorClass must be an integer in [0, 255], got ${input.investorClass}`);
  }

  return keccak256(
    encodeAbiParameters(CCID_PARAMETERS, [
      CCID_DOMAIN,
      input.credentialType,
      BigInt(input.schemaVersion),
      input.providerId,
      BigInt(input.jurisdictionCode),
      Number(input.investorClass),
      input.subjectCommitment,
    ]),
  );
}

/**
 * Check a claimed CCID against the fields it must derive from.
 *
 * The off-chain mirror of `CCIDResolver.verify`. Useful before submitting, to fail with a
 * clear message instead of a contract revert.
 */
export function verifyCcid(ccid: Hex, input: CcidInput): boolean {
  return computeCcid(input) === ccid;
}

/**
 * Structural validation of the derivation inputs.
 *
 * A zero `subjectCommitment` would leave the credential unbound to anybody, which is
 * worse than not issuing it at all - so it is refused rather than hashed into a valid
 * but meaningless CCID.
 */
export function validateCcidParts(input: Pick<CcidInput, "credentialType" | "providerId" | "subjectCommitment">): boolean {
  return (
    isNonZeroHex(input.credentialType) && isNonZeroHex(input.providerId) && isNonZeroHex(input.subjectCommitment)
  );
}

function isNonZeroHex(value: Hex): boolean {
  return typeof value === "string" && value.length === 66 && !/^0x0+$/.test(value);
}

/**
 * Compute a salted subject commitment.
 *
 * `keccak256(utf8(salt) || utf8(attribute))` - a *demonstration* of the shape, not a
 * production construction.
 *
 * ## Do not use this in production
 *
 * A salt of this kind is not a secret. If the attribute is guessable - and a passport
 * number is not - then an attacker with the salt and the commitment can confirm a guess.
 * The real workflow must use a proper HMAC over the verified attribute, or a keyed
 * commitment whose key never leaves the workflow's secret store.
 *
 * It exists here so the SDK's call sites and tests have a working example, and so the
 * "never send the salt" property has something concrete to attach to.
 */
export function saltedSubjectCommitment(salt: string, attribute: string): Hex {
  return keccak256(`${stringToHex(salt)}${stringToHex(attribute)}` as Hex);
}

/** Convenience: hash a policy family label into its `bytes32` form. */
export function labelToId(label: string): Hex {
  return keccak256(stringToHex(label));
}
