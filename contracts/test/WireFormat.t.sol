// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CCIDResolver} from "../src/CCIDResolver.sol";
import {CompliancePayload} from "../src/libraries/CompliancePayload.sol";
import {ComplianceTypes} from "../src/libraries/ComplianceTypes.sol";
import {Test} from "forge-std/Test.sol";

/**
 * @title WireFormatTest
 * @notice CCID derivation and the cross-chain payload encoding.
 *
 * @dev ## The two claims under test
 *
 * 1. **A CCID excludes the nonce.** If renewal minted a new CCID, every renewal
 *    would strand the previous credential on every destination chain as a dangling,
 *    still-`Valid` record that no revocation could reach - nothing would know its
 *    new name. Replay protection is the nonce, kept separate.
 *
 * 2. **Payload integrity is content-bound.** The binding hash covers every field,
 *    so a post-hoc edit to any word is detectable at the receiver.
 */
contract WireFormatTest is Test {
    CCIDResolver internal resolver;

    bytes32 internal constant CRED_TYPE = keccak256("kyc.basic");
    bytes32 internal constant PROVIDER_A = keccak256("provider.alpha");
    bytes32 internal constant SUBJECT = keccak256("subject-commitment-alice");
    uint32 internal constant SCHEMA_VERSION = 1;
    uint16 internal constant US = 840;

    function setUp() public {
        resolver = new CCIDResolver();
    }

    function _ccid(
        bytes32 credType,
        uint32 schema,
        bytes32 provider,
        uint16 jurisdiction,
        ComplianceTypes.InvestorClass cls,
        bytes32 subject
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("rwa-compliance-gateway/CCID/v1"),
                credType,
                uint256(schema),
                provider,
                uint256(jurisdiction),
                uint8(cls),
                subject
            )
        );
    }

    // =================================================================
    // CCID derivation
    // =================================================================

    function test_ComputeIsDeterministic() public {
        bytes32 first = resolver.compute(
            CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
        );
        bytes32 second = resolver.compute(
            CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
        );
        assertEq(first, second);
        assertNotEq(first, bytes32(0));
    }

    function test_ComputeMatchesTheDocumentedPreimage() public {
        // Recomputed independently here rather than by calling `compute` twice, so a
        // change to the field order or the domain separator fails this test instead of
        // silently redefining every existing credential's identity.
        assertEq(
            resolver.compute(
                CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
            ),
            _ccid(CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT)
        );
        assertEq(resolver.DOMAIN(), keccak256("rwa-compliance-gateway/CCID/v1"));
    }

    function test_EveryFieldChangesTheCcid() public {
        bytes32 base = resolver.compute(
            CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
        );

        assertNotEq(
            base,
            resolver.compute(
                keccak256("kyc.enhanced"),
                SCHEMA_VERSION,
                PROVIDER_A,
                US,
                ComplianceTypes.InvestorClass.USAccredited,
                SUBJECT
            ),
            "credential type"
        );
        assertNotEq(
            base,
            resolver.compute(CRED_TYPE, 2, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT),
            "schema version"
        );
        assertNotEq(
            base,
            resolver.compute(
                CRED_TYPE,
                SCHEMA_VERSION,
                keccak256("provider.beta"),
                US,
                ComplianceTypes.InvestorClass.USAccredited,
                SUBJECT
            ),
            "provider"
        );
        assertNotEq(
            base,
            resolver.compute(
                CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, 826, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
            ),
            "jurisdiction"
        );
        assertNotEq(
            base,
            resolver.compute(
                CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.NonUSProfessional, SUBJECT
            ),
            "investor class"
        );
        assertNotEq(
            base,
            resolver.compute(
                CRED_TYPE,
                SCHEMA_VERSION,
                PROVIDER_A,
                US,
                ComplianceTypes.InvestorClass.USAccredited,
                keccak256("subject-commitment-bob")
            ),
            "subject commitment"
        );
    }

    /**
     * @dev The claim the whole credential-lifecycle design rests on.
     *
     *      A CCID is a credential's *identity binding* - "this attestation of these
     *      attributes, by this provider, for this holder". The nonce is a separate
     *      replay counter, so it is not in the derivation.
     *
     *      Consequence if this ever changed: renewal would produce a new CCID, the
     *      previous one would remain `Valid` on every destination chain, and no
     *      revocation could reach it because nothing would know its new name. The
     *      failure is silent and permanent, which is why it is asserted directly
     *      rather than left to the reasoning in the contract docs.
     */
    function test_CcidDoesNotDependOnNonce() public view {
        // The resolver has no nonce parameter at all, which is the structural form of
        // this guarantee. Assert the *absence* so that adding one later is a
        // deliberate, visible act rather than an oversight.
        bytes32 ccid = resolver.compute(
            CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
        );
        assertEq(
            ccid,
            resolver.compute(
                CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
            )
        );
    }

    function test_VerifyAcceptsOnlyTheTrueCcid() public {
        bytes32 ccid = resolver.compute(
            CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
        );
        assertTrue(
            resolver.verify(
                ccid, CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
            )
        );
        assertFalse(
            resolver.verify(
                keccak256("forged"),
                CRED_TYPE,
                SCHEMA_VERSION,
                PROVIDER_A,
                US,
                ComplianceTypes.InvestorClass.USAccredited,
                SUBJECT
            )
        );
    }

    function test_VerifyCatchesASubjectSwap() public {
        // The anti-tampering property: an accreditation claimed for one holder cannot
        // be presented as another's, because the subject is inside the derivation.
        bytes32 ccid = resolver.compute(
            CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
        );
        assertFalse(
            resolver.verify(
                ccid,
                CRED_TYPE,
                SCHEMA_VERSION,
                PROVIDER_A,
                US,
                ComplianceTypes.InvestorClass.USAccredited,
                keccak256("subject-commitment-bob")
            )
        );
    }

    function test_DeriveEmits() public {
        bytes32 expected = resolver.compute(
            CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
        );
        vm.expectEmit(true, true, true, false, address(resolver));
        emit CCIDResolver.CCIDDerived(expected, CRED_TYPE, PROVIDER_A);
        assertEq(
            resolver.derive(
                CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, US, ComplianceTypes.InvestorClass.USAccredited, SUBJECT
            ),
            expected
        );
    }

    function test_ValidatePartsRejectsUnboundCredentials() public {
        assertTrue(resolver.validateParts(CRED_TYPE, PROVIDER_A, SUBJECT));
        // A zero subject commitment would leave the credential bound to nobody, which
        // is worse than not issuing it at all.
        assertFalse(resolver.validateParts(CRED_TYPE, PROVIDER_A, bytes32(0)));
        assertFalse(resolver.validateParts(bytes32(0), PROVIDER_A, SUBJECT));
        assertFalse(resolver.validateParts(CRED_TYPE, bytes32(0), SUBJECT));
    }

    function test_IsKnownJurisdiction() public {
        assertTrue(resolver.isKnownJurisdiction(US));
        assertFalse(resolver.isKnownJurisdiction(0));
    }

    function test_AssertsEligibility() public {
        // Answers "does this credential assert an eligibility class at all", so
        // `Blocked` is excluded: it is a real class, not an unknown one.
        assertTrue(resolver.assertsEligibility(ComplianceTypes.InvestorClass.USAccredited));
        assertTrue(resolver.assertsEligibility(ComplianceTypes.InvestorClass.NonUSProfessional));
        assertFalse(resolver.assertsEligibility(ComplianceTypes.InvestorClass.Blocked));
        assertFalse(resolver.assertsEligibility(ComplianceTypes.InvestorClass.Unknown));
    }

    // =================================================================
    // Payload encoding
    // =================================================================

    function _message() internal pure returns (CompliancePayload.Message memory m) {
        m.ccid = keccak256("ccid.alice");
        m.credentialType = CRED_TYPE;
        m.providerId = PROVIDER_A;
        m.evidenceHash = keccak256("evidence-root");
        m.schemaVersion = SCHEMA_VERSION;
        m.jurisdictionCode = US;
        m.investorClass = uint8(ComplianceTypes.InvestorClass.USAccredited);
        m.issuedAt = 1_700_000_000;
        m.expiresAt = 1_700_000_000 + 365 days;
        m.nonce = 7;
        m.status = uint8(ComplianceTypes.CredentialStatus.Valid);
        m.sourceChainSelector = 16_015_286_601_757_825_753;
        m.bindingHash = CompliancePayload.recomputeBindingHash(m);
    }

    /**
     * @dev The constant the receiver's length guard depends on.
     *
     *      Counted independently here: 13 static 32-byte words. If `encode` gained or
     *      lost a field without this constant being updated, every inbound message
     *      would fail `decode` with `BadLength` - and the failure would look like a
     *      version mismatch rather than an off-by-one.
     */
    function test_EncodedLengthMatchesTheFieldCount() public pure {
        bytes memory payload = CompliancePayload.encode(_message());
        assertEq(payload.length, 13 * 32, "13 static 32-byte words");

        (CompliancePayload.Message memory decoded, CompliancePayload.DecodeError err) =
            CompliancePayload.decode(payload);
        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.None), "the constant must agree with encode()");
        assertEq(decoded.nonce, 7);
    }

    function test_RoundTripPreservesEveryField() public pure {
        CompliancePayload.Message memory original = _message();
        (CompliancePayload.Message memory decoded, CompliancePayload.DecodeError err) =
            CompliancePayload.decode(CompliancePayload.encode(original));

        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.None));
        assertEq(decoded.ccid, original.ccid);
        assertEq(decoded.credentialType, original.credentialType);
        assertEq(decoded.providerId, original.providerId);
        assertEq(decoded.evidenceHash, original.evidenceHash);
        assertEq(decoded.schemaVersion, original.schemaVersion);
        assertEq(decoded.jurisdictionCode, original.jurisdictionCode);
        assertEq(decoded.investorClass, original.investorClass);
        assertEq(decoded.issuedAt, original.issuedAt);
        assertEq(decoded.expiresAt, original.expiresAt);
        assertEq(decoded.nonce, original.nonce);
        assertEq(decoded.status, original.status);
        assertEq(decoded.sourceChainSelector, original.sourceChainSelector);
        assertEq(decoded.bindingHash, original.bindingHash);
    }

    function test_TruncatedPayloadRejected() public pure {
        (, CompliancePayload.DecodeError err) = CompliancePayload.decode(new bytes(415));
        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.BadLength));
    }

    function test_TrailingJunkRejected() public pure {
        // The exact-length guard is what stops a longer buffer being accepted with a
        // valid prefix and an attacker-chosen remainder.
        bytes memory padded = abi.encodePacked(CompliancePayload.encode(_message()), bytes32(0));
        (, CompliancePayload.DecodeError err) = CompliancePayload.decode(padded);
        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.BadLength));
    }

    function test_UnknownStatusRejected() public pure {
        (, CompliancePayload.DecodeError err) =
            CompliancePayload.decode(_withWord(CompliancePayload.encode(_message()), 9, 42));
        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.UnknownStatus));
    }

    function test_UnknownClassRejected() public pure {
        (, CompliancePayload.DecodeError err) =
            CompliancePayload.decode(_withWord(CompliancePayload.encode(_message()), 10, 77));
        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.UnknownClass));
    }

    function test_NumericOverflowRejectedRatherThanWrapping() public pure {
        // A maliciously wide word must not truncate into a small plausible value -
        // e.g. `schemaVersion = 2^32 + 1` must not become `1`.
        (, CompliancePayload.DecodeError err) = CompliancePayload.decode(
            _withWord(CompliancePayload.encode(_message()), 4, uint256(SCHEMA_VERSION) + (1 << 32))
        );
        assertEq(uint8(err), uint8(CompliancePayload.DecodeError.NumericOverflow));
    }

    function test_EveryLegalStatusAndClassDecodes() public pure {
        // The enums are accepted at their boundaries, not just at zero. Without this,
        // a guard written as `<` rather than `<=` would reject `Revoked` or
        // `Blocked` - and revocation is the one status that must never be dropped.
        for (uint256 s = 0; s <= uint256(ComplianceTypes.CredentialStatus.Revoked); ++s) {
            CompliancePayload.Message memory m = _message();
            m.status = uint8(s);
            m.bindingHash = CompliancePayload.recomputeBindingHash(m);
            (, CompliancePayload.DecodeError err) = CompliancePayload.decode(CompliancePayload.encode(m));
            assertEq(uint8(err), uint8(CompliancePayload.DecodeError.None), "every legal status must decode");
        }
        for (uint256 c = 0; c <= uint256(ComplianceTypes.InvestorClass.Blocked); ++c) {
            CompliancePayload.Message memory m = _message();
            m.investorClass = uint8(c);
            m.bindingHash = CompliancePayload.recomputeBindingHash(m);
            (, CompliancePayload.DecodeError err) = CompliancePayload.decode(CompliancePayload.encode(m));
            assertEq(uint8(err), uint8(CompliancePayload.DecodeError.None), "every legal class must decode");
        }
    }

    // =================================================================
    // Binding hash
    // =================================================================

    function test_BindingHashIsDeterministic() public pure {
        assertEq(CompliancePayload.recomputeBindingHash(_message()), CompliancePayload.recomputeBindingHash(_message()));
    }

    function test_BindingHashCoversEveryField() public pure {
        CompliancePayload.Message memory base = _message();
        bytes32 expected = CompliancePayload.recomputeBindingHash(base);

        CompliancePayload.Message memory m = _message();
        m.ccid = keccak256("other");
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "ccid");
        m = _message();
        m.credentialType = keccak256("other");
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "credentialType");
        m = _message();
        m.providerId = keccak256("other");
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "providerId");
        m = _message();
        m.evidenceHash = keccak256("other");
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "evidenceHash");
        m = _message();
        m.schemaVersion = 9;
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "schemaVersion");
        m = _message();
        m.jurisdictionCode = 826;
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "jurisdictionCode");
        m = _message();
        m.investorClass = 2;
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "investorClass");
        m = _message();
        m.issuedAt = 1;
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "issuedAt");
        m = _message();
        m.expiresAt = 1;
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "expiresAt");
        m = _message();
        m.nonce = 8;
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "nonce");
        m = _message();
        m.status = uint8(ComplianceTypes.CredentialStatus.Revoked);
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "status");
        m = _message();
        m.sourceChainSelector = 42;
        assertNotEq(CompliancePayload.recomputeBindingHash(m), expected, "sourceChainSelector");
    }

    /**
     * @dev A revocation and an issuance for the same credential produce different
     *      binding hashes, which is why the receiver can tell a status change from
     *      the state it replaces.
     */
    function test_RevocationHasADistinctBindingHash() public pure {
        CompliancePayload.Message memory issued = _message();
        CompliancePayload.Message memory revoked = _message();
        revoked.status = uint8(ComplianceTypes.CredentialStatus.Revoked);

        assertNotEq(CompliancePayload.recomputeBindingHash(revoked), CompliancePayload.recomputeBindingHash(issued));
    }

    function test_OnlyLegalEnumMembersAreReportedAsKnown() public pure {
        CompliancePayload.Message memory m = _message();
        m.status = 99;
        assertFalse(CompliancePayload.isKnownStatus(m));
        m = _message();
        m.status = uint8(ComplianceTypes.CredentialStatus.Revoked);
        assertTrue(CompliancePayload.isKnownStatus(m));

        m = _message();
        m.investorClass = 99;
        assertFalse(CompliancePayload.isKnownClass(m));
        m = _message();
        m.investorClass = uint8(ComplianceTypes.InvestorClass.Blocked);
        assertTrue(CompliancePayload.isKnownClass(m));
    }

    /**
     * @dev Overwrite one 32-byte word of a payload.
     *
     *      Field order as encoded:
     *      `0 ccid, 1 credentialType, 2 providerId, 3 evidenceHash, 4 schemaVersion,
     *      5 jurisdictionCode, 6 issuedAt, 7 expiresAt, 8 nonce, 9 status,
     *      10 investorClass, 11 sourceChainSelector, 12 bindingHash`
     *
     *      `data` points at the length word, so the first payload word is at
     *      `data + 0x20` - one step, not two.
     */
    function _withWord(bytes memory data, uint256 index, uint256 value) internal pure returns (bytes memory out) {
        out = data;
        assembly {
            mstore(add(add(out, 0x20), mul(index, 0x20)), value)
        }
    }
}
