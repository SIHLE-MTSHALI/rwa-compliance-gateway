// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {CCIDResolver} from "../src/CCIDResolver.sol";
import {ComplianceTypes} from "../src/libraries/ComplianceTypes.sol";

/**
 * @title GenerateCcidVectors
 * @notice Emits known-good CCID values for the SDK's and workflows' test vectors.
 *
 * @dev ## Why these come from the contract rather than being hand-written
 *
 *      The SDK and the workflows derive CCIDs off-chain. If a vector were computed by
 *      hand and pasted in, a change to the derivation - a reordered field, a new domain
 *      separator - would leave the vectors "passing" while no longer matching the chain.
 *      The gateway re-derives every CCID on submission, so the real consequence is that
 *      every issuance fails, in production, with no failing test pointing at the cause.
 *
 *      Generating from the resolver makes the vectors a witness of the implementation:
 *      a protocol change surfaces as a failing TypeScript test instead.
 *
 *      Field order is part of the protocol and is frozen alongside `DOMAIN`. Changing
 *      either is a breaking protocol change, not a refactor.
 *
 * @dev ## Why the output is pipe-delimited rather than JSON
 *
 *      `console.log` pads every argument to a fixed column, so its JSON output is not
 *      reliably parseable - the padding lands inside string values and around numbers.
 *      An earlier version of this script tried to strip the padding with regular
 *      expressions and got it wrong twice, each time producing a subtly malformed value
 *      rather than an error.
 *
 *      One delimiter, no quoting, no nesting, and trailing whitespace stripped per line
 *      is a format that cannot be misread. `scripts/generate-ccid-vectors.mjs` turns it
 *      into the JSON the tests actually read.
 */
contract GenerateCcidVectors is Script {
    /// @dev One row per (jurisdiction, class) pair worth covering: the classes that can
    ///      appear in a real credential, across more than one jurisdiction, so a swapped
    ///      or dropped field cannot pass by accident.
    uint16[4] internal jurisdictions = [uint16(840), 826, 392, 643];
    ComplianceTypes.InvestorClass[3] internal classes = [
        ComplianceTypes.InvestorClass.USAccredited,
        ComplianceTypes.InvestorClass.NonUSProfessional,
        ComplianceTypes.InvestorClass.Blocked
    ];

    function run() external {
        CCIDResolver resolver = new CCIDResolver();

        bytes32 credentialType = keccak256("kyc.basic");
        bytes32 providerId = keccak256("provider.alpha");
        uint32 schemaVersion = 1;

        console.log("RWA_CCID_VECTORS_V1");
        console.log(string.concat("DOMAIN ", _hex(resolver.DOMAIN())));
        // The fixed inputs are emitted rather than recomputed in the consuming script.
        // A second keccak implementation in JavaScript is another thing that can quietly
        // disagree with the chain, and a vectors file that disagrees is exactly the
        // failure this whole mechanism exists to prevent.
        console.log(
            string.concat("INPUTS ", _hex(credentialType), " ", vm.toString(schemaVersion), " ", _hex(providerId))
        );

        for (uint256 j = 0; j < jurisdictions.length; ++j) {
            for (uint256 c = 0; c < classes.length; ++c) {
                bytes32 subject = keccak256(abi.encode("vector-subject", j, c));
                bytes32 ccid =
                    resolver.compute(credentialType, schemaVersion, providerId, jurisdictions[j], classes[c], subject);
                // One argument, not five: `console.log` accepts at most four, and
                // concatenating first also keeps the padding out of the middle of the
                // line, so the consumer splits on whitespace with confidence.
                console.log(
                    string.concat(
                        "VECTOR ",
                        _hex(subject),
                        " ",
                        vm.toString(uint256(jurisdictions[j])),
                        " ",
                        ComplianceTypes.investorClassToString(classes[c]),
                        " ",
                        _hex(ccid)
                    )
                );
            }
        }

        console.log("RWA_CCID_VECTORS_END");
    }

    /**
     * @dev Fixed-width 64-character hex, no `0x` prefix.
     *
     *      Written out rather than using `Strings.toHexString`, which trims leading
     *      zeros - and these values are compared byte-for-byte by the TypeScript
     *      implementation. A short hex string there would look like a derivation
     *      mismatch rather than a formatting difference.
     */
    function _hex(bytes32 value) private pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory out = new bytes(64);
        for (uint256 i = 0; i < 32; ++i) {
            // `bytes1` narrows to `uint8` before widening to `uint256`; Solidity does not
            // allow the conversion in a single step.
            uint8 byteValue = uint8(value[i]);
            out[i * 2] = alphabet[uint256(byteValue) >> 4];
            out[i * 2 + 1] = alphabet[uint256(byteValue) & 0x0f];
        }
        return string(out);
    }
}
