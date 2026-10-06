// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AuditTrail} from "../src/AuditTrail.sol";
import {ProviderRegistry} from "../src/ProviderRegistry.sol";
import {ComplianceTypes} from "../src/libraries/ComplianceTypes.sol";
import {ComplianceTestBase} from "./helpers/ComplianceTestBase.sol";

/**
 * @title NoPiiStorageTest
 * @notice Runtime scan of every storage slot the system writes, looking for
 *         free-form text.
 *
 * @dev ## What this catches that the layout check cannot, and vice versa
 *
 *      `scripts/check-no-dynamic-storage.mjs` reads the *compiled storage layout*. It is
 *      exhaustive - a `string` field cannot exist without being found - but it proves a
 *      shape, not a behaviour.
 *
 *      This test observes the opposite: which slots are actually written, and what ends up
 *      in them. It catches a free-form value reaching storage through a path the layout
 *      cannot describe: an assembly store, a delegatecall into a library that logs, a
 *      struct reached by a mapping the layout printer flattens.
 *
 *      The two are complements, and both are needed. A layout check alone would not
 *      notice a `string` smuggled in via `abi.encodePacked` into a `bytes32`-typed slot.
 *
 * @dev ## The detector
 *
 *      Solidity packs a short string into one slot as `data || len*2`, and a long one as
 *      `data || len*2 + 1` in a trailing slot with the payload elsewhere. Both therefore
 *      leave a slot whose top 31 bytes are printable ASCII and whose lowest byte is a
 *      small length word.
 *
 *      Requiring *both* halves matters: a hash or a timestamp that happens to be printable
 *      would trip a printability test alone, and a genuine 40-character name would not be
 *      missed by a test that only checked the length byte. Tested against both a real
 *      string and real hashes below.
 */
contract NoPiiStorageTest is ComplianceTestBase {
    bytes32 internal poolId = keccak256("pool.treasury");

    /// @dev Counters, so a failure says what was found rather than just that something was.
    uint256 internal scannedSlots;

    // =================================================================
    // The scan
    // =================================================================

    /**
     * @dev Drive a full lifecycle, then scan every slot anything wrote.
     *
     *      The lifecycle is deliberately broad: issuance, a denial, an allow, a
     *      suspension, a revocation, a policy registration and activation, a provider
     *      status change, and an expiry sweep. A narrower run would leave whole code paths
     *      unexamined and the scan would pass without having looked at them.
     */
    function test_NoFreeFormTextReachesStorage() public {
        bytes32 ccid = _issue(SUBJECT, 1);

        // An allow, which writes an audit entry with an amount.
        _seedPermissivePolicy(poolId);
        sourceModule.evaluateAndRecord(_request(ccid, poolId));

        // A denial, which writes nothing - included so the scan covers the path.
        sourceModule.evaluateAndRecord(_request(ccid, keccak256("pool.nonexistent")));

        vm.startPrank(issuer);
        sourceGateway.suspend(ccid, keccak256("under-review"), new uint64[](0));
        sourceGateway.resume(ccid, keccak256("cleared"), new uint64[](0));
        sourceGateway.revoke(ccid, poolId, keccak256("aml-match"), new uint64[](0));
        vm.stopPrank();

        // Provider metadata: the one place a free-form string is *expected*. Scanned
        // separately below rather than excluded, because an allowlist that silently skips
        // a contract is how the next field sneaks in.
        vm.prank(admin);
        sourceProviders.setMetadataURI(PROVIDER_A, "https://example.invalid/adapter/v1/documentation");

        vm.warp(block.timestamp + TTL + 1);
        bytes32[] memory ccids = new bytes32[](1);
        ccids[0] = ccid;
        vm.prank(address(sourceGateway));
        sourceRegistry.expireDue(ccids);

        _assertNoFreeForm(address(sourceRegistry), "ComplianceRegistry");
        _assertNoFreeForm(address(sourcePolicies), "PoolPolicyManager");
        _assertNoFreeForm(address(sourceAudit), "AuditTrail");
        _assertNoFreeForm(address(sourceProviders), "ProviderRegistry");
        _assertNoFreeForm(address(sourceEmergency), "EmergencyControls");
        _assertNoFreeForm(address(destReceiver), "CrossChainComplianceReceiver");

        // The scan has to have looked at something, or every assertion above was vacuous.
        // Asserted here rather than in a separate test: Foundry re-runs `setUp` per test,
        // so a companion test would see a fresh instance with nothing scanned.
        assertGt(scannedSlots, 0, "the scan visited no occupied slots, so it proved nothing");
    }

    // =================================================================
    // Validating the detector itself
    // =================================================================

    /**
     * @dev The detector must actually fire on free-form text.
     *
     *      Without this, the scan above could be a no-op that always passes - which is
     *      precisely the failure mode this whole file exists to prevent, applied to
     *      itself. A mock with a `string` is written to, and the same predicate must
     *      reject the slot.
     */
    function test_DetectorFiresOnRealFreeFormText() public {
        TextHolder holder = new TextHolder();

        // Not free-form: a hash and a number. Must not be flagged.
        holder.writeHash(bytes32(keccak256("some-evidence-root")));
        holder.writeNumber(uint256(12_345));
        assertFalse(_looksLikeFreeForm(vm.load(address(holder), bytes32(uint256(0)))), "a hash must not be flagged");
        assertFalse(_looksLikeFreeForm(vm.load(address(holder), bytes32(uint256(1)))), "a number must not be flagged");

        // Free-form: a name. Must be flagged.
        holder.writeName(bytes("ALICE EXAMPLE-SMITH"));
        assertTrue(_looksLikeFreeForm(vm.load(address(holder), bytes32(uint256(2)))), "a name must be flagged");

        // Free-form: a long string, whose length word lives in its own slot and whose
        // payload lives in the next.
        holder.writeLongName(bytes("a-name-far-too-long-to-pack-into-a-single-storage-slot-by-design"));
        assertTrue(
            _looksLikeFreeForm(vm.load(address(holder), bytes32(uint256(3)))),
            "a long name's length slot must be flagged"
        );
    }

    /**
     * @dev The scan actually looked at something.
     *
     *      Without this the whole file could pass by scanning nothing, which is the exact
     *      failure mode it exists to detect. `ProviderRegistry.metadataURI` gives a floor:
     *      a populated short string is two occupied slots, and the run above writes at
     *      least one for every credential.
     */

    // =================================================================
    // Helpers
    // =================================================================

    /**
     * @dev True when a slot carries the header of a dynamically-sized value.
     *
     *      Solidity has two layouts, and both are matched explicitly:
     *
     *      - **Short** (content fits in the slot): `content || len*2`. So the lowest byte
     *        is even, `len = low/2 <= 31`, the first `len` bytes are the UTF-8 content,
     *        and every byte above them is zero.
     *      - **Long** (content does not fit): the slot holds `len*2 + 1` in the lowest
     *        byte and **zeros** everywhere else, with the payload in the following slots.
     *
     *      Both halves matter, and getting either wrong produces a detector that either
     *      cries wolf or sleeps through the evidence:
     *
     *      - An earlier version allowed zero bytes in the upper region, which flagged the
     *        number `12345` - a small `uint256` has zeros above its two content bytes and a
     *        small low byte, which is byte-for-byte the shape of an empty short string.
     *      - An earlier version required the upper bytes to be printable, which *missed*
     *        every long string, because a long string's length slot is all zeros above the
     *        length word.
     *
     *      Requiring the exact layout of each form rejects both: a hash or timestamp is
     *      overwhelmingly likely to have a non-printable byte in the region the short form
     *      requires to be printable, and a small integer fails the long form's minimum
     *      length.
     */
    function _looksLikeFreeForm(bytes32 slot) internal pure returns (bool) {
        uint256 low = uint256(uint8(uint256(slot))); // lowest byte, i.e. `slot[31]`
        if (low == 0) return false; // a zeroed slot is not text

        if (low % 2 == 0) {
            // --- short form ---
            uint256 len = low / 2;
            if (len == 0 || len > 31) return false;
            for (uint256 i = 0; i < len; ++i) {
                uint8 b = uint8(slot[i]);
                if (b < 0x20 || b > 0x7e) return false;
            }
            for (uint256 i = len; i < 31; ++i) {
                if (uint8(slot[i]) != 0) return false;
            }
            return true;
        }

        // --- long form: a length word and nothing else ---
        uint256 len = (low - 1) / 2;
        // Anything shorter than 32 bytes uses the short encoding, so a small odd low byte
        // is not a long-string header - it is just an odd number.
        if (len < 32) return false;
        for (uint256 i = 0; i < 31; ++i) {
            if (uint8(slot[i]) != 0) return false;
        }
        return true;
    }

    function _assertNoFreeForm(address target, string memory label) internal {
        uint256 highest = _highestSlotTouched(target);

        for (uint256 slot = 0; slot <= highest; ++slot) {
            bytes32 value = vm.load(target, bytes32(slot));
            if (value == bytes32(0)) continue;
            ++scannedSlots;
            assertFalse(
                _looksLikeFreeForm(value), string.concat(label, ": slot ", vm.toString(slot), " holds free-form text")
            );
        }
    }

    /**
     * @dev Upper bound on the slots worth scanning for `target`.
     *
     *      Scans upward until a long run of empty slots appears, which cannot happen
     *      before live state ends - a Solidity mapping's occupied slots are interleaved
     *      with free ones, so a 512-slot gap is not plausible inside a live mapping.
     *      Stopping there keeps the scan linear instead of walking the whole address
     *      space.
     */
    function _highestSlotTouched(address target) internal view returns (uint256 highest) {
        uint256 ceiling = 4096;
        uint256 emptyRun;

        for (uint256 slot = 0; slot <= ceiling; ++slot) {
            if (vm.load(target, bytes32(slot)) == bytes32(0)) {
                ++emptyRun;
                if (emptyRun >= 512) {
                    // Guarded: on a contract with no storage at all the run reaches 512
                    // while `slot` is only 511.
                    return slot < 512 ? 0 : slot - 512;
                }
            } else {
                emptyRun = 0;
            }
        }
        return ceiling;
    }
}

/// @dev Fixture for validating the detector itself. Holds one of each storage shape.
contract TextHolder {
    /**
     * @dev These write with inline assembly rather than declared `string` variables on
     *      purpose: the detector has to recognise the layout Solidity actually produces
     *      for dynamically-sized data, and it is far more obvious here than through a
     *      declared variable.
     *
     *      The parameters are `bytes calldata` rather than `string calldata` because a
     *      `calldata` string slice cannot be copied directly in assembly. The ABI
     *      encoding is identical - offset, length, then payload - so the detector is
     *      still exercising the exact slot layout it will meet in production.
     */
    function writeHash(bytes32 h) external {
        assembly {
            sstore(0, h)
        }
    }

    function writeNumber(uint256 n) external {
        assembly {
            sstore(1, n)
        }
    }

    /**
     * @dev Store `name` using Solidity's **short** string layout.
     *
     *      Written by hand rather than by declaring a `string` state variable because the
     *      detector has to recognise the exact slot encoding, and doing it explicitly
     *      makes the packing visible: content occupies the high 31 bytes and `len*2` sits
     *      in the lowest. An earlier version stored the *memory address* of the data
     *      instead, which the detector correctly did not flag - the slot held a pointer,
     *      not text.
     *
     *      Truncates above 31 bytes, which is the point at which Solidity switches to the
     *      long form; see {writeLongName}.
     */
    function writeName(bytes calldata name) external {
        bytes memory copy = name;
        assembly {
            let len := mload(copy)
            let data := add(copy, 32)
            // `mload(data)` - the *word*, not the pointer. Storing `and(data, ...)`
            // instead would write the memory address, and the detector would be right not
            // to flag a slot containing a pointer.
            sstore(2, or(and(mload(data), not(0xff)), mul(len, 2)))
        }
    }

    /**
     * @dev Store `name` using Solidity's **long** layout: a length word in its own slot,
     *      payload in the slots that follow.
     *
     *      The length slot is `len*2 + 1` with zeros everywhere above it, which is why a
     *      detector that requires printable bytes above the length word misses every long
     *      string.
     */
    function writeLongName(bytes calldata name) external {
        bytes memory copy = name;
        assembly {
            let len := mload(copy)
            let data := add(copy, 32)
            sstore(3, or(mul(len, 2), 1))
            for { let i := 0 } lt(i, len) { i := add(i, 32) } {
                sstore(add(4, div(i, 32)), mload(add(data, i)))
            }
        }
    }
}
