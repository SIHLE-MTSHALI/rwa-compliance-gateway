// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ComplianceTypes} from "./libraries/ComplianceTypes.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title AuditTrail
 * @notice Append-only, privacy-preserving record of credential lifecycle and
 *         policy changes, readable by auditors without exposing investor data.
 *
 * @dev ## What an auditor needs, and what they must not get
 *
 *      An auditor has to answer "why was this investor admitted on this date, and
 *      what was the policy at the time?" That requires a history. It does not
 *      require knowing who the investor is.
 *
 *      So entries carry the CCID - a one-way identifier - and never a name,
 *      address, document reference, or provider case number. An auditor can
 *      reconstruct the decision trail without gaining any new knowledge about the
 *      holder beyond what is already public in the credential record itself.
 *
 * @dev ## Append-only by construction
 *
 *      There is no update or delete function. Entries are indexed by credential and
 *      by pool, and the per-pool count lets an auditor detect a gap - a silent
 *      removal would break the sequence, which is the property that makes an
 *      append-only log worth keeping.
 *
 * @dev ## Storage cost, stated plainly
 *
 *      One storage slot per entry. This is expensive and it is a deliberate trade:
 *      a log that can be rewritten is not evidence. Deployments that expect very
 *      high decision volume should index off-chain from the emitted events and use
 *      this contract for a sampled or policy-level subset.
 */
contract AuditTrail is AccessControl {
    using ComplianceTypes for bytes32;

    /// @dev May record entries.
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /// @notice A single recorded event.
    struct Entry {
        bytes32 ccid;
        bytes32 poolId;
        bytes32 actor;
        bytes32 reasonCode;
        uint256 amount;
        uint64 timestamp;
        uint8 kind; // EntryKind
    }

    /// @dev Category of a recorded event.
    enum EntryKind {
        Unknown,
        AccessAllowed,
        AccessDenied,
        ReviewRequired,
        CredentialIssued,
        CredentialStatusChanged,
        PolicyVersionChanged,
        ProviderStatusChanged,
        EmergencyAction
    }

    event EntryRecorded(uint256 indexed entryId, uint8 indexed kind, bytes32 indexed subject, uint64 timestamp);
    event RecorderAuthorized(address indexed recorder, address indexed authorizedBy);

    /// @dev ccid => entry ids.
    mapping(bytes32 => uint32[]) private _byCredential;

    /// @dev poolId => entry ids.
    mapping(bytes32 => uint32[]) private _byPool;

    /// @dev entryId => entry.
    mapping(uint256 => Entry) private _entries;

    /// @dev Next entry id. Monotonic; also the append-only sequence number.
    uint256 public nextEntryId;

    error NotAuditor(address caller);
    error EntryIdOutOfRange(uint256 entryId);
    /// @dev Distinct from {NotAuditor} so a bad constructor argument is not reported
    ///      as a failed authorization.
    error InvalidAdminAddress();

    /// @dev Bound on a paged read.
    uint256 public constant MAX_PAGE = 50;

    constructor(address admin) {
        if (admin == address(0)) revert InvalidAdminAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(AUDITOR_ROLE, admin);

        // `AccessControl.grantRole` resolves a role's admin to `bytes32(0)` unless
        // told otherwise, and no account can hold that - so without this, the only
        // way to authorize a recorder contract would be {authorizeRecorder}.
        // Declaring the admin as well keeps the standard path working, which matters
        // for tooling and for auditors verifying the role set.
        _setRoleAdmin(AUDITOR_ROLE, DEFAULT_ADMIN_ROLE);
    }

    /**
     * @notice Authorize a contract to record entries, naming it in an event.
     * @dev Preferred over `grantRole(AUDITOR_ROLE, x)` for the same effect, because
     *      it emits {RecorderAuthorized}: an auditor needs to know *which contracts*
     *      are permitted to write history, and the standard role event does not make
     *      that legible in a log sweep.
     */
    function authorizeRecorder(address recorder) external {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert NotAuditor(msg.sender);
        if (recorder == address(0)) revert InvalidAdminAddress();
        _grantRole(AUDITOR_ROLE, recorder);
        emit RecorderAuthorized(recorder, msg.sender);
    }

    modifier onlyAuditor() {
        if (!hasRole(AUDITOR_ROLE, msg.sender)) revert NotAuditor(msg.sender);
        _;
    }

    /**
     * @notice Record an access decision.
     * @dev Called by {PoolComplianceModule.evaluateAndRecord} for allows and
     *      reviews, and available to a compliance officer for denials they resolve.
     *      Denials are not recorded by the module itself: doing so would let anyone
     *      inflate a holder's public denial history by probing.
     */
    function recordDecision(
        bytes32 ccid,
        bytes32 poolId,
        address actor,
        ComplianceTypes.Decision decision,
        bytes32 reasonCode,
        uint256 amount
    ) external onlyAuditor {
        uint8 kind = decision == ComplianceTypes.Decision.Allow
            ? uint8(EntryKind.AccessAllowed)
            : (decision == ComplianceTypes.Decision.ReviewRequired
                    ? uint8(EntryKind.ReviewRequired)
                    : uint8(EntryKind.AccessDenied));
        _append(ccid, poolId, bytes32(uint256(uint160(actor))), reasonCode, amount, kind);
    }

    /// @notice Record a credential lifecycle event.
    /**
     * @notice Record a credential lifecycle event.
     * @dev `resultingStatus` is packed into the entry's `actor` field so the entry
     *      keeps a fixed shape. Packing rather than widening `actor` matters: the
     *      status is what an auditor wants alongside the reason, and a separate
     *      field would cost another slot per entry.
     */
    function recordCredentialEvent(
        bytes32 ccid,
        bytes32 poolId,
        bytes32 reasonCode,
        ComplianceTypes.CredentialStatus resultingStatus
    ) external onlyAuditor {
        _append(
            ccid, poolId, bytes32(uint256(resultingStatus)), reasonCode, 0, uint8(EntryKind.CredentialStatusChanged)
        );
    }

    /// @notice Record a credential issuance.
    function recordIssuance(bytes32 ccid, bytes32 poolId, bytes32 providerId) external onlyAuditor {
        _append(ccid, poolId, providerId, ComplianceTypes.REASON_OK, 0, uint8(EntryKind.CredentialIssued));
    }

    /// @notice Record a policy version change.
    function recordPolicyChange(bytes32 poolId, address actor, uint32 version) external onlyAuditor {
        _append(
            bytes32(0),
            poolId,
            bytes32(uint256(uint160(actor))),
            bytes32(uint256(version)),
            0,
            uint8(EntryKind.PolicyVersionChanged)
        );
    }

    /// @notice Record a provider status change.
    function recordProviderChange(bytes32 providerId, address actor, uint8 newStatus) external onlyAuditor {
        _append(
            bytes32(0),
            providerId,
            bytes32(uint256(uint160(actor))),
            bytes32(uint256(newStatus)),
            0,
            uint8(EntryKind.ProviderStatusChanged)
        );
    }

    /// @notice Record an emergency action.
    function recordEmergencyAction(address actor, bytes32 reasonCode) external onlyAuditor {
        _append(
            bytes32(0), bytes32(0), bytes32(uint256(uint160(actor))), reasonCode, 0, uint8(EntryKind.EmergencyAction)
        );
    }

    // ---------------------------------------------------------------------
    // Reads
    // ---------------------------------------------------------------------

    function totalEntries() external view returns (uint256) {
        return nextEntryId;
    }

    function getEntry(uint256 entryId) external view returns (Entry memory) {
        if (entryId >= nextEntryId) revert EntryIdOutOfRange(entryId);
        return _entries[entryId];
    }

    /// @notice Paged read of a credential's history.
    function credentialHistory(bytes32 ccid, uint256 offset, uint256 limit)
        external
        view
        returns (Entry[] memory page, uint256 total)
    {
        uint32[] storage ids = _byCredential[ccid];
        total = ids.length;
        page = _page(_slice(ids, offset, limit));
    }

    /// @notice Paged read of a pool's history.
    function poolHistory(bytes32 poolId, uint256 offset, uint256 limit)
        external
        view
        returns (Entry[] memory page, uint256 total)
    {
        uint32[] storage ids = _byPool[poolId];
        total = ids.length;
        page = _page(_slice(ids, offset, limit));
    }

    /// @notice Every entry recorded for a credential, bounded by {MAX_PAGE}.
    function credentialHistoryTail(bytes32 ccid) external view returns (Entry[] memory) {
        uint32[] storage ids = _byCredential[ccid];
        uint256 start = ids.length > MAX_PAGE ? ids.length - MAX_PAGE : 0;
        uint32[] memory out = new uint32[](ids.length - start);
        for (uint256 i = start; i < ids.length; ++i) {
            out[i - start] = ids[i];
        }
        return _page(out);
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    function _append(bytes32 ccid, bytes32 poolId, bytes32 actor, bytes32 reasonCode, uint256 amount, uint8 kind)
        private
    {
        uint256 id = nextEntryId;
        Entry storage e = _entries[id];
        e.ccid = ccid;
        e.poolId = poolId;
        e.actor = actor;
        e.reasonCode = reasonCode;
        e.amount = amount;
        e.timestamp = uint64(block.timestamp);
        e.kind = kind;

        nextEntryId = id + 1;

        if (ccid != bytes32(0)) _byCredential[ccid].push(uint32(id));
        if (poolId != bytes32(0)) _byPool[poolId].push(uint32(id));

        bytes32 subject = ccid != bytes32(0) ? ccid : poolId;
        emit EntryRecorded(id, kind, subject, uint64(block.timestamp));
    }

    function _slice(uint32[] storage ids, uint256 offset, uint256 limit) private view returns (uint32[] memory out) {
        if (offset >= ids.length) return new uint32[](0);
        uint256 available = ids.length - offset;
        uint256 take = available > limit ? limit : available;
        if (take > MAX_PAGE) take = MAX_PAGE;
        out = new uint32[](take);
        for (uint256 i = 0; i < take; ++i) {
            out[i] = ids[offset + i];
        }
    }

    function _page(uint32[] memory ids) private view returns (Entry[] memory out) {
        if (ids.length == 0) return new Entry[](0);
        out = new Entry[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            out[i] = _entries[ids[i]];
        }
    }
}
