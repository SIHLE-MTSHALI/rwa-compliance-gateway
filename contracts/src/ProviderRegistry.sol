// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ComplianceTypes} from "./libraries/ComplianceTypes.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ProviderRegistry
 * @notice Registry of KYC/KYB verification providers, their supported schemas, and
 *         their operational health.
 *
 * @dev ## Why the status set has four values, not two
 *
 *      `Paused` and `Revoked` both deny policy checks, and keeping them distinct is
 *      what makes them operationally different:
 *
 *      - `Paused`     - a temporary operational stop. Backlog or rate limiting.
 *      - `Deprecated` - a planned wind-down. **Still backs existing credentials**,
 *        because a migration must not retroactively invalidate credentials
 *        integrators already reasoned about, while new issuance is blocked.
 *      - `Revoked`    - the adapter's attestations are no longer trusted at all.
 *        Issued on compromise.
 *
 *      Collapsing `Deprecated` into `Paused` would punish every existing holder
 *      during a routine provider change. That is a real failure mode, not a
 *      hypothetical one.
 *
 * @dev ## New providers start paused
 *
 *      {registerProvider} sets `Paused` on creation. An adapter must be reviewed
 *      and explicitly activated before it can influence any decision.
 */
contract ProviderRegistry is AccessControl {
    using ComplianceTypes for bytes32;

    /// @dev May register providers and change status.
    bytes32 public constant PROVIDER_ADMIN = keccak256("PROVIDER_ADMIN");

    /// @dev May submit heartbeats and failure reports.
    bytes32 public constant PROVIDER_OPERATOR = keccak256("PROVIDER_OPERATOR");

    /// @notice A registered provider.
    /// @dev `status` is held as `uint8` rather than the `ProviderStatus` enum so
    ///      the struct packs with the fields after it. It is always a valid enum
    ///      member; {setProviderStatus} and {registerProvider} are the only writers
    ///      and both range-check.
    struct Provider {
        bytes32 providerId;
        string metadataURI;
        uint64 lastHeartbeat;
        uint64 failureCount;
        uint64 registeredAt;
        uint64 updatedAt;
        uint8 status;
        bool registered;
    }

    event ProviderRegistered(bytes32 indexed providerId, string metadataURI);
    /// @dev Emitted with the `providerId` as the subject rather than an address:
    ///      providers are identified by hash, and logging an address that stands in
    ///      for a provider invites the reader to treat it as a person.
    event ProviderStatusChanged(bytes32 indexed providerId, ProviderStatus previous, ProviderStatus current);
    event ProviderSchemaSupportSet(
        bytes32 indexed providerId, bytes32 indexed credentialType, uint32 schemaVersion, bool supported
    );
    event ProviderHeartbeat(bytes32 indexed providerId, uint64 timestamp);
    event ProviderFailureReported(bytes32 indexed providerId, uint64 consecutiveFailures);
    event ProviderMetadataUpdated(bytes32 indexed providerId, string metadataURI);

    /**
     * @notice Operational state of a provider adapter.
     * @dev `Deprecated` means "no new issuance, existing credentials keep their
     *      validity" - the wind-down state, distinct from `Paused` and `Revoked`.
     */
    enum ProviderStatus {
        Unknown,
        Active,
        Paused,
        Deprecated,
        Revoked
    }

    /// @dev providerId => Provider
    mapping(bytes32 => Provider) private _providers;

    /// @dev providerId => credentialType => schemaVersion => supported
    mapping(bytes32 => mapping(bytes32 => mapping(uint32 => bool))) private _schemaSupport;

    error NotProviderAdmin(address caller);
    error NotProviderOperator(address caller);
    error ProviderAlreadyRegistered(bytes32 providerId);
    error ProviderNotRegistered(bytes32 providerId);
    error EmptyProviderId();
    /// @dev Distinct from {EmptyProviderId} so a bad constructor argument is not
    ///      reported as a bad provider.
    error InvalidAdminAddress();
    error MetadataUriTooLong(uint256 length);
    error StaleHeartbeat(uint64 lastHeartbeat, uint64 nowTs);
    error NotStaleHeartbeat(uint64 lastHeartbeat, uint64 nowTs);

    uint256 public constant MAX_METADATA_URI_LENGTH = 512;

    /// @dev A heartbeat older than this is stale. Monitoring signal only.
    uint64 public constant HEARTBEAT_STALENESS_SECONDS = 7 days;

    constructor(address admin) {
        if (admin == address(0)) revert InvalidAdminAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PROVIDER_ADMIN, admin);

        // Without an explicit role admin, `AccessControl.grantRole` resolves the
        // admin of these roles to `bytes32(0)` and reverts - so the roles could
        // never be granted to anyone but the deployer, and a handover would be
        // impossible. Declaring the hierarchy makes the grant path work:
        //
        //     DEFAULT_ADMIN_ROLE -> PROVIDER_ADMIN -> PROVIDER_OPERATOR
        //
        // Two levels rather than one so that adding health reporters is a
        // `PROVIDER_ADMIN` action, not a change to the root of trust.
        _setRoleAdmin(PROVIDER_ADMIN, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(PROVIDER_OPERATOR, PROVIDER_ADMIN);
    }

    modifier onlyProviderAdmin() {
        if (!hasRole(PROVIDER_ADMIN, msg.sender)) revert NotProviderAdmin(msg.sender);
        _;
    }

    modifier onlyProviderOperator() {
        if (!hasRole(PROVIDER_OPERATOR, msg.sender)) revert NotProviderOperator(msg.sender);
        _;
    }

    // ---------------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------------

    /// @notice Register a provider adapter in `Paused` state.
    function registerProvider(bytes32 providerId, string calldata metadataURI) external onlyProviderAdmin {
        if (providerId == bytes32(0)) revert EmptyProviderId();
        if (_providers[providerId].registered) revert ProviderAlreadyRegistered(providerId);
        if (bytes(metadataURI).length > MAX_METADATA_URI_LENGTH) revert MetadataUriTooLong(bytes(metadataURI).length);

        Provider storage p = _providers[providerId];
        p.providerId = providerId;
        p.status = uint8(ProviderStatus.Paused);
        p.metadataURI = metadataURI;
        p.registered = true;
        p.registeredAt = uint64(block.timestamp);
        p.updatedAt = uint64(block.timestamp);

        emit ProviderRegistered(providerId, metadataURI);
        emit ProviderStatusChanged(providerId, ProviderStatus.Unknown, ProviderStatus.Paused);
    }

    /**
     * @notice Change a provider's operational status.
     * @dev No explicit range check: the parameter is the {ProviderStatus} enum, so
     *      solc's ABI decoder already rejects any out-of-range calldata value with
     *      `Panic(0x21)` before the body runs. An in-body range check on an enum
     *      parameter would be unreachable code that implies a guarantee the
     *      compiler, not this function, is providing.
     *      `ProviderRegistryTest.test_OutOfRangeStatusRejectedViaRawCalldata` pins
     *      that behaviour so it is a tested fact rather than an assumption.
     */
    function setProviderStatus(bytes32 providerId, ProviderStatus status) external onlyProviderAdmin {
        if (!_providers[providerId].registered) revert ProviderNotRegistered(providerId);

        ProviderStatus previous = ProviderStatus(_providers[providerId].status);
        _providers[providerId].status = uint8(status);
        _providers[providerId].updatedAt = uint64(block.timestamp);

        // Re-activation clears the failure counter: an operator bringing a
        // provider back should not inherit an unbounded stale alert.
        if (status == ProviderStatus.Active) _providers[providerId].failureCount = 0;

        emit ProviderStatusChanged(providerId, previous, status);
    }

    /// @notice Declare whether a provider may attest a given schema version.
    function setSchemaSupport(bytes32 providerId, bytes32 credentialType, uint32 schemaVersion, bool supported)
        external
        onlyProviderAdmin
    {
        if (!_providers[providerId].registered) revert ProviderNotRegistered(providerId);
        _schemaSupport[providerId][credentialType][schemaVersion] = supported;
        _providers[providerId].updatedAt = uint64(block.timestamp);
        emit ProviderSchemaSupportSet(providerId, credentialType, schemaVersion, supported);
    }

    /// @notice Update the adapter documentation pointer.
    function setMetadataURI(bytes32 providerId, string calldata metadataURI) external onlyProviderAdmin {
        if (!_providers[providerId].registered) revert ProviderNotRegistered(providerId);
        if (bytes(metadataURI).length > MAX_METADATA_URI_LENGTH) revert MetadataUriTooLong(bytes(metadataURI).length);
        _providers[providerId].metadataURI = metadataURI;
        _providers[providerId].updatedAt = uint64(block.timestamp);
        emit ProviderMetadataUpdated(providerId, metadataURI);
    }

    // ---------------------------------------------------------------------
    // Health
    // ---------------------------------------------------------------------

    /// @notice Record a liveness check. Rejects out-of-order reports.
    function heartbeat(bytes32 providerId) external onlyProviderOperator {
        Provider storage p = _providers[providerId];
        if (!p.registered) revert ProviderNotRegistered(providerId);
        if (p.lastHeartbeat != 0 && uint64(block.timestamp) < p.lastHeartbeat) {
            revert StaleHeartbeat(p.lastHeartbeat, uint64(block.timestamp));
        }
        p.lastHeartbeat = uint64(block.timestamp);
        p.updatedAt = uint64(block.timestamp);
        emit ProviderHeartbeat(providerId, uint64(block.timestamp));
    }

    /// @notice Record an adapter failure.
    function reportFailure(bytes32 providerId) external onlyProviderOperator {
        Provider storage p = _providers[providerId];
        if (!p.registered) revert ProviderNotRegistered(providerId);
        p.failureCount += 1;
        p.updatedAt = uint64(block.timestamp);
        emit ProviderFailureReported(providerId, p.failureCount);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function getProvider(bytes32 providerId) external view returns (Provider memory) {
        return _providers[providerId];
    }

    function getProviderStatus(bytes32 providerId) external view returns (ProviderStatus) {
        return ProviderStatus(_providers[providerId].status);
    }

    /// @notice True when registered and `Active`. The single issuance gate.
    function isActive(bytes32 providerId) external view returns (bool) {
        Provider storage p = _providers[providerId];
        return p.registered && p.status == uint8(ProviderStatus.Active);
    }

    /**
     * @notice True when the provider still backs credentials that already exist.
     * @dev `Deprecated` returns true. This is the distinction that stops a routine
     *      provider migration from invalidating every live credential.
     */
    function backsExistingCredentials(bytes32 providerId) external view returns (bool) {
        Provider storage p = _providers[providerId];
        if (!p.registered) return false;
        return p.status == uint8(ProviderStatus.Active) || p.status == uint8(ProviderStatus.Deprecated);
    }

    function supportsSchema(bytes32 providerId, bytes32 credentialType, uint32 schemaVersion)
        external
        view
        returns (bool)
    {
        return _schemaSupport[providerId][credentialType][schemaVersion];
    }

    /**
     * @notice Liveness assessment for monitoring. Not part of the access path.
     * @dev A stale heartbeat does **not** deny access. Denying on liveness would
     *      let a missed heartbeat become a denial of service against every holder,
     *      so health is surfaced to operators and kept out of policy.
     */
    function isProviderHealthy(bytes32 providerId) external view returns (bool healthy) {
        Provider storage p = _providers[providerId];
        if (!p.registered) return false;
        if (p.status != uint8(ProviderStatus.Active)) return false;
        if (p.failureCount != 0) return false;
        if (p.lastHeartbeat == 0) return false;
        healthy = (uint64(block.timestamp) - p.lastHeartbeat) <= HEARTBEAT_STALENESS_SECONDS;
    }

    /// @notice Seconds since last heartbeat, or `type(uint64).max` if never seen.
    function heartbeatAge(bytes32 providerId) external view returns (uint64) {
        uint64 last = _providers[providerId].lastHeartbeat;
        if (last == 0) return type(uint64).max;
        return uint64(block.timestamp) - last;
    }
}
