// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title ComplianceTypes
 * @notice Shared enums, structs, and reason codes for the RWA compliance layer.
 *
 * @dev ## What this system stores
 *
 *      A *class*, not an identity. `jurisdictionCode` and `investorClass` are the
 *      only investor-shaped values on chain, and both are coarse buckets selected
 *      by issuer policy. No name, address, tax ID, document, accreditation
 *      certificate number, or provider case reference is stored, emitted, or
 *      loggable anywhere in this repository.
 *
 *      The reason this is possible is that the access decision does not need the
 *      investor. It needs to know "this credential, presented by this holder,
 *      represents a US-accredited investor under jurisdiction 840" - and that is
 *      expressible as two small integers.
 *
 * @dev ## The central invariant
 *
 *      Only `Valid` may produce an ALLOW. `Pending` is explicitly a denial, not a
 *      provisional allow: a credential whose verification has not finished cannot
 *      be relied on, and treating it as "probably fine" is the failure this whole
 *      design exists to prevent.
 *
 *      `MANUAL_REVIEW_REQUIRED` is likewise a denial with a distinct reason, so an
 *      integrator can route it to a review queue rather than to a rejection.
 */
library ComplianceTypes {
    // ---------------------------------------------------------------------
    // Enums
    // ---------------------------------------------------------------------

    /**
     * @notice Lifecycle state of a compliance credential.
     * @dev Mirrors `ENGINEERING_SPEC.md` section 4.
     */
    enum CredentialStatus {
        Unknown,
        Pending,
        Valid,
        Expired,
        Suspended,
        Revoked
    }

    /**
     * @notice Coarse investor eligibility class.
     * @dev Deliberately limited to four values. Every additional class is another
     *      axis on which holders can be correlated from public chain state, so the
     *      set is kept as small as real policy permits. `Blocked` is a first-class
     *      value rather than an absent credential so a denial is explainable.
     */
    enum InvestorClass {
        Unknown,
        USAccredited,
        NonUSProfessional,
        Blocked
    }

    /**
     * @notice How a credential may be revoked, decided per policy version.
     * @dev `GovernanceOnly` deliberately excludes the issuer: a governance-scoped
     *      credential the issuer could revoke unilaterally would not be
     *      governance-scoped.
     */
    enum RevocationMode {
        IssuerOnly,
        HolderOrIssuer,
        GovernanceOnly
    }

    /**
     * @notice Outcome of an access check.
     */
    enum Decision {
        Allow,
        Deny,
        ReviewRequired
    }

    // ---------------------------------------------------------------------
    // Records
    // ---------------------------------------------------------------------

    /**
     * @notice Minimal compliance credential state.
     * @param ccid One-way content identifier binding the credential to its holder.
     * @param credentialType Policy family, e.g. `"kyc.basic"`.
     * @param providerId Verifying provider.
     * @param evidenceHash Commitment to provider evidence. Never the evidence.
     * @param schemaVersion Version of the policy schema applied at issuance.
     * @param jurisdictionCode ISO 3166-1 numeric code of the holder's jurisdiction.
     *        A country, not a person: 840 is the United States.
     * @param investorClass Coarse eligibility bucket.
     * @param status Lifecycle state.
     * @param issuedAt Issuance timestamp.
     * @param expiresAt Expiry timestamp, enforced lazily on read.
     * @param updatedAt Last mutation timestamp.
     * @param nonce Monotonic counter; the replay guard.
     */
    struct ComplianceCredential {
        bytes32 ccid;
        bytes32 credentialType;
        bytes32 providerId;
        bytes32 evidenceHash;
        uint32 schemaVersion;
        uint16 jurisdictionCode;
        InvestorClass investorClass;
        CredentialStatus status;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 updatedAt;
        uint64 nonce;
    }

    /**
     * @notice A credential result as submitted by an authorized Chainlink workflow.
     * @dev `subjectCommitment` is deliberately absent from the struct's
     *      persistent form: the gateway verifies the binding via the CCID and then
     *      discards it, so the commitment never reaches storage.
     */
    struct CredentialResult {
        bytes32 ccid;
        bytes32 credentialType;
        bytes32 providerId;
        bytes32 subjectCommitment;
        bytes32 evidenceHash;
        uint32 schemaVersion;
        uint16 jurisdictionCode;
        InvestorClass investorClass;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 nonce;
        uint64[] destinationChainSelectors;
    }

    /**
     * @notice Cross-chain replication metadata.
     * @dev Kept out of {ComplianceCredential} so the struct matches the spec while
     *      destination freshness stays first-class.
     */
    struct PropagationState {
        bool isReplica;
        uint64 sourceChainSelector;
        uint64 lastUpdatedAt;
        uint64 lastSourceNonce;
    }

    /**
     * @notice An issuer's pool policy.
     * @param poolId Pool this policy governs.
     * @param version Monotonic policy version.
     * @param active False while deactivated or superseded.
     * @param registered Exists as a distinct flag so deactivation is reversible.
     * @param requiresManualReview True forces every access into review.
     * @param requiresFreshReplica Reject replicas older than {maxReplicaAge}.
     * @param acceptedJurisdictions Allowed ISO 3166-1 codes; empty means all.
     * @param acceptedInvestorClasses Allowed classes; empty means all but Blocked.
     * @param maxReplicaAge Tolerance in seconds for replicated state.
     * @param maxAllocationPerInvestor Cap in the pool's accounting token. Zero
     *        means uncapped, which is the natural "not configured" value.
     * @param revocationMode Who may revoke a credential admitted under this policy.
     *        Scoped per-policy so a governance-controlled pool cannot have its
     *        credentials withdrawn unilaterally by its own issuer.
     * @param effectiveAt Timestamp from which this version applies.
     * @param createdAt Registration timestamp.
     */
    struct PoolPolicy {
        bytes32 poolId;
        uint32 version;
        bool active;
        bool registered;
        bool requiresManualReview;
        bool requiresFreshReplica;
        uint16[] acceptedJurisdictions;
        InvestorClass[] acceptedInvestorClasses;
        uint64 maxReplicaAge;
        uint256 maxAllocationPerInvestor;
        RevocationMode revocationMode;
        uint64 effectiveAt;
        uint64 createdAt;
    }

    /**
     * @notice An integrator's access request.
     * @param ccid Credential being presented.
     * @param poolId Pool access is sought.
     * @param requestedAmount Units of the pool's accounting token. Used against
     *        the policy's allocation cap; zero skips the cap check.
     * @param currentAllocation What the holder already holds, so the cap is
     *        evaluated against the total rather than the increment alone.
     */
    struct AccessRequest {
        bytes32 ccid;
        bytes32 poolId;
        uint256 requestedAmount;
        uint256 currentAllocation;
    }

    // ---------------------------------------------------------------------
    // Reason codes
    // ---------------------------------------------------------------------

    /// @notice Access granted.
    bytes32 internal constant REASON_OK = keccak256("OK");

    /// @notice No credential exists for the presented CCID.
    bytes32 internal constant REASON_NO_CREDENTIAL = keccak256("NO_CREDENTIAL");

    /// @notice Verification has not completed. A denial, not a provisional allow.
    bytes32 internal constant REASON_PENDING = keccak256("PENDING");

    /// @notice Past `expiresAt`, or explicitly expired.
    bytes32 internal constant REASON_EXPIRED = keccak256("EXPIRED");

    /// @notice Temporarily blocked by the issuer.
    bytes32 internal constant REASON_SUSPENDED = keccak256("SUSPENDED");

    /// @notice Permanently withdrawn.
    bytes32 internal constant REASON_REVOKED = keccak256("REVOKED");

    /// @notice Holder's jurisdiction is not accepted by this pool's policy.
    bytes32 internal constant REASON_JURISDICTION_BLOCKED = keccak256("JURISDICTION_BLOCKED");

    /// @notice Holder's investor class is not accepted by this pool's policy.
    bytes32 internal constant REASON_INVESTOR_CLASS_BLOCKED = keccak256("INVESTOR_CLASS_BLOCKED");

    /// @notice Replicated state is older than the pool will accept.
    bytes32 internal constant REASON_STALE_DESTINATION = keccak256("STALE_DESTINATION");

    /// @notice Requested or total allocation exceeds the pool's per-investor cap.
    bytes32 internal constant REASON_ALLOCATION_CAP_EXCEEDED = keccak256("ALLOCATION_CAP_EXCEEDED");

    /// @notice Pool policy requires human review before any access.
    bytes32 internal constant REASON_MANUAL_REVIEW_REQUIRED = keccak256("MANUAL_REVIEW_REQUIRED");

    /// @notice No active policy governs this pool.
    bytes32 internal constant REASON_POLICY_INACTIVE = keccak256("POLICY_INACTIVE");

    /// @notice Issuing or attesting provider is not currently Active.
    bytes32 internal constant REASON_PROVIDER_PAUSED = keccak256("PROVIDER_PAUSED");

    /// @notice System is paused; no decision can be trusted.
    bytes32 internal constant REASON_SYSTEM_PAUSED = keccak256("SYSTEM_PAUSED");

    /// @notice The system cannot decide yet and must be asked again.
    bytes32 internal constant REASON_POOL_NOT_REGISTERED = keccak256("POOL_NOT_REGISTERED");

    /**
     * @dev Every reason code, for exhaustive mapping in {reasonToString}.
     *
     *      `POOL_NOT_REGISTERED` was missing from this list while
     *      {PoolComplianceModule._evaluate} returned it as a live reason, so
     *      `describeReason(POOL_NOT_REGISTERED)` answered `UNRECOGNIZED` - an integrator
     *      rendering the reason for "this pool has no policy configured" would have shown
     *      an unrecognised code for one of the most common misconfigurations there is.
     *
     *      The test claiming to cover every code did not catch it, because it iterated
     *      this same list and compared the count to the number of constants *as they were
     *      then written*. {test_EveryDeclaredReasonCodeHasALabel} now derives its
     *      expectation from the declarations instead.
     */
    function allReasons() internal pure returns (bytes32[] memory out) {
        out = new bytes32[](15);
        out[0] = REASON_OK;
        out[1] = REASON_NO_CREDENTIAL;
        out[2] = REASON_PENDING;
        out[3] = REASON_EXPIRED;
        out[4] = REASON_SUSPENDED;
        out[5] = REASON_REVOKED;
        out[6] = REASON_JURISDICTION_BLOCKED;
        out[7] = REASON_INVESTOR_CLASS_BLOCKED;
        out[8] = REASON_STALE_DESTINATION;
        out[9] = REASON_ALLOCATION_CAP_EXCEEDED;
        out[10] = REASON_MANUAL_REVIEW_REQUIRED;
        out[11] = REASON_POOL_NOT_REGISTERED;
        out[12] = REASON_POLICY_INACTIVE;
        out[13] = REASON_PROVIDER_PAUSED;
        out[14] = REASON_SYSTEM_PAUSED;
    }

    /**
     * @notice Map a reason code to its label.
     * @dev Returns `UNRECOGNIZED` rather than reverting, so a newer contract
     *      cannot brick an older SDK's logging path.
     *
     *      The label array is walked in parallel with {allReasons}, so the two must stay
     *      the same length. The `string[15]` type makes a mismatch a compile error rather
     *      than a silent label shift.
     */
    function reasonToString(bytes32 code) internal pure returns (string memory) {
        bytes32[] memory codes = allReasons();
        string[15] memory names = [
            "OK",
            "NO_CREDENTIAL",
            "PENDING",
            "EXPIRED",
            "SUSPENDED",
            "REVOKED",
            "JURISDICTION_BLOCKED",
            "INVESTOR_CLASS_BLOCKED",
            "STALE_DESTINATION",
            "ALLOCATION_CAP_EXCEEDED",
            "MANUAL_REVIEW_REQUIRED",
            "POOL_NOT_REGISTERED",
            "POLICY_INACTIVE",
            "PROVIDER_PAUSED",
            "SYSTEM_PAUSED"
        ];
        for (uint256 i = 0; i < codes.length; ++i) {
            if (codes[i] == code) return names[i];
        }
        return "UNRECOGNIZED";
    }

    /**
     * @notice Human-readable status name.
     */
    function statusToString(CredentialStatus status) internal pure returns (string memory) {
        if (status == CredentialStatus.Unknown) return "Unknown";
        if (status == CredentialStatus.Pending) return "Pending";
        if (status == CredentialStatus.Valid) return "Valid";
        if (status == CredentialStatus.Expired) return "Expired";
        if (status == CredentialStatus.Suspended) return "Suspended";
        if (status == CredentialStatus.Revoked) return "Revoked";
        return "Unrecognized";
    }

    /**
     * @notice Human-readable investor class name.
     */
    function investorClassToString(InvestorClass cls) internal pure returns (string memory) {
        if (cls == InvestorClass.Unknown) return "Unknown";
        if (cls == InvestorClass.USAccredited) return "USAccredited";
        if (cls == InvestorClass.NonUSProfessional) return "NonUSProfessional";
        if (cls == InvestorClass.Blocked) return "Blocked";
        return "Unrecognized";
    }

    /**
     * @notice True only for the single reason that permits access.
     * @dev The one correct way to branch on a decision. Comparing a status to
     *      `Valid` directly is the mistake this library exists to prevent.
     */
    function isAllow(bytes32 code) internal pure returns (bool) {
        return code == REASON_OK;
    }

    /**
     * @notice True when a denial should be routed to a human rather than rejected.
     * @dev `MANUAL_REVIEW_REQUIRED` is the only one. Treating it as a hard deny
     *      makes a policy's review requirement unenforceable, because integrators
     *      would configure it and then ignore it.
     */
    function isReviewRequired(bytes32 code) internal pure returns (bool) {
        return code == REASON_MANUAL_REVIEW_REQUIRED;
    }
}
