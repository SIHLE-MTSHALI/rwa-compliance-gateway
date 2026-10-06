// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {AuditTrail} from "../../src/AuditTrail.sol";
import {CCIDResolver} from "../../src/CCIDResolver.sol";
import {ComplianceGateway} from "../../src/ComplianceGateway.sol";
import {ComplianceRegistry} from "../../src/ComplianceRegistry.sol";
import {CrossChainComplianceSender} from "../../src/CrossChainComplianceSender.sol";
import {EmergencyControls} from "../../src/EmergencyControls.sol";
import {PoolComplianceModule} from "../../src/PoolComplianceModule.sol";
import {PoolPolicyManager} from "../../src/PoolPolicyManager.sol";
import {ProviderRegistry} from "../../src/ProviderRegistry.sol";
import {ComplianceTypes} from "../../src/libraries/ComplianceTypes.sol";

/**
 * @title ComplianceLifecycleHandler
 * @notice Stateful-action generator and ghost state for the compliance invariants.
 *
 * @dev ## Why a small, bounded key space
 *
 *      The actions pick from `NUM_SUBJECTS` subjects rather than deriving a fresh
 *      CCID each time. That is deliberate: with a per-call unique key, no action
 *      ever collides with an existing credential, so every compound path -
 *      renew-after-revoke, resume-after-suspend, reissue - is **unreachable**, and
 *      the corresponding invariants pass vacuously.
 *
 *      Bounding the key space makes collisions the common case rather than the
 *      exception, which is what puts the interesting transitions in reach of the
 *      fuzzer. The price is that reverts are frequent, which is why
 *      `fail_on_revert = false` is set in `foundry.toml`.
 *
 * @dev ## Ghost variables
 *
 *      Invariants are stated against the registry, but the registry does not
 *      remember what it *was*. So the handler records, per subject, the highest
 *      nonce it has observed, whether it has ever seen a credential become
 *      `Revoked`, and a digest of each policy version at the moment it was
 *      registered. Without those, "nonce never decreases" and "a policy version is
 *      immutable" are both unstateable.
 */
contract ComplianceLifecycleHandler is Test {
    // -----------------------------------------------------------------
    // System
    // -----------------------------------------------------------------
    ComplianceRegistry public registry;
    ProviderRegistry public providers;
    PoolPolicyManager public policies;
    PoolComplianceModule public complianceModule;
    AuditTrail public audit;
    CCIDResolver public resolver;
    ComplianceGateway public gateway;
    EmergencyControls public emergency;

    // -----------------------------------------------------------------
    // Actors
    // -----------------------------------------------------------------
    address public immutable admin;
    address public immutable guardian;
    address public immutable workflow;
    address public immutable issuer;
    address public immutable holder;

    // -----------------------------------------------------------------
    // Fixture shape
    // -----------------------------------------------------------------
    bytes32 public constant CRED_TYPE = keccak256("kyc.basic");
    bytes32 public constant PROVIDER_A = keccak256("provider.alpha");
    uint32 public constant SCHEMA_VERSION = 1;
    uint64 public constant TTL = 365 days;

    /**
     * @dev Small on purpose. See the contract docs.
     *
     *      Four subjects with nine (class, jurisdiction) pairs each gives 36 reachable
     *      credentials. Any smaller and the fuzzer's collisions get so frequent that
     *      compound actions dominate; any larger and every invariant's exhaustive
     *      key sweep becomes the suite's runtime cost.
     */
    uint256 public constant NUM_SUBJECTS = 4;
    uint256 public constant NUM_POOLS = 2;

    bytes32[] internal subjects;
    bytes32[] internal pools;

    // -----------------------------------------------------------------
    // Ghost state
    // -----------------------------------------------------------------

    /// @dev Highest nonce observed for a subject, written only after a successful write.
    mapping(bytes32 => uint64) public ghostHighestNonce;

    /// @dev True once a subject has been observed `Revoked`.
    mapping(bytes32 => bool) public ghostEverRevoked;

    /// @dev True once a subject has been observed to exist.
    mapping(bytes32 => bool) public ghostEverIssued;

    /// @dev `keccak256` of a policy version's material fields, captured at registration.
    mapping(bytes32 => mapping(uint32 => bytes32)) public ghostPolicyDigest;

    /// @dev Pool => highest version the handler has observed registered.
    mapping(bytes32 => uint32) public ghostHighestPolicyVersion;

    /// @dev Highest audit entry count observed. Must never decrease.
    uint256 public ghostHighestAuditCount;

    /// @dev Entry id => ccid, captured at write time, to detect any rewrite.
    mapping(uint256 => bytes32) public ghostAuditEntryCcid;

    /// @dev Nonce the handler will submit next for a subject, so submissions increase.
    mapping(bytes32 => uint64) public ghostNextNonce;

    constructor() {
        admin = makeAddr("handler-admin");
        guardian = makeAddr("handler-guardian");
        workflow = makeAddr("handler-workflow");
        issuer = makeAddr("handler-issuer");
        holder = makeAddr("handler-holder");

        vm.warp(1_700_000_000);

        registry = new ComplianceRegistry(admin);
        providers = new ProviderRegistry(admin);
        policies = new PoolPolicyManager(admin);
        audit = new AuditTrail(admin);
        resolver = new CCIDResolver();
        emergency = new EmergencyControls(admin, guardian);

        // No sender: propagation is off, so the invariant suite exercises the
        // single-chain lifecycle. `ComplianceGateway` treats a zero sender as
        // "propagation disabled", which is the configuration under test. Cross-chain
        // behaviour is covered by the deterministic suites, where each rejection
        // path can be asserted exactly rather than sampled.
        gateway = new ComplianceGateway(
            admin, registry, providers, policies, resolver, audit, CrossChainComplianceSender(address(0)), emergency
        );

        vm.startPrank(admin);
        registry.setWriter(address(gateway), true);
        audit.authorizeRecorder(address(gateway));
        providers.registerProvider(PROVIDER_A, "https://example.invalid/adapter");
        providers.setSchemaSupport(PROVIDER_A, CRED_TYPE, SCHEMA_VERSION, true);
        providers.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Active);

        for (uint256 i = 0; i < NUM_SUBJECTS; ++i) {
            subjects.push(keccak256(abi.encode("subject", i)));
        }
        for (uint256 p = 0; p < NUM_POOLS; ++p) {
            bytes32 poolId = keccak256(abi.encode("pool", p));
            pools.push(poolId);
            _registerAndActivate(poolId, uint8(p % 2 == 0 ? 1 : 0), false, 0);
        }
        vm.stopPrank();

        complianceModule = new PoolComplianceModule(registry, providers, policies, emergency, audit);
        // The module writes to the trail too, but only exists now, so it is authorized
        // after construction. Recording an unrecorded allow would leave a gap an
        // auditor could not distinguish from a broken hook.
        vm.prank(admin);
        audit.authorizeRecorder(address(complianceModule));

        vm.startPrank(admin);
        gateway.grantRole(gateway.WORKFLOW_SUBMITTER(), workflow);
        gateway.grantRole(gateway.ISSUER(), issuer);
        gateway.grantRole(gateway.HOLDER(), holder);
        vm.stopPrank();
    }

    // -----------------------------------------------------------------
    // Key selection
    // -----------------------------------------------------------------

    function subjectAt(uint256 i) public view returns (bytes32) {
        return subjects[i];
    }

    function poolAt(uint256 i) public view returns (bytes32) {
        return pools[i];
    }

    function subjectCount() external view returns (uint256) {
        return subjects.length;
    }

    function poolCount() external view returns (uint256) {
        return pools.length;
    }

    /// @dev Bounded, so repeated calls land on the same subject often. See the docs.
    ///
    ///      The three selectors (subject, class, jurisdiction) are drawn from different
    ///      divisors of the seed so all `NUM_SUBJECTS * 3 * 3` keys are reachable. With
    ///      a single divisor they would be correlated - 12 distinct triples instead of
    ///      36 - and the invariant sweep would spend two thirds of its runtime on states
    ///      the fuzzer cannot produce.
    function _pickSubject(uint256 rawSeed) internal view returns (bytes32) {
        return subjects[(rawSeed / 9) % subjects.length];
    }

    function _pickPool(uint256 rawSeed) internal view returns (bytes32) {
        return pools[rawSeed % pools.length];
    }

    /// @dev The CCID the gateway would compute for this subject and class pair.
    function ccidFor(bytes32 subjectCommitment, ComplianceTypes.InvestorClass cls, uint16 jurisdiction)
        public
        view
        returns (bytes32)
    {
        return resolver.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, jurisdiction, cls, subjectCommitment);
    }

    // -----------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------

    function issueCredential(uint256 seed) public {
        bytes32 subjectCommitment = _pickSubject(seed);
        ComplianceTypes.InvestorClass cls = _classFor(seed);
        uint16 jurisdiction = _jurisdictionFor(seed);
        bytes32 ccid = ccidFor(subjectCommitment, cls, jurisdiction);

        ComplianceTypes.CredentialResult memory r = ComplianceTypes.CredentialResult({
            ccid: ccid,
            credentialType: CRED_TYPE,
            providerId: PROVIDER_A,
            subjectCommitment: subjectCommitment,
            evidenceHash: keccak256(abi.encode("evidence", seed)),
            schemaVersion: SCHEMA_VERSION,
            jurisdictionCode: jurisdiction,
            investorClass: cls,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp) + TTL,
            nonce: ++ghostNextNonce[ccid],
            destinationChainSelectors: new uint64[](0)
        });

        vm.prank(workflow);
        gateway.submitCredentialResult(r);

        _observe(ccid);
    }

    function beginVerification(uint256 seed) public {
        bytes32 subjectCommitment = _pickSubject(seed);
        bytes32 ccid = ccidFor(subjectCommitment, _classFor(seed), _jurisdictionFor(seed));
        vm.prank(workflow);
        gateway.beginVerification(ccid, CRED_TYPE, SCHEMA_VERSION, TTL);
        _observe(ccid);
    }

    function renewCredential(uint256 seed) public {
        bytes32 subjectCommitment = _pickSubject(seed);
        ComplianceTypes.InvestorClass cls = _classFor(seed);
        uint16 jurisdiction = _jurisdictionFor(seed);
        bytes32 ccid = ccidFor(subjectCommitment, cls, jurisdiction);

        ComplianceTypes.CredentialResult memory r = ComplianceTypes.CredentialResult({
            ccid: ccid,
            credentialType: CRED_TYPE,
            providerId: PROVIDER_A,
            subjectCommitment: subjectCommitment,
            evidenceHash: keccak256("renewed-evidence"),
            schemaVersion: SCHEMA_VERSION,
            jurisdictionCode: jurisdiction,
            investorClass: cls,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp) + TTL,
            nonce: ++ghostNextNonce[ccid],
            destinationChainSelectors: new uint64[](0)
        });

        vm.prank(workflow);
        gateway.renewCredential(r, new uint64[](0), uint64(block.timestamp) + TTL, ghostNextNonce[ccid]);
        _observe(ccid);
    }

    /**
     * @dev Renewal attempt with a nonce that is deliberately **lower** than the
     *      credential's current one.
     *
     *      Included because without it the nonce-monotonicity invariant is untested
     *      against its own failure mode. Every other renewal action raises the nonce,
     *      so a missing or inverted guard in {ComplianceRegistry.renew} would let a
     *      stale provider result roll the nonce backwards and nothing here would
     *      notice - even though a destination would then discard the resulting message
     *      as stale, leaving a revoked credential valid on other chains.
     *
     *      Expected to revert on every call. The point is the *attempt*, which is what
     *      makes `invariant_nonceNeverDecreases` meaningful rather than trivially true.
     */
    function renewWithStaleNonce(uint256 seed) public {
        bytes32 subjectCommitment = _pickSubject(seed);
        ComplianceTypes.InvestorClass cls = _classFor(seed);
        uint16 jurisdiction = _jurisdictionFor(seed);
        bytes32 ccid = ccidFor(subjectCommitment, cls, jurisdiction);

        ComplianceTypes.CredentialResult memory r = ComplianceTypes.CredentialResult({
            ccid: ccid,
            credentialType: CRED_TYPE,
            providerId: PROVIDER_A,
            subjectCommitment: subjectCommitment,
            evidenceHash: keccak256("stale-result"),
            schemaVersion: SCHEMA_VERSION,
            jurisdictionCode: jurisdiction,
            investorClass: cls,
            issuedAt: uint64(block.timestamp),
            // Twice the TTL, so the expiry guard cannot be the reason this is refused.
            // See {renewWithStaleNonceForTesting}.
            expiresAt: uint64(block.timestamp) + 2 * TTL,
            nonce: ghostNextNonce[ccid], // never incremented: strictly below what was last used
            destinationChainSelectors: new uint64[](0)
        });

        vm.prank(workflow);
        gateway.renewCredential(r, new uint64[](0), uint64(block.timestamp) + 2 * TTL, ghostNextNonce[ccid]);
        _observe(ccid);
    }

    function revokeCredential(uint256 seed) public {
        bytes32 subjectCommitment = _pickSubject(seed);
        bytes32 ccid = ccidFor(subjectCommitment, _classFor(seed), _jurisdictionFor(seed));
        vm.prank(seed % 2 == 0 ? issuer : holder);
        gateway.revoke(ccid, _pickPool(seed), keccak256("fuzz-revoke"), new uint64[](0));
        _observe(ccid);
    }

    function suspendCredential(uint256 seed) public {
        bytes32 subjectCommitment = _pickSubject(seed);
        bytes32 ccid = ccidFor(subjectCommitment, _classFor(seed), _jurisdictionFor(seed));
        vm.prank(issuer);
        gateway.suspend(ccid, keccak256("fuzz-suspend"), new uint64[](0));
        _observe(ccid);
    }

    function resumeCredential(uint256 seed) public {
        bytes32 subjectCommitment = _pickSubject(seed);
        bytes32 ccid = ccidFor(subjectCommitment, _classFor(seed), _jurisdictionFor(seed));
        vm.prank(issuer);
        gateway.resume(ccid, keccak256("fuzz-resume"), new uint64[](0));
        _observe(ccid);
    }

    /**
     * @dev The compound action.
     *
     *      Revoke, then immediately attempt every route back to `Valid`. Each attempt
     *      must revert; if any succeeded, `ghostEverRevoked` would already be set and
     *      the invariant `revoked is terminal` would fail - which is the point.
     *
     *      This path is only reachable because the key space is bounded. With a fresh
     *      CCID per call, the revoke would revert (nothing to revoke) and the recovery
     *      attempts would never run.
     */
    function revokeThenAttemptResurrection(uint256 seed) public {
        bytes32 subjectCommitment = _pickSubject(seed);
        ComplianceTypes.InvestorClass cls = _classFor(seed);
        uint16 jurisdiction = _jurisdictionFor(seed);
        bytes32 ccid = ccidFor(subjectCommitment, cls, jurisdiction);

        vm.prank(issuer);
        gateway.revoke(ccid, _pickPool(seed), keccak256("compound-revoke"), new uint64[](0));
        _observe(ccid);

        // Route 1: resume. Must revert - `Revoked` is terminal.
        vm.prank(issuer);
        gateway.resume(ccid, keccak256("attempt-resume"), new uint64[](0));

        // Route 2: suspend. Must revert.
        vm.prank(issuer);
        gateway.suspend(ccid, keccak256("attempt-suspend"), new uint64[](0));

        // Route 3: renewal with a fresh, higher nonce and a provider result that
        // satisfies every issuance check. This is the strongest attempt available -
        // it is exactly what a legitimate renewal looks like - so if anything could
        // resurrect a revoked credential, it would be this.
        ComplianceTypes.CredentialResult memory r = ComplianceTypes.CredentialResult({
            ccid: ccid,
            credentialType: CRED_TYPE,
            providerId: PROVIDER_A,
            subjectCommitment: subjectCommitment,
            evidenceHash: keccak256("resurrection-attempt"),
            schemaVersion: SCHEMA_VERSION,
            jurisdictionCode: jurisdiction,
            investorClass: cls,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp) + TTL,
            nonce: ++ghostNextNonce[ccid],
            destinationChainSelectors: new uint64[](0)
        });
        vm.prank(workflow);
        gateway.renewCredential(r, new uint64[](0), uint64(block.timestamp) + TTL, ghostNextNonce[ccid]);
    }

    /// @dev Advance time, including past expiry, so lazy expiry is exercised.
    function warpTime(uint256 seed) public {
        vm.warp(block.timestamp + (seed % 90 days) + 1);
    }

    function sweepExpiries(uint256 seed) public {
        bytes32[] memory ccids = new bytes32[](4);
        uint256 n;
        for (uint256 i = 0; i < 4; ++i) {
            bytes32 s = subjects[(seed + i) % subjects.length];
            ccids[n++] = ccidFor(s, _classFor(seed + i), _jurisdictionFor(seed + i));
        }
        vm.prank(address(gateway));
        registry.expireDue(ccids);
        for (uint256 i = 0; i < n; ++i) {
            _observe(ccids[i]);
        }
    }

    function setProviderStatus(uint256 seed) public {
        // Weighted towards `Active` rather than uniform over the five states.
        //
        // Uniform selection leaves the provider `Revoked` about a fifth of the time
        // it runs, and `ProviderRegistry.setProviderStatus` is the only thing that can
        // change it - so an early revoke leaves the system unable to issue for the rest
        // of the run. Measured, not assumed: see {HandlerCoverageTest}.
        ProviderRegistry.ProviderStatus[] memory all = new ProviderRegistry.ProviderStatus[](6);
        all[0] = ProviderRegistry.ProviderStatus.Active;
        all[1] = ProviderRegistry.ProviderStatus.Active;
        all[2] = ProviderRegistry.ProviderStatus.Active;
        all[3] = ProviderRegistry.ProviderStatus.Deprecated;
        all[4] = ProviderRegistry.ProviderStatus.Paused;
        all[5] = ProviderRegistry.ProviderStatus.Revoked;

        // Acts on half the calls, so the status is revisited often without the system
        // being flipped on every single step.
        if (seed % 2 != 0) return;

        vm.prank(admin);
        providers.setProviderStatus(PROVIDER_A, all[(seed / 2) % all.length]);
    }

    /**
     * @dev Guarantee the system is usable again, without asserting a particular state.
     *
     *      This is the single most important action in the handler. Without it the run
     *      spends most of its time in a terminal state:
     *
     *        - `EmergencyControls.pause` has no way back except the two-step unpause,
     *          and every gateway write checks `isPaused()` first, so a single early
     *          pause disables issuance, renewal, suspension, resumption and revocation
     *          for the rest of the run;
     *        - `ProviderRegistry` status changes the same way - a `Revoked` provider
     *          makes every issuance check fail.
     *
     *      Either case leaves the system in a state where every lifecycle action
     *      reverts, the ghost variables never populate, and every invariant passes
     *      vacuously. That is not a hypothetical: it is what the first version of this
     *      handler did, and it reported all six mutations as surviving.
     *
     * @dev ## Schedule first, then warp, then execute
     *
     *      The order is load-bearing and was itself a bug when first written.
     *      `scheduleUnpause` records `unpauseExecutableAt = block.timestamp +
     *      UNPAUSE_DELAY`, so executing in the same transaction always reverts with
     *      `UnpauseDelayNotElapsed` - the delay must elapse *after* the scheduling
     *      transaction, not before it. So the window has to be opened, then the clock
     *      moved past the recorded time, and only then executed.
     *
     *      On a real deployment that is two transactions an hour apart, which is the
     *      property the contract exists to enforce. {HandlerCoverageTest} is what
     *      caught this: the unpause reverted every time, the system stayed paused, and
     *      every lifecycle action became unreachable.
     *
     * @dev Two things are deliberately left alone:
     *
     *        - it never pauses, so the pause invariants still have something to bite on;
     *        - it does not force a policy to be active, so the policy-state invariants
     *          keep seeing both registered-and-active and registered-but-inactive pools.
     */
    function reconcileSystem() public {
        if (!providers.isActive(PROVIDER_A)) {
            vm.prank(admin);
            providers.setProviderStatus(PROVIDER_A, ProviderRegistry.ProviderStatus.Active);
        }
        _unpause("reconciled");
    }

    /// @dev Shared unpause sequence. See {reconcileSystem} for why the order matters.
    function _unpause(string memory reason) internal {
        if (!emergency.isPaused()) return;

        vm.prank(admin);
        emergency.scheduleUnpause(reason);

        vm.warp(uint256(emergency.unpauseExecutableAt()) + 1);
        emergency.executeUnpause();
    }

    function registerPolicyVersion(uint256 seed) public {
        bytes32 poolId = _pickPool(seed);
        uint16[] memory jurisdictions = new uint16[](seed % 3);
        for (uint256 i = 0; i < jurisdictions.length; ++i) {
            jurisdictions[i] = uint16(800 + (seed + i) % 100);
        }
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](seed % 3);
        for (uint256 i = 0; i < classes.length; ++i) {
            classes[i] = ComplianceTypes.InvestorClass((seed + i) % 4);
        }

        uint32 version;
        vm.startPrank(admin);
        policies.registerPolicy(
            poolId,
            seed % 2 == 0,
            jurisdictions,
            classes,
            seed % 3 == 0,
            uint64((seed % 7) * 1 days),
            (seed % 2 == 0) ? 0 : uint256((seed % 1000) * 1e18),
            ComplianceTypes.RevocationMode(uint8(seed % 3)),
            0
        );
        version = policies.latestVersion(poolId);
        vm.stopPrank();

        // Captured once per version, never refreshed. Re-capturing on every
        // registration would defeat the immutability check: a registry that
        // overwrote version 1 in place would have its new contents snapshotted each
        // time, and `invariant_registeredPolicyVersionsAreImmutable` would compare the
        // mutation against itself. The first capture is the witness.
        if (ghostPolicyDigest[poolId][version] == bytes32(0)) {
            ghostPolicyDigest[poolId][version] = _policyDigest(poolId, version);
        }
        ghostHighestPolicyVersion[poolId] = version;
    }

    function activatePolicyVersion(uint256 seed) public {
        bytes32 poolId = _pickPool(seed);
        uint32 version = policies.latestVersion(poolId);
        if (version == 0) return;

        // Move past the activation delay so activation is not always a revert - but
        // only forward, so the clock still advances monotonically overall.
        vm.warp(block.timestamp + policies.POLICY_ACTIVATION_DELAY() + 1);
        vm.prank(admin);
        policies.activatePolicyVersion(poolId, version);
    }

    /**
     * @dev Deactivate a pool's active policy, on half the calls.
     *
     *      Gated so both the active-policy and the policy-inactive invariants see real
     *      traffic: `PoolComplianceModule` reports `POLICY_INACTIVE` for the latter, and
     *      an invariant can only check that reason code if the state occurs.
     */
    function deactivatePolicy(uint256 seed) public {
        if (seed % 2 != 0) return;
        vm.prank(admin);
        policies.deactivateActivePolicy(_pickPool(seed));
    }

    /**
     * @dev Pause the system, on roughly a quarter of calls.
     *
     *      Gated rather than uniform so the paused state is entered often enough for
     *      the pause invariants to bite and cleared often enough for the lifecycle
     *      invariants to keep running. {reconcileSystem} does the clearing.
     *
     * @param seed Also selects which pool and subject are affected, so pausing
     *        interacts with the rest of the state rather than being a pure toggle.
     */
    function pauseSystem(uint256 seed) public {
        seed; // read for signature symmetry with the other actions
        if (seed % 4 != 0) return;
        if (emergency.isPaused()) return;
        vm.prank(guardian);
        emergency.pause("fuzz-incident");
    }

    /**
     * @dev Clear the pause, without touching provider state.
     * @dev Exists alongside {reconcileSystem} so a run can exercise the unpause path
     *      independently - the invariants then observe a paused-then-resumed system
     *      regardless of which provider is active.
     *
     *      Schedule, then warp past the recorded executable time, then execute. See
     *      {reconcileSystem}: doing it in the other order always reverts.
     */
    function scheduleAndExecuteUnpause(uint256 seed) public {
        if (!emergency.isPaused()) return;
        vm.startPrank(admin);
        emergency.scheduleUnpause("fuzz-resolved");
        vm.stopPrank();

        // `seed` only adds jitter to the elapsed margin, so the handler does not always
        // execute on the very first block the contract would allow.
        vm.warp(uint256(emergency.unpauseExecutableAt()) + 1 + (seed % 3));
        emergency.executeUnpause();
    }

    function cancelUnpause() public {
        vm.prank(admin);
        emergency.cancelUnpause();
    }

    function evaluateAccess(uint256 seed) public {
        bytes32 subjectCommitment = _pickSubject(seed);
        bytes32 ccid = ccidFor(subjectCommitment, _classFor(seed), _jurisdictionFor(seed));
        complianceModule.evaluateAndRecord(
            ComplianceTypes.AccessRequest({
                ccid: ccid,
                poolId: _pickPool(seed),
                requestedAmount: uint256(seed % 2000) * 1e18,
                currentAllocation: uint256(seed % 500) * 1e18
            })
        );
    }

    // -----------------------------------------------------------------
    // Direct-call helpers
    //
    // These bypass seed selection so a test can address one specific credential. They
    // are `public` and therefore also reachable by the fuzzer, which is why they are
    // named distinctly: an action the fuzzer can drive on a *chosen* CCID is more
    // dangerous to the invariant suite's coverage story than one it cannot.
    // -----------------------------------------------------------------

    function issueCredentialForTesting(bytes32 ccid, bytes32 subjectCommitment) public {
        ComplianceTypes.CredentialResult memory r = ComplianceTypes.CredentialResult({
            ccid: ccid,
            credentialType: CRED_TYPE,
            providerId: PROVIDER_A,
            subjectCommitment: subjectCommitment,
            evidenceHash: keccak256("coverage-evidence"),
            schemaVersion: SCHEMA_VERSION,
            jurisdictionCode: 840,
            investorClass: ComplianceTypes.InvestorClass.USAccredited,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp) + TTL,
            nonce: ++ghostNextNonce[ccid],
            destinationChainSelectors: new uint64[](0)
        });
        vm.prank(workflow);
        gateway.submitCredentialResult(r);
        _observe(ccid);
    }

    function revokeCredentialForTesting(bytes32 ccid) public {
        vm.prank(issuer);
        gateway.revoke(ccid, pools[0], keccak256("coverage-revoke"), new uint64[](0));
        _observe(ccid);
    }

    function suspendCredentialForTesting(bytes32 ccid) public {
        vm.prank(issuer);
        gateway.suspend(ccid, keccak256("coverage-suspend"), new uint64[](0));
        _observe(ccid);
    }

    function resumeCredentialForTesting(bytes32 ccid) public {
        vm.prank(issuer);
        gateway.resume(ccid, keccak256("coverage-resume"), new uint64[](0));
        _observe(ccid);
    }

    function renewCredentialForTesting(bytes32 ccid, uint64 newNonce) public {
        bytes32 subjectCommitment;
        // Recover the subject commitment from the stored record's own CCID inputs:
        // only the handler knows which subject it used, and re-deriving keeps the
        // CCID binding intact, which the gateway re-checks.
        subjectCommitment = _subjectForCcid(ccid);

        ComplianceTypes.CredentialResult memory r = ComplianceTypes.CredentialResult({
            ccid: ccid,
            credentialType: CRED_TYPE,
            providerId: PROVIDER_A,
            subjectCommitment: subjectCommitment,
            evidenceHash: keccak256("coverage-renewal"),
            schemaVersion: SCHEMA_VERSION,
            jurisdictionCode: 840,
            investorClass: ComplianceTypes.InvestorClass.USAccredited,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp) + TTL,
            nonce: newNonce,
            destinationChainSelectors: new uint64[](0)
        });
        if (newNonce > ghostNextNonce[ccid]) ghostNextNonce[ccid] = newNonce;
        vm.prank(workflow);
        gateway.renewCredential(r, new uint64[](0), uint64(block.timestamp) + TTL, newNonce);
        _observe(ccid);
    }

    /**
     * @dev Renewal attempt for a specific credential, using a nonce that is
     *      deliberately **not** greater than the one last written.
     * @dev The direct-call counterpart of {renewWithStaleNonce}, so a test can
     *      address a known credential rather than hoping a seed selects it.
     */
    function renewWithStaleNonceForTesting(bytes32 ccid) public {
        bytes32 subjectCommitment = _subjectForCcid(ccid);
        ComplianceTypes.CredentialResult memory r = ComplianceTypes.CredentialResult({
            ccid: ccid,
            credentialType: CRED_TYPE,
            providerId: PROVIDER_A,
            subjectCommitment: subjectCommitment,
            evidenceHash: keccak256("coverage-stale"),
            schemaVersion: SCHEMA_VERSION,
            jurisdictionCode: 840,
            investorClass: ComplianceTypes.InvestorClass.USAccredited,
            issuedAt: uint64(block.timestamp),
            // Twice the TTL, so the expiry is always strictly later than the current
            // one. Using `now + TTL` would tie with the existing expiry whenever no time
            // had passed since issuance, so the attempt would be refused on
            // `ExpiryNotLater` instead of on the nonce - and the guard under test would
            // never actually be reached. That mistake hid the mutation for one round.
            expiresAt: uint64(block.timestamp) + 2 * TTL,
            nonce: ghostNextNonce[ccid], // never incremented: strictly below what was last used
            destinationChainSelectors: new uint64[](0)
        });
        vm.prank(workflow);
        gateway.renewCredential(r, new uint64[](0), uint64(block.timestamp) + 2 * TTL, ghostNextNonce[ccid]);
        _observe(ccid);
    }

    /// @dev The handler only ever issues US-accredited credentials at jurisdiction 840
    ///      through the direct-call helpers, so the search is over that pair.
    function _subjectForCcid(bytes32 ccid) internal view returns (bytes32) {
        for (uint256 i = 0; i < subjects.length; ++i) {
            bytes32 candidate = resolver.compute(
                CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, 840, ComplianceTypes.InvestorClass.USAccredited, subjects[i]
            );
            if (candidate == ccid) return subjects[i];
        }
        revert SubjectNotInHandlerKeySpace(ccid);
    }

    error SubjectNotInHandlerKeySpace(bytes32 ccid);

    // -----------------------------------------------------------------
    // Ghost bookkeeping
    // -----------------------------------------------------------------

    /// @dev Read the registry and fold what happened into the ghost state.
    ///
    ///      Called only after a successful action, so a reverted call cannot make the
    ///      ghost state look further along than the registry really is.
    function _observe(bytes32 ccid) internal {
        if (!registry.exists(ccid)) return;
        ghostEverIssued[ccid] = true;

        ComplianceTypes.ComplianceCredential memory r = registry.getRecord(ccid);
        if (r.nonce > ghostHighestNonce[ccid]) ghostHighestNonce[ccid] = r.nonce;
        if (r.status == ComplianceTypes.CredentialStatus.Revoked) ghostEverRevoked[ccid] = true;

        // Capture audit entries as they appear, so a later rewrite is detectable.
        uint256 total = audit.totalEntries();
        for (uint256 i = 0; i < total; ++i) {
            if (ghostAuditEntryCcid[i] == bytes32(0)) {
                ghostAuditEntryCcid[i] = audit.getEntry(i).ccid;
            }
        }
        if (total > ghostHighestAuditCount) ghostHighestAuditCount = total;
    }

    function _policyDigest(bytes32 poolId, uint32 version) internal view returns (bytes32) {
        ComplianceTypes.PoolPolicy memory p = policies.getPolicy(poolId, version);
        return keccak256(
            abi.encode(
                p.poolId,
                p.version,
                p.registered,
                p.requiresManualReview,
                p.requiresFreshReplica,
                p.acceptedJurisdictions,
                p.acceptedInvestorClasses,
                p.maxReplicaAge,
                p.maxAllocationPerInvestor,
                uint8(p.revocationMode),
                p.effectiveAt,
                p.createdAt
            )
        );
    }

    function policyDigest(bytes32 poolId, uint32 version) external view returns (bytes32) {
        return _policyDigest(poolId, version);
    }

    /**
     * @dev Investor class and jurisdiction are derived from **different** parts of the
     *      seed, so all nine combinations are reachable.
     *
     *      Selecting both from `seed % 3` would pair them permanently - a US-accredited
     *      credential could only ever carry jurisdiction 840 - and the invariant suite
     *      would enumerate combinations the fuzzer can never produce, spending its
     *      runtime on states that do not exist.
     */
    function _classFor(uint256 seed) internal pure returns (ComplianceTypes.InvestorClass) {
        ComplianceTypes.InvestorClass[] memory all = new ComplianceTypes.InvestorClass[](3);
        all[0] = ComplianceTypes.InvestorClass.USAccredited;
        all[1] = ComplianceTypes.InvestorClass.NonUSProfessional;
        all[2] = ComplianceTypes.InvestorClass.Blocked;
        return all[seed % all.length];
    }

    function _jurisdictionFor(uint256 seed) internal pure returns (uint16) {
        // Zero is excluded: the gateway rejects an unset jurisdiction, and letting the
        // fuzzer pick it would just produce constant reverts.
        uint16[] memory all = new uint16[](3);
        all[0] = 840;
        all[1] = 826;
        all[2] = 392;
        return all[(seed / all.length) % all.length];
    }

    function _registerAndActivate(
        bytes32 poolId,
        uint8 requiresManualReview,
        bool requiresFreshReplica,
        uint64 maxReplicaAge
    ) internal {
        ComplianceTypes.InvestorClass[] memory classes = new ComplianceTypes.InvestorClass[](2);
        classes[0] = ComplianceTypes.InvestorClass.USAccredited;
        classes[1] = ComplianceTypes.InvestorClass.NonUSProfessional;

        policies.registerPolicy(
            poolId,
            requiresManualReview == 1,
            new uint16[](0),
            classes,
            requiresFreshReplica,
            maxReplicaAge,
            0,
            ComplianceTypes.RevocationMode.IssuerOnly,
            0
        );
        uint32 version = policies.latestVersion(poolId);
        vm.warp(block.timestamp + policies.POLICY_ACTIVATION_DELAY() + 1);
        policies.activatePolicyVersion(poolId, version);

        // Captured here as well as in `registerPolicyVersion`. The fixture policies
        // exist for the whole run, so leaving them out of the ghost state would make
        // `invariant_registeredPolicyVersionsAreImmutable` skip them permanently - and
        // they are the versions the handler actually evaluates against most of the time.
        // Captured once per version, never refreshed.
        //
        // Re-capturing on every registration would defeat the immutability check: a
        // registry that overwrote version 1 in place would have its new contents
        // snapshotted each time, and `invariant_registeredPolicyVersionsAreImmutable`
        // would compare the mutation against itself. The first capture is the witness.
        if (ghostPolicyDigest[poolId][version] == bytes32(0)) {
            ghostPolicyDigest[poolId][version] = _policyDigest(poolId, version);
        }
        ghostHighestPolicyVersion[poolId] = version;
    }
}
