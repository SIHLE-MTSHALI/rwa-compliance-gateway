import type { Address, Hex, PublicClient, WalletClient, Chain } from "viem";
import { getContract } from "viem";

import { InvestorClass, RevocationMode } from "./reasons.js";

/**
 * Policy management for an RWA pool.
 *
 * ## Why registration and activation are two calls
 *
 * Because {PoolPolicyManager.POLICY_ACTIVATION_DELAY} sits between them - a week, by
 * default.
 *
 * That gap is the entire reason versioning is worth doing. Without it, an issuer - or
 * someone holding a compromised issuer key - could tighten a policy so sharply that
 * every existing investor became instantly ineligible, with no window in which anyone
 * could notice or respond. Policy that can change without notice is indistinguishable
 * from arbitrary denial.
 *
 * So this client makes the delay impossible to skip by accident: {register} returns the
 * timestamp at which the version becomes activatable rather than activating it, and
 * {activationTime} is the one call an operator needs to check before planning a rollout.
 */

export const POLICY_MANAGER_ABI = [
  {
    type: "function",
    name: "registerPolicy",
    stateMutability: "nonpayable",
    inputs: [
      { name: "poolId", type: "bytes32" },
      { name: "requiresManualReview", type: "bool" },
      { name: "acceptedJurisdictions", type: "uint16[]" },
      { name: "acceptedInvestorClasses", type: "uint8[]" },
      { name: "requiresFreshReplica", type: "bool" },
      { name: "maxReplicaAge", type: "uint64" },
      { name: "maxAllocationPerInvestor", type: "uint256" },
      { name: "revocationMode", type: "uint8" },
      { name: "effectiveAt", type: "uint64" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "activatePolicyVersion",
    stateMutability: "nonpayable",
    inputs: [
      { name: "poolId", type: "bytes32" },
      { name: "version", type: "uint32" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "deactivateActivePolicy",
    stateMutability: "nonpayable",
    inputs: [{ name: "poolId", type: "bytes32" }],
    outputs: [],
  },
  {
    type: "function",
    name: "activeVersion",
    stateMutability: "view",
    inputs: [{ name: "poolId", type: "bytes32" }],
    outputs: [{ type: "uint32" }],
  },
  {
    type: "function",
    name: "latestVersion",
    stateMutability: "view",
    inputs: [{ name: "poolId", type: "bytes32" }],
    outputs: [{ type: "uint32" }],
  },
  {
    type: "function",
    name: "hasActivePolicy",
    stateMutability: "view",
    inputs: [{ name: "poolId", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "hasAnyPolicy",
    stateMutability: "view",
    inputs: [{ name: "poolId", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "isPolicyDeactivated",
    stateMutability: "view",
    inputs: [{ name: "poolId", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "getPolicy",
    stateMutability: "view",
    inputs: [
      { name: "poolId", type: "bytes32" },
      { name: "version", type: "uint32" },
    ],
    outputs: [
      {
        name: "policy",
        type: "tuple",
        components: [
          { name: "poolId", type: "bytes32" },
          { name: "version", type: "uint32" },
          { name: "active", type: "bool" },
          { name: "registered", type: "bool" },
          { name: "requiresManualReview", type: "bool" },
          { name: "requiresFreshReplica", type: "bool" },
          { name: "acceptedJurisdictions", type: "uint16[]" },
          { name: "acceptedInvestorClasses", type: "uint8[]" },
          { name: "maxReplicaAge", type: "uint64" },
          { name: "maxAllocationPerInvestor", type: "uint256" },
          { name: "revocationMode", type: "uint8" },
          { name: "effectiveAt", type: "uint64" },
          { name: "createdAt", type: "uint64" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "POLICY_ACTIVATION_DELAY",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint64" }],
  },
  {
    type: "function",
    name: "isJurisdictionAccepted",
    stateMutability: "view",
    inputs: [
      { name: "poolId", type: "bytes32" },
      { name: "version", type: "uint32" },
      { name: "jurisdictionCode", type: "uint16" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "isInvestorClassAccepted",
    stateMutability: "view",
    inputs: [
      { name: "poolId", type: "bytes32" },
      { name: "version", type: "uint32" },
      { name: "cls", type: "uint8" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "exceedsAllocationCap",
    stateMutability: "view",
    inputs: [
      { name: "poolId", type: "bytes32" },
      { name: "version", type: "uint32" },
      { name: "totalRequested", type: "uint256" },
    ],
    outputs: [{ type: "bool" }],
  },
] as const;

/** A policy version as stored. Immutable once registered - only `active` ever moves. */
export interface PoolPolicy {
  readonly poolId: Hex;
  readonly version: number;
  readonly active: boolean;
  readonly registered: boolean;
  /**
   * Forces every access into review. Checked *last* in the decision order, so it never
   * masks a real denial - an integrator that routed on the reason code would otherwise
   * send a suspended credential to a review queue.
   */
  readonly requiresManualReview: boolean;
  /** Reject replicas older than `maxReplicaAge`. Opt-in; off by default. */
  readonly requiresFreshReplica: boolean;
  /** Empty means **all** jurisdictions are permitted. */
  readonly acceptedJurisdictions: readonly number[];
  /**
   * Empty means all classes **except `Blocked`**.
   *
   * Serving a blocked investor requires an explicit opt-in. The alternative - an empty
   * list meaning "everything" - would make safety depend on an operator remembering to
   * configure an exclusion.
   */
  readonly acceptedInvestorClasses: readonly InvestorClass[];
  readonly maxReplicaAge: bigint;
  /** Zero means uncapped, which is the natural "not configured" value. */
  readonly maxAllocationPerInvestor: bigint;
  readonly revocationMode: RevocationMode;
  readonly effectiveAt: bigint;
  readonly createdAt: bigint;
}

/** What to configure. Every field has a documented default, so a minimal policy is valid. */
export interface PolicyInput {
  readonly requiresManualReview?: boolean;
  /** Omit or leave empty for "all jurisdictions". */
  readonly acceptedJurisdictions?: readonly number[];
  /** Omit or leave empty for "all classes except `Blocked`". */
  readonly acceptedInvestorClasses?: readonly InvestorClass[];
  /** Opt in to rejecting stale replicas. */
  readonly requiresFreshReplica?: boolean;
  /** Seconds. Only consulted when `requiresFreshReplica` is set. */
  readonly maxReplicaAge?: bigint;
  /** Omit or zero for uncapped. */
  readonly maxAllocationPerInvestor?: bigint;
  /** Defaults to `IssuerOnly`. */
  readonly revocationMode?: RevocationMode;
  readonly effectiveAt?: bigint;
}

function assertJurisdictionCodes(codes: readonly number[]): void {
  for (const code of codes) {
    // 0 is rejected by the gateway, so allowing it here would produce a policy that can
    // never match a real credential.
    if (!Number.isInteger(code) || code <= 0 || code > 0xffff) {
      throw new RangeError(`jurisdiction code must be an integer in [1, 65535], got ${code}`);
    }
  }
}

/** Named factory so the ABI-specific `read`/`write` inference survives the field
 *  annotation - see the note in `complianceClient.ts`. */
function policyContract(client: WalletClient, address: Address, chain?: Chain) {
  return getContract({ abi: POLICY_MANAGER_ABI, address, client, ...(chain ? { chain } : {}) });
}

export interface PolicyClientOptions {
  readonly walletClient: WalletClient;
  /** The signer whose `ISSUER_ADMIN` role authorises policy changes. */
  readonly account: Address;
  readonly policyManagerAddress: Address;
  readonly chain?: Chain;
}

/** Write client. Requires a wallet; every call is a transaction the issuer authorises. */
export class PolicyClient {
  private readonly contract: ReturnType<typeof policyContract>;

  /**
   * Passed on every write. viem's contract writer requires explicit options rather than
   * defaulting to a client account, which suits a compliance client: a policy change
   * should never be sent from an account nobody chose.
   */
  private readonly writeOptions: { account: Address; chain: Chain | undefined };

  constructor(options: PolicyClientOptions) {
    this.contract = policyContract(options.walletClient, options.policyManagerAddress, options.chain);
    this.writeOptions = { account: options.account, chain: options.chain };
  }

  /** Seconds a pending version must wait before it can be activated. */
  async activationDelay(): Promise<bigint> {
    return this.contract.read.POLICY_ACTIVATION_DELAY();
  }

  /**
   * Register a new immutable policy version.
   *
   * Does **not** activate it. Returns the version number and the earliest timestamp at
   * which {activate} will succeed, so an operator can plan the rollout rather than
   * discovering the delay when their transaction reverts.
   */
  async register(
    poolId: Hex,
    input: PolicyInput = {},
  ): Promise<{ version: number; activatableAt: bigint; hash: Hex }> {
    const acceptedJurisdictions = input.acceptedJurisdictions ?? [];
    assertJurisdictionCodes(acceptedJurisdictions);

    const hash = await this.contract.write.registerPolicy(
      [
        poolId,
      input.requiresManualReview ?? false,
      [...acceptedJurisdictions],
      [...(input.acceptedInvestorClasses ?? [])],
      input.requiresFreshReplica ?? false,
      input.maxReplicaAge ?? 0n,
      input.maxAllocationPerInvestor ?? 0n,
        input.revocationMode ?? RevocationMode.IssuerOnly,
        input.effectiveAt ?? 0n,
      ],
      this.writeOptions,
    );

    const version = Number(await this.contract.read.latestVersion([poolId]));
    const policy = await this.getPolicy(poolId, version);
    const delay = await this.activationDelay();

    return { version, activatableAt: policy.createdAt + delay, hash };
  }

  /**
   * Activate a registered version. Reverts until the activation delay has elapsed.
   */
  async activate(poolId: Hex, version: number): Promise<Hex> {
    return this.contract.write.activatePolicyVersion([poolId, version], this.writeOptions);
  }

  /**
   * Close a pool to new access without replacing its policy.
   *
   * The policy stays readable, so a past decision can still be explained - which matters
   * to an auditor long after the fact.
   */
  async deactivate(poolId: Hex): Promise<Hex> {
    return this.contract.write.deactivateActivePolicy([poolId], this.writeOptions);
  }

  async activeVersion(poolId: Hex): Promise<number> {
    return this.contract.read.activeVersion([poolId]);
  }

  async latestVersion(poolId: Hex): Promise<number> {
    return this.contract.read.latestVersion([poolId]);
  }

  async hasActivePolicy(poolId: Hex): Promise<boolean> {
    return this.contract.read.hasActivePolicy([poolId]);
  }

  /**
   * True when any version has ever been registered.
   *
   * The counterpart to {hasActivePolicy}, and why `POOL_NOT_REGISTERED` and
   * `POLICY_INACTIVE` are two reason codes rather than one: "never configured" is an
   * integration bug on the caller's side, while "configured but switched off" is a
   * deliberate operational state that will resolve on its own.
   */
  async hasAnyPolicy(poolId: Hex): Promise<boolean> {
    return this.contract.read.hasAnyPolicy([poolId]);
  }

  async isDeactivated(poolId: Hex): Promise<boolean> {
    return this.contract.read.isPolicyDeactivated([poolId]);
  }

  async getPolicy(poolId: Hex, version: number): Promise<PoolPolicy> {
    const p = await this.contract.read.getPolicy([poolId, version]);
    return {
      poolId: p.poolId,
      version: Number(p.version),
      active: p.active,
      registered: p.registered,
      requiresManualReview: p.requiresManualReview,
      requiresFreshReplica: p.requiresFreshReplica,
      acceptedJurisdictions: p.acceptedJurisdictions.map(Number),
      acceptedInvestorClasses: p.acceptedInvestorClasses as InvestorClass[],
      maxReplicaAge: p.maxReplicaAge,
      maxAllocationPerInvestor: p.maxAllocationPerInvestor,
      revocationMode: p.revocationMode as RevocationMode,
      effectiveAt: p.effectiveAt,
      createdAt: p.createdAt,
    };
  }

  async isJurisdictionAccepted(poolId: Hex, version: number, jurisdictionCode: number): Promise<boolean> {
    return this.contract.read.isJurisdictionAccepted([poolId, version, jurisdictionCode]);
  }

  async isInvestorClassAccepted(poolId: Hex, version: number, cls: InvestorClass): Promise<boolean> {
    return this.contract.read.isInvestorClassAccepted([poolId, version, cls]);
  }

  /** Whether a *total* allocation would exceed the cap. Zero cap means uncapped. */
  async exceedsAllocationCap(poolId: Hex, version: number, totalRequested: bigint): Promise<boolean> {
    return this.contract.read.exceedsAllocationCap([poolId, version, totalRequested]);
  }

  /**
   * How long until this version can be activated, in seconds. Zero when already past.
   *
   * Read with the chain's own clock by the caller - this returns the arithmetic, not a
   * timestamp, so it stays correct however long the call is queued.
   */
  async secondsUntilActivatable(poolId: Hex, version: number, now: bigint): Promise<bigint> {
    const policy = await this.getPolicy(poolId, version);
    const activatableAt = policy.createdAt + (await this.activationDelay());
    return activatableAt > now ? activatableAt - now : 0n;
  }
}

/** Read-only view of the same surface, for a public client. */
export function readOnlyPolicyClient(client: PublicClient, address: Address, chain?: Chain) {
  return getContract({
    abi: POLICY_MANAGER_ABI,
    address,
    client,
    ...(chain ? { chain } : {}),
  });
}
