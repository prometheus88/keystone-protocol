# Bounty Lifecycle in Keystone Protocol

This document provides comprehensive examples and best practices for implementing the complete bounty lifecycle within the Keystone protocol. The bounty system enables cybernetic emergence through decentralized task markets that support both foundational infrastructure and exploratory research initiatives.

> **Repository Status Note:** This documentation describes the intended bounty system architecture and workflow patterns. The repository contains references to bounty-related structures in some proto files and examples, but the actual bounty smart contracts, submission handling logic, evaluation systems, and settlement mechanisms are not implemented. The bounty system represents a critical component for the Keystone ecosystem's autonomous evolution that needs to be built on top of the core protocol foundation.

> **Examples and Placeholders:** All values marked with `// EXAMPLE:` comments are placeholder data for documentation purposes only. This includes:
> - Email addresses (e.g., `alice@example.com`, `provider@agent-lab.io`)
> - URLs and URIs (e.g., `https://schemas.postfiat.org/...`, `ipfs://Qm...`, `arweave://...`)
> - Ethereum addresses and contract addresses (e.g., `0x1234...`, `0xBountyContract123...`)
> - Token IDs, transaction hashes, and attestation UIDs (e.g., `1001`, `0x789...abc`)
> - Timestamps, UUIDs, and other identifiers
> - GitHub usernames, repository URLs, and commit hashes
> - Reward amounts and token addresses
> - Replace these with your actual production values when implementing.

## Table of Contents

1. [Bounty Creation](#bounty-creation)
2. [Submission Process](#submission-process)
3. [Award and Settlement](#award-and-settlement)
4. [Genesis Event Support](#genesis-event-support)

---

## Bounty Creation

> **Current Implementation Status:** The repository shows examples of bounty metadata structures and integration patterns with existing Keystone protocols, but contains no actual bounty creation logic, smart contract definitions, or marketplace mechanisms. The documentation demonstrates how bounties would integrate with content descriptors, access control, and agent capabilities, but the implementation is entirely theoretical.
>
> **Future Implementation:** The bounty system will require smart contract implementations for escrow and settlement, integration with EAS for reputation tracking, agent discovery services for capability matching, and coordination with the Keystone registry for agent qualification. The system will need to handle both foundational and exploratory bounty categories with different evaluation criteria.
>
> **Open Architectural Decisions:**
> - **Smart Contract Platform**: Whether to build on Ethereum, Polygon, Arbitrum, or support multiple chains
> - **Submission Format**: Standardized deliverable formats and integration with storage backends
> - **Portfolio Management**: Automated balancing between foundational/exploratory vs. manual curation
> - **Genesis Integration**: How the bounty system bootstraps the initial "Recursion 1" phase

The bounty creation process involves structuring metadata, deploying smart contracts, and setting up agent discovery mechanisms. Bounties are categorized as either **foundational** (infrastructure/tools) or **exploratory** (research/experimental) to support strategic portfolio balancing.

### 1.1 Structuring KeystoneBountyMetadata

```protobuf
// Example: Foundational Bounty for DeFi Risk Assessment Tool
KeystoneBountyMetadata {
  required_capability_uri: "https://schemas.postfiat.org/capabilities/defi-risk/compound-v3/v1", // EXAMPLE: Capability URI
  triggering_context_hash: "0x1234567890abcdef...", // EXAMPLE: SHA-256 of triggering envelope
  submission_deadline: "2024-06-01T23:59:59Z", // EXAMPLE: ISO 8601 timestamp
  
  description_descriptor: {
    uri: "ipfs://QmBountyDescription123", // EXAMPLE: IPFS content URI
    content_type: "text/markdown",
    content_length: 2048,
    content_hash: "sha256_hash_of_description_bytes", // EXAMPLE: Content hash
    metadata: {
      "language": "en",
      "version": "1.0"
    }
  },
  
  contract_info: {
    contract_address: "0xBountyContract123...", // EXAMPLE: Bounty contract address
    chain_id: 1, // Ethereum mainnet
    token_id: "1001" // EXAMPLE: NFT token ID
  },
  
  requirements: {
    "min_accuracy": "95%",
    "response_time": "<5s",
    "supported_protocols": "compound-v3,aave-v3", // EXAMPLE: Protocol requirements
    "audit_requirement": "true"
  },
  
  categories: ["foundational", "defi", "risk-assessment"],
  
  identity_attestations: {
    "github": "risk-dao", // EXAMPLE: GitHub organization
    "eas": "0x789...abc" // EXAMPLE: Ethereum Attestation Service UID
  },
  
  deliverable_type: "agent"
}
```

```protobuf
// Example: Exploratory Bounty for Novel Consensus Research
KeystoneBountyMetadata {
  required_capability_uri: "https://schemas.postfiat.org/capabilities/consensus/novel-mechanisms/v1", // EXAMPLE: Capability URI
  triggering_context_hash: "0xfedcba0987654321...", // EXAMPLE: SHA-256 of triggering envelope
  submission_deadline: "2024-09-15T23:59:59Z", // EXAMPLE: ISO 8601 timestamp
  
  description_descriptor: {
    uri: "arweave://Ary123ConsensusResearch", // EXAMPLE: Arweave content URI
    content_type: "text/markdown",
    content_length: 4096,
    content_hash: "sha256_hash_of_research_brief_bytes" // EXAMPLE: Content hash
  },
  
  contract_info: {
    contract_address: "0xResearchBounty456...", // EXAMPLE: Bounty contract address
    chain_id: 137, // Polygon
    token_id: "2001" // EXAMPLE: NFT token ID
  },
  
  requirements: {
    "novelty_score": ">8.0",
    "theoretical_soundness": "peer_reviewed",
    "implementation_feasibility": "prototype_required",
    "publication_ready": "true"
  },
  
  categories: ["exploratory", "consensus", "research"],
  
  identity_attestations: {
    "orcid": "0000-0002-1234-5678", // EXAMPLE: ORCID researcher ID
    "university": "ethereum-research.eth" // EXAMPLE: University ENS domain
  },
  
  deliverable_type: "analysis"
}
```

### 1.2 Smart Contract Deployment and ERC-20 Setup

```javascript
// Smart Contract Interaction Pattern
const bountyFactoryContract = new ethers.Contract(
  BOUNTY_FACTORY_ADDRESS, // EXAMPLE: Factory contract address
  bountyFactoryABI,
  signer
);

// 1. Approve ERC-20 token transfer
const tokenContract = new ethers.Contract(rewardTokenAddress, erc20ABI, signer);
await tokenContract.approve(BOUNTY_FACTORY_ADDRESS, rewardAmount);

// 2. Create bounty with metadata
const createBountyRequest = {
  bounty_metadata_descriptor: {
    uri: "ipfs://QmBountyMetadata123", // EXAMPLE: IPFS metadata URI
    content_type: "application/protobuf",
    content_length: metadataBytes.length,
    content_hash: ethers.utils.sha256(metadataBytes)
  },
  reward_amount: ethers.utils.parseEther("10.0"), // EXAMPLE: 10 tokens
  reward_token_address: "0xA0b86a33E6441b8bA1eA3"  // EXAMPLE: USDC or custom token address
};

const tx = await bountyFactoryContract.createBounty(createBountyRequest);
const receipt = await tx.wait();

// Extract created bounty details from events
const bountyCreatedEvent = receipt.events.find(e => e.event === 'BountyCreated');
const bountyContractAddress = bountyCreatedEvent.args.bounty_contract_address;
const bountyTokenId = bountyCreatedEvent.args.bounty_token_id;
```

### 1.3 GitHub Integration via Identity Attestations

```typescript
// GitHub Integration for Identity Verification
interface GitHubAttestation {
  username: string;
  repositoryUrl: string;
  commitHash: string;
  verificationProof: string;
}

async function createGitHubAttestation(
  username: string, // EXAMPLE: GitHub username
  repo: string, // EXAMPLE: Repository name
  bountyId: string // EXAMPLE: Bounty identifier
): Promise<GitHubAttestation> {
  // 1. Create verification commit in repository
  const verificationMessage = `Keystone Bounty Verification: ${bountyId}`;
  const commitHash = await createVerificationCommit(repo, verificationMessage);
  
  // 2. Generate cryptographic proof
  const proof = await signMessage(
    `${username}:${repo}:${commitHash}:${bountyId}`,
    privateKey // EXAMPLE: Private key for signing
  );
  
  return {
    username,
    repositoryUrl: `https://github.com/${username}/${repo}`, // EXAMPLE: GitHub repository URL
    commitHash, // EXAMPLE: Git commit hash
    verificationProof: proof // EXAMPLE: Cryptographic proof
  };
}

// Add to bounty metadata
const identityAttestations = {
  "github": `${username}:${repo}:${commitHash}`, // EXAMPLE: GitHub attestation string
  "github_proof": verificationProof // EXAMPLE: Verification proof
};
```

---

## Submission Process

The submission process allows providers to submit solutions to bounties through the public submission pool, with proper task state management and DAG context linking.

### 2.1 Provider Solution Submission

```protobuf
// Solution Submission Request
KeystoneSubmitSolutionRequest {
  solution_descriptor: {
    uri: "ipfs://QmSolutionAgent123", // EXAMPLE: IPFS solution URI
    content_type: "application/json",
    content_length: 1024,
    content_hash: "sha256_hash_of_solution_bytes", // EXAMPLE: Solution content hash
    metadata: {
      "agent_version": "1.2.0", // EXAMPLE: Agent version number
      "deployment_ready": "true",
      "test_coverage": "95%" // EXAMPLE: Test coverage percentage
    }
  },
  
  comment_descriptor: {
    uri: "ipfs://QmSubmissionNotes123", // EXAMPLE: IPFS submission notes URI
    content_type: "text/markdown",
    content_length: 512,
    content_hash: "sha256_hash_of_comments_bytes" // EXAMPLE: Comments content hash
  }
}
```

### 2.2 KeystoneSubmission with Task States

```protobuf
// Submission Entry in Contract Pool
KeystoneSubmission {
  solution_descriptor: {
    uri: "ipfs://QmSolutionAgent123", // EXAMPLE: IPFS solution URI
    content_type: "application/json",
    content_length: 1024,
    content_hash: "sha256_hash_of_solution_bytes" // EXAMPLE: Solution content hash
  },
  
  provider_address: "0x742d35cc6554c2c1494f7f374cc1d8e66746b4a1", // EXAMPLE: Provider Ethereum address
  submission_time: "2024-03-15T10:30:00Z", // EXAMPLE: ISO 8601 timestamp
  
  comment_descriptor: {
    uri: "ipfs://QmSubmissionNotes123", // EXAMPLE: IPFS submission notes URI
    content_type: "text/markdown",
    content_length: 512,
    content_hash: "sha256_hash_of_comments_bytes" // EXAMPLE: Comments content hash
  },
  
  // A2A TaskState integration
  status: TASK_STATE_SUBMITTED // Initial state: 1
}
```

### 2.3 Task State Progression

```typescript
// Task State Management for Bounty Submissions
enum TaskState {
  TASK_STATE_SUBMITTED = 1,    // Solution submitted to pool
  TASK_STATE_WORKING = 2,      // Under review/testing
  TASK_STATE_COMPLETED = 3,    // Successfully completed
  TASK_STATE_FAILED = 4,       // Failed review/testing
  TASK_STATE_REJECTED = 7      // Rejected by issuer
}

// Update submission status
async function updateSubmissionStatus(
  bountyContract: ethers.Contract,
  submissionId: string,
  newStatus: TaskState,
  statusMessage?: string
) {
  const updateRequest = {
    submission_id: submissionId,
    new_status: newStatus,
    status_message: statusMessage || "",
    timestamp: new Date().toISOString()
  };
  
  const tx = await bountyContract.updateSubmissionStatus(updateRequest);
  return await tx.wait();
}
```

### 2.4 Linking Submissions to Bounty Context via DAG References

```protobuf
// Submission with Context DAG References
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_submission_content_bytes",
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  // Public reference to the original bounty
  public_references: [
    {
      content_hash: "sha256_hash_of_bounty_content_bytes",
      group_id: "bounty_group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_REPLY_TO,
      annotation: "Solution submission for DeFi risk bounty"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_submission_content_hex",
      encrypted_key_material: "encrypted_cek_for_bounty_group"
    }
  ],
  
  message: "encrypted_submission_bytes",
  
  metadata: {
    "author": "provider@agent-lab.io", // EXAMPLE: Provider email
    "timestamp": "2024-03-15T10:30:00Z", // EXAMPLE: ISO 8601 timestamp
    "submission_type": "agent_solution",
    "bounty_id": "1001" // EXAMPLE: Bounty ID
  }
}

// Submission Content (decrypted)
KeystoneCoreMessage {
  content_descriptor: {
    uri: "ipfs://QmSolutionAgent123",
    content_type: "application/json",
    content_length: 1024,
    content_hash: "sha256_hash_of_submission_content_bytes"
  },
  
  // Private context references for detailed relationships
  context_references: [
    {
      content_hash: "sha256_hash_of_bounty_content_bytes",
      group_id: "bounty_group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_REPLY_TO,
      annotation: "Addresses requirements in original bounty"
    },
    {
      content_hash: "sha256_hash_of_test_results_bytes",
      group_id: "bounty_group_1", 
      reference_type: CONTEXT_REFERENCE_TYPE_EXTENDS,
      annotation: "Test results and performance metrics"
    }
  ],
  
  metadata: {
    "solution_type": "agent_implementation",
    "github_repo": "https://github.com/provider/defi-risk-agent", // EXAMPLE: GitHub repository URL
    "deployment_instructions": "included",
    "license": "MIT"
  }
}
```

---

## Award and Settlement

The award process involves selection criteria evaluation, automatic fund transfer, NFT minting, and succession record creation.

### 3.1 Selection Criteria and Award Process

```typescript
// Automated Selection Criteria Evaluation
interface SelectionCriteria {
  technicalScore: number;      // 0-10 based on requirements match
  reputationScore: number;     // Provider's historical performance
  timelinessScore: number;     // Submission timing factor
  communityVotes: number;      // Optional community validation
}

async function evaluateSubmission(
  submission: KeystoneSubmission,
  bountyRequirements: Map<string, string>
): Promise<SelectionCriteria> {
  // 1. Technical evaluation against requirements
  const technicalScore = await evaluateTechnicalRequirements(
    submission.solution_descriptor,
    bountyRequirements
  );
  
  // 2. Provider reputation lookup
  const reputationScore = await getProviderReputation(
    submission.provider_address
  );
  
  // 3. Timeline factor (earlier submissions get slight bonus)
  const timelinessScore = calculateTimelinessScore(
    submission.submission_time,
    bountyRequirements.get("submission_deadline")
  );
  
  // 4. Community validation (if enabled)
  const communityVotes = await getCommunityVotes(submission);
  
  return {
    technicalScore,
    reputationScore,
    timelinessScore,
    communityVotes
  };
}
```

### 3.2 Award Bounty and Fund Transfer

```javascript
// Award Selection and Execution
async function awardBounty(
  bountyContract: ethers.Contract,
  winningProviderAddress: string, // EXAMPLE: Winner's Ethereum address
  selectionRationale: string // EXAMPLE: Human-readable rationale
) {
  const awardRequest = {
    winning_provider_address: winningProviderAddress
  };
  
  // Execute award - this triggers:
  // 1. ERC-20 reward transfer to provider
  // 2. Bounty NFT transfer to issuer
  // 3. Contract state update to COMPLETED
  const tx = await bountyContract.awardBounty(awardRequest);
  const receipt = await tx.wait();
  
  // Log award details
  const awardEvent = receipt.events.find(e => e.event === 'BountyAwarded');
  console.log('Award Details:', {
    provider: awardEvent.args.provider, // EXAMPLE: Provider address from event
    rewardAmount: awardEvent.args.reward_amount, // EXAMPLE: Reward amount from event
    tokenId: awardEvent.args.bounty_token_id, // EXAMPLE: NFT token ID from event
    rationale: selectionRationale
  });
  
  return receipt;
}
```

### 3.3 Automatic NFT Minting and Succession Records

```protobuf
// Succession Record for Completed Bounty
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_completion_record_bytes",
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  // References to bounty and winning submission
  public_references: [
    {
      content_hash: "sha256_hash_of_original_bounty_bytes",
      group_id: "bounty_group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_SUCCESSION,
      annotation: "Bounty completion record"
    },
    {
      content_hash: "sha256_hash_of_winning_submission_bytes",
      group_id: "bounty_group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Winning solution"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_completion_record_hex",
      encrypted_key_material: "encrypted_cek_for_public_group"
    }
  ],
  
  message: "encrypted_completion_record_bytes",
  
  metadata: {
    "completion_timestamp": "2024-04-01T15:00:00Z", // EXAMPLE: ISO 8601 completion timestamp
    "award_amount": "10000000000000000000", // EXAMPLE: 10 tokens in wei
    "award_token": "0xA0b86a33E6441b8bA1eA3", // EXAMPLE: Token contract address
    "bounty_nft_id": "1001", // EXAMPLE: NFT token ID
    "provider_address": "0x742d35cc6554c2c1494f7f374cc1d8e66746b4a1" // EXAMPLE: Provider Ethereum address
  }
}
```

### 3.4 NFT Metadata and Provenance

```json
// Bounty NFT Metadata (ERC-721 compliant)
{
  "name": "Keystone Bounty #1001: DeFi Risk Assessment", // EXAMPLE: NFT display name
  "description": "Completed bounty for DeFi risk assessment agent capable of analyzing Compound v3 and Aave v3 protocols", // EXAMPLE: NFT description
  "image": "ipfs://QmBountyImage123", // EXAMPLE: IPFS image URI
  "attributes": [
    {
      "trait_type": "Category",
      "value": "foundational"
    },
    {
      "trait_type": "Domain",
      "value": "defi"
    },
    {
      "trait_type": "Reward Amount",
      "value": "10 USDC" // EXAMPLE: Reward amount display
    },
    {
      "trait_type": "Completion Date",
      "value": "2024-04-01" // EXAMPLE: Completion date
    },
    {
      "trait_type": "Provider",
      "value": "0x742d35cc6554c2c1494f7f374cc1d8e66746b4a1" // EXAMPLE: Provider Ethereum address
    }
  ],
  "keystone_metadata": {
    "bounty_hash": "0x1234567890abcdef...", // EXAMPLE: Original bounty hash
    "solution_hash": "0xfedcba0987654321...", // EXAMPLE: Winning solution hash
    "completion_proof": "0x789...abc" // EXAMPLE: Completion proof hash
  }
}
```

---

## Genesis Event Support

The Genesis Event represents the initial bootstrapping phase ("Recursion 1") where foundational agents and infrastructure are established to enable subsequent autonomous growth and specialization.

### 4.1 Recursion 1 Requirements

The Genesis Event bounty system supports the initial emergence phase by:

1. **Strategist Agent Development**: Creating portfolio management agents that balance foundational vs exploratory initiatives
2. **Core Infrastructure**: Establishing essential protocol agents and tools
3. **Bootstrap Economics**: Providing initial liquidity and incentive structures
4. **Capability Mapping**: Defining the semantic URI space for agent capabilities

```protobuf
// Genesis Event Bounty Template
KeystoneBountyMetadata {
  required_capability_uri: "https://schemas.postfiat.org/genesis/strategist-agent/v1", // EXAMPLE: Genesis capability URI
  triggering_context_hash: "0x0000000000000000...", // EXAMPLE: Genesis trigger hash
  submission_deadline: "2024-12-31T23:59:59Z", // EXAMPLE: ISO 8601 timestamp
  
  description_descriptor: {
    uri: "ipfs://QmGenesisStrategist", // EXAMPLE: IPFS genesis description URI
    content_type: "text/markdown",
    content_length: 8192,
    content_hash: "sha256_hash_of_genesis_brief_bytes" // EXAMPLE: Content hash
  },
  
  requirements: {
    "portfolio_optimization": "pareto_efficient",
    "risk_management": "value_at_risk_model",
    "foundational_allocation": "60-80%",
    "exploratory_allocation": "20-40%",
    "rebalancing_frequency": "weekly",
    "market_cap_threshold": "1000000" // EXAMPLE: $1M minimum for decisions
  },
  
  categories: ["genesis", "foundational", "strategist"],
  
  identity_attestations: {
    "genesis_validator": "keystone_protocol_foundation", // EXAMPLE: Foundation validator
    "audit_firm": "trail_of_bits", // EXAMPLE: Security audit firm
    "economic_review": "a16z_crypto" // EXAMPLE: Economic review organization
  },
  
  deliverable_type: "agent"
}
```

### 4.2 Strategist Agent Integration

```typescript
// Strategist Agent Capability Definition
interface StrategistAgentCapabilities {
  // Portfolio management functions
  assessMarketConditions(): Promise<MarketState>;
  optimizeBountyPortfolio(currentBounties: Bounty[]): Promise<PortfolioAllocation>;
  rebalanceAllocations(targetRatios: AllocationRatios): Promise<RebalanceActions>;
  
  // Risk management
  calculateVaR(positions: Position[], confidence: number): Promise<number>;
  assessBountyRisk(bounty: Bounty): Promise<RiskMetrics>;
  
  // Strategic planning
  identifyGaps(currentCapabilities: string[]): Promise<string[]>;
  prioritizeBounties(candidates: Bounty[]): Promise<Bounty[]>;
}

// Integration with A2A Agent Discovery
const strategistAgentCard: AgentCard = {
  protocol_version: "1.0.0",
  name: "Genesis Strategist Agent", // EXAMPLE: Agent display name
  description: "Portfolio optimization agent for Keystone bounty ecosystem", // EXAMPLE: Agent description
  url: "https://strategist.keystone.protocol", // EXAMPLE: Agent service URL
  preferred_transport: "JSONRPC",
  
  provider: {
    url: "https://keystone.protocol", // EXAMPLE: Provider organization URL
    organization: "Keystone Protocol Foundation" // EXAMPLE: Organization name
  },
  
  version: "1.0.0", // EXAMPLE: Agent version
  documentation_url: "https://docs.keystone.protocol/strategist", // EXAMPLE: Documentation URL
  
  capabilities: {
    streaming: true,
    push_notifications: true,
    extensions: []
  },
  
  skills: [
    {
      id: "portfolio_optimization",
      name: "Bounty Portfolio Optimization",
      description: "Optimize allocation between foundational and exploratory bounties",
      tags: ["portfolio", "optimization", "strategy"],
      examples: [
        "Analyze current bounty portfolio and suggest rebalancing", // EXAMPLE: Portfolio analysis example
        "Identify strategic gaps in foundational infrastructure", // EXAMPLE: Gap analysis example
        "Optimize risk-adjusted returns for bounty investments" // EXAMPLE: Optimization example
      ],
      input_modes: ["application/json", "text/plain"],
      output_modes: ["application/json", "text/markdown"]
    },
    {
      id: "risk_assessment", 
      name: "Bounty Risk Assessment",
      description: "Assess technical and economic risks of bounty proposals",
      tags: ["risk", "assessment", "due-diligence"],
      examples: [
        "Evaluate technical feasibility of DeFi protocol integration", // EXAMPLE: Technical evaluation example
        "Assess market demand for proposed capability", // EXAMPLE: Market assessment example
        "Calculate expected value and risk metrics" // EXAMPLE: Risk calculation example
      ],
      input_modes: ["application/json"],
      output_modes: ["application/json", "text/markdown"]
    }
  ],
  
  default_input_modes: ["application/json", "text/plain"],
  default_output_modes: ["application/json", "text/markdown"],
  
  security_schemes: {
    "bearer_auth": {
      http_auth_security_scheme: {
        description: "Bearer token authentication",
        scheme: "Bearer",
        bearer_format: "JWT"
      }
    }
  },
  
  security: [
    {
      schemes: {
        "bearer_auth": {
          list: []
        }
      }
    }
  ]
};
```

### 4.3 Portfolio Balancing (Foundational vs Exploratory)

```typescript
// Portfolio Balancing Algorithm
interface AllocationRatios {
  foundational: number;  // 0.6-0.8 (60-80%)
  exploratory: number;   // 0.2-0.4 (20-40%)
}

interface PortfolioMetrics {
  totalValue: bigint;
  foundationalValue: bigint;
  exploratoryValue: bigint;
  riskScore: number;
  diversificationIndex: number;
}

class StrategistAgent {
  async optimizePortfolio(
    currentBounties: Bounty[],
    targetRatios: AllocationRatios,
    constraints: PortfolioConstraints
  ): Promise<PortfolioAllocation> {
    // 1. Assess current state
    const currentMetrics = this.calculatePortfolioMetrics(currentBounties);
    
    // 2. Identify imbalances
    const foundationalRatio = Number(currentMetrics.foundationalValue) / 
                             Number(currentMetrics.totalValue);
    const exploratoryRatio = Number(currentMetrics.exploratoryValue) / 
                            Number(currentMetrics.totalValue);
    
    // 3. Generate rebalancing actions
    const actions: RebalanceAction[] = [];
    
    if (foundationalRatio < targetRatios.foundational) {
      // Need more foundational bounties
      actions.push({
        type: 'CREATE_BOUNTY',
        category: 'foundational',
        suggestedAmount: this.calculateFoundationalGap(currentMetrics, targetRatios),
        priority: 'HIGH',
        capabilities: await this.identifyFoundationalGaps(currentBounties)
      });
    }
    
    if (exploratoryRatio > targetRatios.exploratory) {
      // Too much exploratory allocation
      actions.push({
        type: 'REDUCE_ALLOCATION',
        category: 'exploratory', 
        targetReduction: this.calculateExploratoryExcess(currentMetrics, targetRatios),
        priority: 'MEDIUM'
      });
    }
    
    return {
      currentMetrics,
      targetRatios,
      recommendedActions: actions,
      expectedOutcome: this.simulateRebalancing(currentMetrics, actions)
    };
  }
  
  async identifyFoundationalGaps(currentBounties: Bounty[]): Promise<string[]> {
    const requiredCapabilities = [
      "https://schemas.postfiat.org/capabilities/identity/verification/v1", // EXAMPLE: Identity verification capability URI
      "https://schemas.postfiat.org/capabilities/payment/cross-chain/v1", // EXAMPLE: Cross-chain payment capability URI
      "https://schemas.postfiat.org/capabilities/governance/voting/v1", // EXAMPLE: Governance voting capability URI
      "https://schemas.postfiat.org/capabilities/oracle/price-feeds/v1", // EXAMPLE: Price oracle capability URI
      "https://schemas.postfiat.org/capabilities/security/audit/v1" // EXAMPLE: Security audit capability URI
    ];
    
    const coveredCapabilities = currentBounties
      .filter(b => b.categories.includes('foundational'))
      .map(b => b.required_capability_uri);
    
    return requiredCapabilities.filter(cap => !coveredCapabilities.includes(cap));
  }
}
```

### 4.4 Genesis Event Preparation Examples

```protobuf
// Genesis Event Coordination Message
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_genesis_coordination_bytes",
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PUBLIC_KEY, // Public for transparency
  
  public_references: [], // Root coordination message
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "genesis_coordination_message",
      encrypted_key_material: "public_key_encrypted_for_all_participants"
    }
  ],
  
  message: "encrypted_genesis_coordination_bytes",
  
  metadata: {
    "event_type": "genesis_coordination",
    "timestamp": "2024-01-01T00:00:00Z", // EXAMPLE: Genesis event timestamp
    "phase": "recursion_1",
    "participants": "all_qualified_agents"
  }
}

// Genesis Coordination Content
KeystoneCoreMessage {
  content_descriptor: {
    uri: "ipfs://QmGenesisCoordination",
    content_type: "application/json",
    content_length: 4096,
    content_hash: "sha256_hash_of_genesis_coordination_bytes"
  },
  
  context_references: [], // No predecessors - this is genesis
  
  metadata: {
    "total_genesis_allocation": "10000000", // EXAMPLE: $10M USDC total allocation
    "foundational_target": "7000000",      // EXAMPLE: $7M (70%) for foundational
    "exploratory_target": "3000000",       // EXAMPLE: $3M (30%) for exploratory
    "initial_bounty_count": "50", // EXAMPLE: Initial number of bounties
    "strategist_agents_required": "3", // EXAMPLE: Required strategist agents
    "completion_criteria": "80% foundational capabilities covered" // EXAMPLE: Completion threshold
  }
}
```

---

## Complete End-to-End Example

### Workflow: From Genesis to Operational Ecosystem

```typescript
// 1. Genesis Event Initiation
async function initiateGenesisEvent() {
  // Deploy initial strategist agents
  const strategistBounties = await createStrategistAgentBounties();
  
  // Establish foundational infrastructure bounties
  const foundationalBounties = await createFoundationalBounties([
    "identity-verification", // EXAMPLE: Infrastructure component
    "cross-chain-payments", // EXAMPLE: Infrastructure component
    "governance-voting", // EXAMPLE: Infrastructure component
    "price-oracles", // EXAMPLE: Infrastructure component
    "security-auditing" // EXAMPLE: Infrastructure component
  ]);
  
  // Seed exploratory research bounties
  const exploratoryBounties = await createExploratoryBounties([
    "novel-consensus-mechanisms", // EXAMPLE: Research topic
    "zk-privacy-protocols", // EXAMPLE: Research topic
    "automated-market-makers", // EXAMPLE: Research topic
    "dao-governance-innovations" // EXAMPLE: Research topic
  ]);
  
  return {
    strategistBounties,
    foundationalBounties,
    exploratoryBounties,
    totalAllocation: calculateTotalAllocation([
      ...strategistBounties,
      ...foundationalBounties, 
      ...exploratoryBounties
    ])
  };
}

// 2. Submission and Evaluation Cycle
async function processSubmissionCycle(bountyId: string) {
  // Receive submissions
  const submissions = await getSubmissionsForBounty(bountyId);
  
  // Evaluate each submission
  const evaluatedSubmissions = await Promise.all(
    submissions.map(async (submission) => {
      const criteria = await evaluateSubmission(submission, bountyRequirements);
      return { submission, criteria };
    })
  );
  
  // Rank and select winner
  const rankedSubmissions = evaluatedSubmissions.sort(
    (a, b) => calculateOverallScore(b.criteria) - calculateOverallScore(a.criteria)
  );
  
  const winner = rankedSubmissions[0];
  
  // Award bounty
  const awardReceipt = await awardBounty(
    bountyContract,
    winner.submission.provider_address,
    generateSelectionRationale(winner.criteria)
  );
  
  // Create succession record
  const successionRecord = await createSuccessionRecord(
    bountyId,
    winner.submission,
    awardReceipt
  );
  
  return {
    winner: winner.submission,
    awardReceipt,
    successionRecord
  };
}

// 3. Ecosystem Evolution
async function evolveEcosystem() {
  // Strategist agents analyze current state
  const currentPortfolio = await getActivePortfolio();
  const strategistRecommendations = await strategistAgent.optimizePortfolio(
    currentPortfolio,
    { foundational: 0.7, exploratory: 0.3 },
    constraints
  );
  
  // Execute recommendations
  for (const action of strategistRecommendations.recommendedActions) {
    switch (action.type) {
      case 'CREATE_BOUNTY':
        await createBountyFromRecommendation(action);
        break;
      case 'REDUCE_ALLOCATION':
        await adjustBountyAllocations(action);
        break;
      case 'REBALANCE_PORTFOLIO':
        await rebalancePortfolio(action);
        break;
    }
  }
  
  return strategistRecommendations;
}
```

This comprehensive bounty lifecycle documentation provides the foundation for implementing a self-sustaining, cybernetic emergence system where autonomous agents can discover, bid on, complete, and create new bounties while maintaining strategic balance between foundational infrastructure development and exploratory research initiatives. 