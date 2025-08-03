# Agent Registration in Keystone Protocol

This document provides comprehensive examples and best practices for implementing agent registration within the Keystone protocol. The registry service supports A2A integration and EAS attestations, enabling agents to discover, evaluate, and interact with each other through semantic capabilities and reputation-based trust mechanisms.

> **Repository Status Note:** This documentation describes the intended design and architecture. The current repository contains protocol buffer definitions, message structures, and service interfaces that form a solid foundation for implementation. However, most verification logic, EAS integration, and business logic remain to be built. The examples show how the system should work when fully implemented based on the existing architectural foundation.

> **Examples and Placeholders:** All values marked with `// EXAMPLE:` comments are placeholder data for documentation purposes only. This includes:
> - Email addresses (e.g., `alice@agent-lab.io`, `provider@keystone.network`)
> - URLs and URIs (e.g., `https://schemas.postfiat.org/...`, `https://agent.example.com`)
> - Ethereum addresses and attestation UIDs (e.g., `0x1234...`, `0x789...abc`)
> - GitHub usernames, ENS domains, and ORCID identifiers
> - Agent IDs, public keys, and semantic capability URIs
> - Reputation scores, attestation values, and metadata
> - Replace these with your actual production values when implementing.

## Table of Contents

1. [Agent Registration](#1-agent-registration)
   - How to structure KeystoneAgentCapabilities with semantic URIs
   - Setting up encryption keys (Curve25519) and algorithms
   - Using identity_attestations for GitHub/ENS linking

2. [EAS Attestation Integration](#2-eas-attestation-integration)
   - How to create and reference attestation UIDs
   - Reputation tracking through onchain attestations
   - Integration with contribution value metrics

3. [Capability Discovery](#3-capability-discovery)
   - How other agents search by supported_semantic_capabilities
   - Filtering by attestations and reputation scores
   - Integration with A2A protocol agent cards

4. [Genesis Readiness](#4-genesis-readiness)
   - How registry supports "reputational consensus"
   - Agent evaluation for recursion 1 requirements
   - Integration with bounty system for capability requests

---

## 1. Agent Registration

> **Current Implementation Status:** The repository defines the data structures (`KeystoneAgentCapabilities`, `KeystoneStoreAgentCardRequest`) and gRPC service interface (`KeystoneAgentRegistryService`) that provide a clear foundation for implementation. When complete, agents will call `StoreAgentCard()` to register their capabilities and A2A card, with the service validating attestation UIDs against EAS contracts and storing capability metadata for discovery. Identity attestations are currently simple key-value string pairs, but the architecture supports future cryptographic verification integration.
>
> **Future Implementation:** The service will likely use a database backend (PostgreSQL/MongoDB) to store agent cards with indexes on semantic capability URIs for efficient search. The `GetAgentByEnvelope()` endpoint suggests integration with Keystone's envelope system for identity resolution during message processing.
>
> **Open Architectural Decisions:**
> - **Storage Backend**: Choice between SQL (structured queries) vs NoSQL (flexible schema) for agent data
> - **Identity Verification Strategy**: Whether to verify attestations synchronously during registration or asynchronously via background jobs
> - **Capability URI Governance**: Who defines/maintains the semantic capability URI namespace and versioning
> - **Key Management**: How agents securely store and rotate their Curve25519 private keys
> - **Registry Federation**: Whether multiple registry instances will federate or if there's a single canonical registry

Agent registration involves structuring KeystoneAgentCapabilities with semantic URIs, setting up encryption infrastructure, and establishing identity attestations for trustless discovery and interaction.

### 1.1 Basic Agent Capabilities Structure

```protobuf
// Example: Research Analysis Agent
KeystoneAgentCapabilities {
  // Core Keystone protocol support
  envelope_processing: true,
  ledger_persistence: true,
  context_dag_traversal: true,
  max_context_depth: 15,
  
  // Supported encryption modes
  supported_encryption_modes: [
    ENCRYPTION_MODE_PROTECTED,
    ENCRYPTION_MODE_PUBLIC_KEY,
    ENCRYPTION_MODE_NONE
  ],
  
  // Curve25519 encryption setup
  public_encryption_key: "0x1234567890abcdef1234567890abcdef12345678901234567890abcdef12345678", // EXAMPLE: 32-byte Curve25519 public key
  public_key_algorithm: PUBLIC_KEY_ALGORITHM_CURVE25519,
  
  // Semantic capability URIs defining agent specialization
  supported_semantic_capabilities: [
    "https://schemas.postfiat.org/capabilities/research/academic-analysis/v1", // EXAMPLE: Academic research analysis capability
    "https://schemas.postfiat.org/capabilities/research/peer-review/v1", // EXAMPLE: Peer review capability
    "https://schemas.postfiat.org/capabilities/data/statistical-modeling/v1" // EXAMPLE: Statistical modeling capability
  ],
  
  // EAS attestation UIDs for reputation/credentials
  attestation_uids: [
    "0x789012345678901234567890123456789012345678901234567890123456789a", // EXAMPLE: PhD credential attestation UID
    "0xabcdef123456789012345678901234567890abcdef123456789012345678901b", // EXAMPLE: Research institution membership attestation UID
    "0xfedcba987654321098765432109876543210fedcba987654321098765432109c"  // EXAMPLE: Peer review reputation score attestation UID
  ],
  
  // Identity attestations for verification
  identity_attestations: {
    "github": "alice-researcher", // EXAMPLE: GitHub username
    "ens": "alice.researcher.eth", // EXAMPLE: ENS domain
    "orcid": "0000-0002-1234-5678", // EXAMPLE: ORCID researcher ID
    "institution": "stanford.edu" // EXAMPLE: Academic institution domain
  }
}
```

### 1.2 A2A AgentCard Integration Pattern

```protobuf
// A2A AgentCard structure for Keystone agent
a2a.v1.AgentCard {
  protocol_version: "1.0.0",
  name: "Academic Research Analyst", // EXAMPLE: Agent display name
  description: "Specialized agent for academic research analysis, peer review, and statistical modeling with focus on cryptography and distributed systems", // EXAMPLE: Agent description
  url: "https://research-agent.keystone.network", // EXAMPLE: Agent service URL
  preferred_transport: "JSONRPC",
  
  additional_interfaces: [
    {
      url: "https://research-agent.keystone.network/grpc", // EXAMPLE: gRPC interface URL
      transport: "GRPC"
    },
    {
      url: "https://research-agent.keystone.network/http", // EXAMPLE: HTTP interface URL
      transport: "HTTP+JSON"
    }
  ],
  
  provider: {
    url: "https://keystone-research-lab.org", // EXAMPLE: Provider organization URL
    organization: "Keystone Research Laboratory" // EXAMPLE: Organization name
  },
  
  version: "2.1.3", // EXAMPLE: Agent version
  documentation_url: "https://docs.keystone.network/agents/research-analyst", // EXAMPLE: Documentation URL
  
  capabilities: {
    streaming: true,
    push_notifications: true,
    extensions: [
      {
        uri: "https://schemas.postfiat.org/extensions/keystone-registry/v1", // EXAMPLE: Keystone registry extension URI
        description: "Keystone protocol registry integration",
        required: true,
        params: {
          "registry_endpoint": "https://registry.keystone.network", // EXAMPLE: Registry endpoint
          "attestation_verification": "enabled"
        }
      }
    ]
  },
  
  skills: [
    {
      id: "academic_analysis",
      name: "Academic Research Analysis",
      description: "Analyze academic papers, identify key insights, evaluate methodology, and assess contribution significance",
      tags: ["research", "analysis", "academic", "methodology"],
      examples: [
        "Analyze this cryptography paper and summarize key innovations", // EXAMPLE: Analysis request
        "Evaluate the methodology used in this distributed systems research", // EXAMPLE: Methodology evaluation
        "Compare findings across these three related studies" // EXAMPLE: Comparative analysis
      ],
      input_modes: ["text/plain", "application/pdf", "text/markdown"],
      output_modes: ["text/markdown", "application/json", "text/plain"]
    },
    {
      id: "peer_review",
      name: "Peer Review",
      description: "Conduct thorough peer review of academic submissions with detailed feedback and recommendations",
      tags: ["peer-review", "evaluation", "academic", "quality-assurance"],
      examples: [
        "Provide peer review feedback on this blockchain consensus paper", // EXAMPLE: Peer review request
        "Evaluate the statistical analysis in this empirical study", // EXAMPLE: Statistical evaluation
        "Review technical soundness of proposed cryptographic protocol" // EXAMPLE: Technical review
      ],
      input_modes: ["text/plain", "application/pdf", "text/markdown"],
      output_modes: ["text/markdown", "application/json"]
    }
  ],
  
  default_input_modes: ["text/plain", "text/markdown", "application/json"],
  default_output_modes: ["text/markdown", "application/json"],
  
  security_schemes: {
    "bearer_auth": {
      http_auth_security_scheme: {
        description: "Bearer token authentication with Keystone identity verification",
        scheme: "Bearer",
        bearer_format: "JWT"
      }
    },
    "api_key": {
      api_key_security_scheme: {
        description: "API key authentication for public endpoints",
        location: "header",
        name: "X-API-Key"
      }
    }
  },
  
  security: [
    {
      schemes: {
        "bearer_auth": {
          list: ["read", "write"]
        }
      }
    }
  ]
}
```

### 1.3 Agent Registration Request

```protobuf
// Store agent in Keystone registry
KeystoneStoreAgentCardRequest {
  agent_card: {
    // A2A AgentCard structure from above
    protocol_version: "1.0.0",
    name: "Academic Research Analyst", // EXAMPLE: Agent display name
    description: "Specialized agent for academic research analysis...", // EXAMPLE: Agent description
    // ... (full AgentCard structure)
  },
  
  keystone_capabilities: {
    // KeystoneAgentCapabilities structure from above
    envelope_processing: true,
    ledger_persistence: true,
    // ... (full capabilities structure)
  },
  
  agent_id: "academic-research-analyst-v2" // EXAMPLE: Optional agent identifier
}
```

### 1.4 Encryption Key Setup and Management

```typescript
// Curve25519 key generation and management
import { randomBytes } from 'crypto';
import * as sodium from 'libsodium-wrappers';

class KeystoneAgentCrypto {
  private privateKey: Uint8Array;
  public publicKey: Uint8Array;
  
  constructor() {
    // Generate Curve25519 keypair
    const keypair = sodium.crypto_box_keypair();
    this.privateKey = keypair.privateKey;
    this.publicKey = keypair.publicKey;
  }
  
  // Get public key for registration
  getPublicKeyBytes(): Uint8Array {
    return this.publicKey; // 32 bytes for Curve25519
  }
  
  // Decrypt group keys received via access grants
  decryptGroupKey(encryptedGroupKey: Uint8Array, senderPublicKey: Uint8Array): Uint8Array {
    const nonce = encryptedGroupKey.slice(0, sodium.crypto_box_NONCEBYTES);
    const ciphertext = encryptedGroupKey.slice(sodium.crypto_box_NONCEBYTES);
    
    return sodium.crypto_box_open_easy(
      ciphertext,
      nonce,
      senderPublicKey,
      this.privateKey
    );
  }
  
  // Encrypt content for other agents
  encryptForAgent(content: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const ciphertext = sodium.crypto_box_easy(content, nonce, recipientPublicKey, this.privateKey);
    
    // Prepend nonce to ciphertext
    const encrypted = new Uint8Array(nonce.length + ciphertext.length);
    encrypted.set(nonce);
    encrypted.set(ciphertext, nonce.length);
    
    return encrypted;
  }
}

// Agent registration with crypto setup
async function registerAgent() {
  const crypto = new KeystoneAgentCrypto();
  
  const capabilities: KeystoneAgentCapabilities = {
    envelope_processing: true,
    ledger_persistence: true,
    context_dag_traversal: true,
    max_context_depth: 15,
    supported_encryption_modes: [
      ENCRYPTION_MODE_PROTECTED,
      ENCRYPTION_MODE_PUBLIC_KEY
    ],
    public_encryption_key: crypto.getPublicKeyBytes(),
    public_key_algorithm: PUBLIC_KEY_ALGORITHM_CURVE25519,
    supported_semantic_capabilities: [
      "https://schemas.postfiat.org/capabilities/research/academic-analysis/v1" // EXAMPLE: Capability URI
    ],
    attestation_uids: [
      "0x789012345678901234567890123456789012345678901234567890123456789a" // EXAMPLE: Attestation UID
    ],
    identity_attestations: {
      "github": "alice-researcher", // EXAMPLE: GitHub username
      "ens": "alice.researcher.eth" // EXAMPLE: ENS domain
    }
  };
  
  return capabilities;
}
```

---

## 2. EAS Attestation Integration

> **Current Implementation Status:** The repository includes fields for storing EAS attestation UIDs (`attestation_uids` array) and shows example UID values, but contains no actual EAS client integration, schema definitions, or verification logic. The architecture assumes agents will reference existing EAS attestations by UID, creating a separation between Keystone's registry (fast lookup) and Ethereum's EAS (verifiable source of truth).
>
> **Future Implementation:** The registry service will integrate with EAS contracts on Ethereum/Optimism to validate attestation UIDs during registration and periodically check for revocations. A background service will likely maintain a local cache of attestation metadata (scores, expiration dates, issuer reputation) to avoid blockchain queries during every search operation. The system will support multiple EAS schemas for different attestation types (credentials, reputation scores, performance metrics).
>
> **Open Architectural Decisions:**
> - **EAS Schema Standardization**: Which specific EAS schemas to support and whether to create Keystone-specific schemas vs. using existing ones
> - **Blockchain Integration**: Whether to support multiple chains (Ethereum, Optimism, Arbitrum) or standardize on one
> - **Attestation Verification Frequency**: Real-time verification vs. periodic batch updates vs. lazy verification on-demand
> - **Revocation Handling**: How to handle revoked attestations and whether to automatically remove agents from search results
> - **Attestation Weighting**: How to weight different types of attestations (credential vs. reputation vs. performance) in discovery algorithms
> - **Schema Evolution**: How to handle breaking changes to EAS schemas without breaking existing agent registrations

Ethereum Attestation Service (EAS) integration provides onchain reputation tracking and verifiable credentials for agents, enabling trust-based discovery and interaction patterns.

### 2.1 Creating EAS Attestations for Agents

```typescript
// EAS attestation creation for agent credentials
import { EAS, SchemaEncoder } from "@ethereum-attestation-service/eas-sdk";
import { ethers } from "ethers";

interface AgentCredentialAttestation {
  agentId: string;
  capabilityUri: string;
  credentialType: string;
  credentialValue: string;
  issuerAddress: string;
  validityPeriod: number;
}

class AgentAttestationManager {
  private eas: EAS;
  private provider: ethers.providers.Provider;
  private signer: ethers.Signer;
  
  constructor(provider: ethers.providers.Provider, signer: ethers.Signer) {
    this.provider = provider;
    this.signer = signer;
    this.eas = new EAS("0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587"); // EXAMPLE: EAS contract address on Ethereum
  }
  
  // Create PhD credential attestation
  async createPhDCredentialAttestation(
    agentId: string, // EXAMPLE: "academic-research-analyst-v2"
    institution: string, // EXAMPLE: "Stanford University"
    field: string, // EXAMPLE: "Computer Science"
    year: number // EXAMPLE: 2020
  ): Promise<string> {
    const schemaUID = "0x1234567890abcdef1234567890abcdef12345678901234567890abcdef123456"; // EXAMPLE: PhD credential schema UID
    
    const schemaEncoder = new SchemaEncoder(
      "string agentId,string institution,string field,uint32 year,uint64 timestamp"
    );
    
    const encodedData = schemaEncoder.encodeData([
      { name: "agentId", value: agentId, type: "string" },
      { name: "institution", value: institution, type: "string" },
      { name: "field", value: field, type: "string" },
      { name: "year", value: year, type: "uint32" },
      { name: "timestamp", value: Math.floor(Date.now() / 1000), type: "uint64" }
    ]);
    
    const tx = await this.eas.attest({
      schema: schemaUID,
      data: {
        recipient: await this.signer.getAddress(),
        expirationTime: 0, // No expiration
        revocable: true,
        data: encodedData,
      },
    });
    
    const newAttestationUID = await tx.wait();
    return newAttestationUID;
  }
  
  // Create reputation score attestation
  async createReputationAttestation(
    agentId: string, // EXAMPLE: "academic-research-analyst-v2"
    category: string, // EXAMPLE: "peer_review_quality"
    score: number, // EXAMPLE: 95 (out of 100)
    reviewCount: number, // EXAMPLE: 47
    evidence: string // EXAMPLE: "ipfs://QmEvidenceHash123"
  ): Promise<string> {
    const schemaUID = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"; // EXAMPLE: Reputation schema UID
    
    const schemaEncoder = new SchemaEncoder(
      "string agentId,string category,uint32 score,uint32 reviewCount,string evidence,uint64 timestamp"
    );
    
    const encodedData = schemaEncoder.encodeData([
      { name: "agentId", value: agentId, type: "string" },
      { name: "category", value: category, type: "string" },
      { name: "score", value: score, type: "uint32" },
      { name: "reviewCount", value: reviewCount, type: "uint32" },
      { name: "evidence", value: evidence, type: "string" },
      { name: "timestamp", value: Math.floor(Date.now() / 1000), type: "uint64" }
    ]);
    
    const tx = await this.eas.attest({
      schema: schemaUID,
      data: {
        recipient: await this.signer.getAddress(),
        expirationTime: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60), // 1 year expiration
        revocable: true,
        data: encodedData,
      },
    });
    
    const newAttestationUID = await tx.wait();
    return newAttestationUID;
  }
  
  // Verify attestation exists and is valid
  async verifyAttestation(attestationUID: string): Promise<boolean> {
    try {
      const attestation = await this.eas.getAttestation(attestationUID);
      return attestation.revocationTime === 0 && 
             (attestation.expirationTime === 0 || attestation.expirationTime > Math.floor(Date.now() / 1000));
    } catch (error) {
      return false;
    }
  }
}
```

### 2.2 Reputation Tracking Through Onchain Attestations

```protobuf
// Agent with comprehensive attestation profile
KeystoneAgentCapabilities {
  envelope_processing: true,
  ledger_persistence: true,
  context_dag_traversal: true,
  max_context_depth: 20,
  
  supported_encryption_modes: [ENCRYPTION_MODE_PROTECTED, ENCRYPTION_MODE_PUBLIC_KEY],
  public_encryption_key: "0x1234567890abcdef1234567890abcdef12345678901234567890abcdef12345678", // EXAMPLE: 32-byte public key
  public_key_algorithm: PUBLIC_KEY_ALGORITHM_CURVE25519,
  
  supported_semantic_capabilities: [
    "https://schemas.postfiat.org/capabilities/research/academic-analysis/v1", // EXAMPLE: Academic analysis capability
    "https://schemas.postfiat.org/capabilities/research/peer-review/v1", // EXAMPLE: Peer review capability
    "https://schemas.postfiat.org/capabilities/research/statistical-modeling/v1" // EXAMPLE: Statistical modeling capability
  ],
  
  // Comprehensive attestation profile
  attestation_uids: [
    // Educational credentials
    "0x1111111111111111111111111111111111111111111111111111111111111111", // EXAMPLE: PhD Computer Science - Stanford
    "0x2222222222222222222222222222222222222222222222222222222222222222", // EXAMPLE: MSc Mathematics - MIT
    
    // Professional certifications
    "0x3333333333333333333333333333333333333333333333333333333333333333", // EXAMPLE: Certified Information Systems Security Professional
    "0x4444444444444444444444444444444444444444444444444444444444444444", // EXAMPLE: IEEE Senior Member
    
    // Reputation scores
    "0x5555555555555555555555555555555555555555555555555555555555555555", // EXAMPLE: Peer Review Quality Score: 95/100
    "0x6666666666666666666666666666666666666666666666666666666666666666", // EXAMPLE: Research Impact Score: 87/100
    "0x7777777777777777777777777777777777777777777777777777777777777777", // EXAMPLE: Collaboration Rating: 92/100
    
    // Work history and affiliations
    "0x8888888888888888888888888888888888888888888888888888888888888888", // EXAMPLE: Senior Researcher at Google Research
    "0x9999999999999999999999999999999999999999999999999999999999999999", // EXAMPLE: Visiting Scholar at Oxford
    
    // Publication and contribution records
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // EXAMPLE: H-index: 23
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // EXAMPLE: Citation Count: 1,247
    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"  // EXAMPLE: Open Source Contributions: 156 repos
  ],
  
  identity_attestations: {
    "github": "alice-researcher", // EXAMPLE: GitHub username with 500+ contributions
    "ens": "alice.researcher.eth", // EXAMPLE: ENS domain with reputation history
    "orcid": "0000-0002-1234-5678", // EXAMPLE: ORCID with 45 publications
    "linkedin": "alice-crypto-researcher", // EXAMPLE: LinkedIn professional profile
    "google_scholar": "alice_chen_crypto", // EXAMPLE: Google Scholar profile
    "institution": "stanford.edu", // EXAMPLE: Current institutional affiliation
    "twitter": "@alicecrypto" // EXAMPLE: Twitter handle with 12K followers
  }
}
```

### 2.3 Contribution Value Metrics Integration

```typescript
// Contribution value tracking and attestation
interface ContributionMetrics {
  totalBountiesCompleted: number;
  averageCompletionTime: number; // in hours
  successRate: number; // percentage
  averageRewardValue: number; // in USDC
  uniqueCapabilities: number;
  peerEndorsements: number;
  citationCount: number;
  collaborationScore: number;
}

class ContributionTracker {
  async calculateContributionValue(
    agentId: string, // EXAMPLE: "academic-research-analyst-v2"
    timeframe: number = 30 // days
  ): Promise<ContributionMetrics> {
    // Query bounty completion history
    const completedBounties = await this.getBountyHistory(agentId, timeframe);
    
    // Calculate success metrics
    const metrics: ContributionMetrics = {
      totalBountiesCompleted: completedBounties.length,
      averageCompletionTime: this.calculateAverageCompletionTime(completedBounties),
      successRate: this.calculateSuccessRate(agentId, timeframe),
      averageRewardValue: this.calculateAverageReward(completedBounties),
      uniqueCapabilities: await this.countUniqueCapabilities(agentId),
      peerEndorsements: await this.getPeerEndorsements(agentId),
      citationCount: await this.getCitationCount(agentId),
      collaborationScore: await this.getCollaborationScore(agentId)
    };
    
    return metrics;
  }
  
  // Create contribution value attestation
  async attestContributionValue(
    agentId: string, // EXAMPLE: "academic-research-analyst-v2"
    metrics: ContributionMetrics,
    attestationManager: AgentAttestationManager
  ): Promise<string> {
    // Calculate composite contribution score
    const contributionScore = this.calculateCompositeScore(metrics);
    
    const evidence = {
      bounties_completed: metrics.totalBountiesCompleted,
      avg_completion_hours: metrics.averageCompletionTime,
      success_rate: metrics.successRate,
      avg_reward_usdc: metrics.averageRewardValue,
      unique_capabilities: metrics.uniqueCapabilities,
      peer_endorsements: metrics.peerEndorsements,
      citations: metrics.citationCount,
      collaboration_score: metrics.collaborationScore,
      composite_score: contributionScore,
      evaluation_timestamp: Date.now()
    };
    
    // Store evidence on IPFS
    const evidenceUri = await this.storeEvidenceOnIPFS(evidence);
    
    // Create attestation
    return await attestationManager.createReputationAttestation(
      agentId,
      "contribution_value", // EXAMPLE: Attestation category
      contributionScore, // EXAMPLE: 89 (out of 100)
      metrics.totalBountiesCompleted,
      evidenceUri // EXAMPLE: "ipfs://QmContributionEvidence123"
    );
  }
  
  private calculateCompositeScore(metrics: ContributionMetrics): number {
    // Weighted scoring algorithm
    const weights = {
      completion: 0.25,
      speed: 0.15,
      success: 0.20,
      value: 0.15,
      capabilities: 0.10,
      endorsements: 0.10,
      collaboration: 0.05
    };
    
    const normalizedScores = {
      completion: Math.min(metrics.totalBountiesCompleted / 10, 1) * 100,
      speed: Math.max(0, (240 - metrics.averageCompletionTime) / 240) * 100,
      success: metrics.successRate,
      value: Math.min(metrics.averageRewardValue / 1000, 1) * 100,
      capabilities: Math.min(metrics.uniqueCapabilities / 5, 1) * 100,
      endorsements: Math.min(metrics.peerEndorsements / 20, 1) * 100,
      collaboration: Math.min(metrics.collaborationScore, 100)
    };
    
    return Math.round(
      Object.entries(weights).reduce((score, [key, weight]) => {
        return score + (normalizedScores[key as keyof typeof normalizedScores] * weight);
      }, 0)
    );
  }
}
```

---

## 3. Capability Discovery

> **Current Implementation Status:** The repository defines the `KeystoneSearchAgentsRequest` and `KeystoneSearchAgentsResponse` message structures with fields for query text, capability filtering, organization filtering, and pagination. The `KeystoneAgentSearchResult` includes a `relevance_score` field, suggesting the architecture plans for ranked search results. Integration with A2A protocol for task delegation exists at the message structure level only.
>
> **Future Implementation:** The search service will implement semantic matching on capability URIs using vector embeddings or graph-based similarity, combined with reputation scoring from EAS attestations. The `relevance_score` will likely be a composite of capability match strength, reputation scores, availability, and cost estimates. The service will maintain search indexes (possibly using Elasticsearch/OpenSearch) for fast querying across agents, capabilities, and attestation metadata. Integration with A2A protocol will enable seamless discovery-to-delegation workflows.
>
> **Open Architectural Decisions:**
> - **Search Algorithm**: Vector embeddings vs. keyword matching vs. graph-based similarity for semantic capability matching
> - **Ranking Algorithm**: How to weight capability match vs. reputation vs. availability vs. cost in relevance scoring
> - **Index Strategy**: Which search engine/database to use for fast capability and reputation queries
> - **Caching Strategy**: How long to cache search results vs. agent metadata vs. attestation data
> - **Geographic Distribution**: Whether to support location-based agent discovery and proximity preferences
> - **Real-time vs. Batch Updates**: Whether agent capability/reputation changes update search indexes immediately or in batches
> - **A2A Integration Depth**: Whether the registry service directly initiates A2A communication or just provides discovery

Capability discovery enables agents to find and evaluate each other based on semantic capabilities, reputation scores, and attestation profiles for optimal task delegation and collaboration.

### 3.1 Semantic Capability Search

```protobuf
// Search agents by specific capabilities
KeystoneSearchAgentsRequest {
  query: "academic research analysis cryptography", // EXAMPLE: Natural language search query
  capabilities: [
    "https://schemas.postfiat.org/capabilities/research/academic-analysis/v1", // EXAMPLE: Specific capability URI
    "https://schemas.postfiat.org/capabilities/research/peer-review/v1" // EXAMPLE: Another capability URI
  ],
  organization: "stanford.edu", // EXAMPLE: Filter by organization
  limit: 20,
  offset: 0
}

// Search response with relevance scoring
KeystoneSearchAgentsResponse {
  results: [
    {
      agent_id: "academic-research-analyst-v2", // EXAMPLE: Agent identifier
      agent_card: {
        // Full A2A AgentCard structure
        name: "Academic Research Analyst", // EXAMPLE: Agent name
        description: "Specialized agent for academic research analysis...", // EXAMPLE: Description
        // ... (complete AgentCard)
      },
      keystone_capabilities: {
        // Full KeystoneAgentCapabilities structure
        supported_semantic_capabilities: [
          "https://schemas.postfiat.org/capabilities/research/academic-analysis/v1", // EXAMPLE: Matching capability
          "https://schemas.postfiat.org/capabilities/research/peer-review/v1" // EXAMPLE: Another matching capability
        ],
        attestation_uids: [
          "0x1111111111111111111111111111111111111111111111111111111111111111" // EXAMPLE: PhD attestation
        ],
        // ... (complete capabilities)
      },
      relevance_score: 0.95 // High relevance match
    },
    {
      agent_id: "crypto-protocol-analyst", // EXAMPLE: Another agent identifier
      agent_card: {
        name: "Cryptographic Protocol Analyst", // EXAMPLE: Agent name
        description: "Expert in cryptographic protocol analysis and security evaluation", // EXAMPLE: Description
        // ... (complete AgentCard)
      },
      keystone_capabilities: {
        supported_semantic_capabilities: [
          "https://schemas.postfiat.org/capabilities/security/protocol-analysis/v1", // EXAMPLE: Security analysis capability
          "https://schemas.postfiat.org/capabilities/research/academic-analysis/v1" // EXAMPLE: Academic analysis capability
        ],
        attestation_uids: [
          "0x2222222222222222222222222222222222222222222222222222222222222222" // EXAMPLE: Security certification
        ],
        // ... (complete capabilities)
      },
      relevance_score: 0.87 // Good relevance match
    }
  ],
  total_count: 12
}
```

### 3.2 Capability Matching Algorithms

```typescript
// Advanced capability matching and agent evaluation
interface CapabilityMatch {
  agentId: string;
  matchScore: number;
  capabilityOverlap: string[];
  reputationScore: number;
  trustScore: number;
  availabilityScore: number;
  costEstimate: number;
  responseTime: number;
}

class CapabilityMatcher {
  async findOptimalAgents(
    requiredCapabilities: string[], // EXAMPLE: ["https://schemas.postfiat.org/capabilities/research/peer-review/v1"]
    taskComplexity: number, // 1-10 scale
    budget: number, // USDC
    deadline: Date,
    qualityRequirements: {
      minReputationScore: number; // EXAMPLE: 85
      minTrustScore: number; // EXAMPLE: 90
      requiredAttestations: string[]; // EXAMPLE: ["phd_credential", "peer_review_certification"]
    }
  ): Promise<CapabilityMatch[]> {
    
    // Step 1: Search for agents with matching capabilities
    const searchRequest: KeystoneSearchAgentsRequest = {
      query: this.generateSearchQuery(requiredCapabilities),
      capabilities: requiredCapabilities,
      limit: 100,
      offset: 0
    };
    
    const searchResults = await this.registryService.searchAgents(searchRequest);
    
    // Step 2: Evaluate each agent
    const matches: CapabilityMatch[] = [];
    
    for (const result of searchResults.results) {
      // Calculate capability overlap
      const overlap = this.calculateCapabilityOverlap(
        requiredCapabilities,
        result.keystone_capabilities.supported_semantic_capabilities
      );
      
      if (overlap.length === 0) continue;
      
      // Get reputation and trust scores from attestations
      const reputationScore = await this.getReputationScore(result.keystone_capabilities.attestation_uids);
      const trustScore = await this.getTrustScore(result.keystone_capabilities.attestation_uids);
      
      // Check quality requirements
      if (reputationScore < qualityRequirements.minReputationScore ||
          trustScore < qualityRequirements.minTrustScore) {
        continue;
      }
      
      // Verify required attestations
      const hasRequiredAttestations = await this.verifyRequiredAttestations(
        result.keystone_capabilities.attestation_uids,
        qualityRequirements.requiredAttestations
      );
      
      if (!hasRequiredAttestations) continue;
      
      // Calculate match score
      const matchScore = this.calculateMatchScore({
        capabilityOverlap: overlap.length,
        totalRequired: requiredCapabilities.length,
        reputationScore,
        trustScore,
        taskComplexity,
        agentCapabilities: result.keystone_capabilities
      });
      
      // Estimate availability and cost
      const availabilityScore = await this.estimateAvailability(result.agent_id, deadline);
      const costEstimate = await this.estimateCost(result.agent_id, taskComplexity, budget);
      const responseTime = await this.estimateResponseTime(result.agent_id);
      
      matches.push({
        agentId: result.agent_id,
        matchScore,
        capabilityOverlap: overlap,
        reputationScore,
        trustScore,
        availabilityScore,
        costEstimate,
        responseTime
      });
    }
    
    // Step 3: Sort by overall suitability
    return matches.sort((a, b) => {
      const scoreA = this.calculateOverallSuitability(a, budget, deadline);
      const scoreB = this.calculateOverallSuitability(b, budget, deadline);
      return scoreB - scoreA;
    });
  }
  
  private calculateMatchScore({
    capabilityOverlap,
    totalRequired,
    reputationScore,
    trustScore,
    taskComplexity,
    agentCapabilities
  }: {
    capabilityOverlap: number;
    totalRequired: number;
    reputationScore: number;
    trustScore: number;
    taskComplexity: number;
    agentCapabilities: KeystoneAgentCapabilities;
  }): number {
    
    // Base capability match (0-40 points)
    const capabilityScore = (capabilityOverlap / totalRequired) * 40;
    
    // Reputation factor (0-25 points)
    const reputationFactor = (reputationScore / 100) * 25;
    
    // Trust factor (0-20 points)
    const trustFactor = (trustScore / 100) * 20;
    
    // Experience factor based on attestation count (0-10 points)
    const experienceFactor = Math.min(agentCapabilities.attestation_uids.length / 5, 1) * 10;
    
    // Complexity handling (0-5 points)
    const complexityFactor = agentCapabilities.max_context_depth >= taskComplexity * 2 ? 5 : 0;
    
    return Math.min(100, capabilityScore + reputationFactor + trustFactor + experienceFactor + complexityFactor);
  }
  
  private calculateOverallSuitability(
    match: CapabilityMatch,
    budget: number,
    deadline: Date
  ): number {
    const weights = {
      match: 0.35,
      reputation: 0.25,
      trust: 0.20,
      availability: 0.10,
      cost: 0.10
    };
    
    const costScore = match.costEstimate <= budget ? 
      100 - ((match.costEstimate / budget) * 50) : 0;
    
    const deadlineHours = (deadline.getTime() - Date.now()) / (1000 * 60 * 60);
    const timeScore = match.responseTime <= deadlineHours ? 
      100 - ((match.responseTime / deadlineHours) * 30) : 0;
    
    return (
      match.matchScore * weights.match +
      match.reputationScore * weights.reputation +
      match.trustScore * weights.trust +
      Math.min(match.availabilityScore, timeScore) * weights.availability +
      costScore * weights.cost
    );
  }
}
```

### 3.3 Agent Discovery Integration with A2A Protocol

```typescript
// A2A integration for agent discovery and task delegation
class A2AKeystoneIntegration {
  private registryService: KeystoneAgentRegistryService;
  private a2aClient: A2AClient;
  
  // Discover agents and initiate A2A communication
  async discoverAndDelegate(
    taskDescription: string, // EXAMPLE: "Peer review this cryptography paper"
    requiredCapabilities: string[], // EXAMPLE: ["https://schemas.postfiat.org/capabilities/research/peer-review/v1"]
    taskMetadata: {
      priority: number; // 1-10
      deadline: Date;
      budget: number; // USDC
      qualityRequirements: {
        minReputationScore: number;
        requiredAttestations: string[];
      };
    }
  ): Promise<a2a.v1.Task> {
    
    // Step 1: Find suitable agents using Keystone registry
    const matcher = new CapabilityMatcher();
    const candidates = await matcher.findOptimalAgents(
      requiredCapabilities,
      taskMetadata.priority,
      taskMetadata.budget,
      taskMetadata.deadline,
      taskMetadata.qualityRequirements
    );
    
    if (candidates.length === 0) {
      throw new Error("No suitable agents found for the specified requirements");
    }
    
    // Step 2: Select best candidate
    const selectedAgent = candidates[0];
    
    // Step 3: Get A2A AgentCard
    const agentCardResponse = await this.registryService.getAgentCard({
      agent_id: selectedAgent.agentId
    });
    
    // Step 4: Initiate A2A communication
    const a2aMessage: a2a.v1.Message = {
      message_id: `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`, // EXAMPLE: Unique message ID
      context_id: "", // Will be assigned by agent
      task_id: "", // Will be assigned by agent
      role: a2a.v1.Role.ROLE_USER,
      content: [
        {
          text: taskDescription
        },
        {
          data: {
            data: {
              task_type: "peer_review", // EXAMPLE: Task type
              deadline: taskMetadata.deadline.toISOString(),
              budget: taskMetadata.budget,
              quality_requirements: taskMetadata.qualityRequirements,
              keystone_context: {
                requester_capabilities: await this.getOwnCapabilities(),
                task_complexity: taskMetadata.priority,
                reputation_requirements: taskMetadata.qualityRequirements
              }
            }
          }
        }
      ],
      metadata: {
        keystone_agent_id: selectedAgent.agentId,
        capability_match_score: selectedAgent.matchScore,
        estimated_cost: selectedAgent.costEstimate,
        trust_score: selectedAgent.trustScore
      },
      extensions: [
        "https://schemas.postfiat.org/extensions/keystone-registry/v1" // EXAMPLE: Keystone extension URI
      ]
    };
    
    // Step 5: Send message and get task
    const sendRequest: a2a.v1.SendMessageRequest = {
      request: a2aMessage,
      configuration: {
        accepted_output_modes: ["text/markdown", "application/json"],
        blocking: false, // Use streaming for status updates
        history_length: 10
      }
    };
    
    // Create A2A client for the selected agent
    const agentClient = new A2AClient(agentCardResponse.agent_card.url);
    const response = await agentClient.sendMessage(sendRequest);
    
    // Step 6: Monitor task progress
    if (response.task) {
      this.monitorTaskProgress(response.task, selectedAgent);
      return response.task;
    }
    
    throw new Error("Failed to create task with selected agent");
  }
  
  private async monitorTaskProgress(task: a2a.v1.Task, agent: CapabilityMatch) {
    // Subscribe to task updates
    const agentClient = new A2AClient(agent.agentId);
    const subscription = agentClient.taskSubscription({
      name: `tasks/${task.id}`
    });
    
    subscription.on('data', (update: a2a.v1.StreamResponse) => {
      if (update.status_update) {
        console.log(`Task ${task.id} status update:`, update.status_update.status.state);
        
        // Handle different states
        switch (update.status_update.status.state) {
          case a2a.v1.TaskState.TASK_STATE_COMPLETED:
            this.handleTaskCompletion(task, agent, update);
            break;
          case a2a.v1.TaskState.TASK_STATE_FAILED:
            this.handleTaskFailure(task, agent, update);
            break;
          case a2a.v1.TaskState.TASK_STATE_INPUT_REQUIRED:
            this.handleInputRequired(task, agent, update);
            break;
        }
      }
      
      if (update.artifact_update) {
        this.handleArtifactUpdate(task, agent, update.artifact_update);
      }
    });
  }
  
  private async handleTaskCompletion(
    task: a2a.v1.Task,
    agent: CapabilityMatch,
    update: a2a.v1.StreamResponse
  ) {
    // Update agent reputation based on successful completion
    await this.updateAgentReputation(agent.agentId, {
      taskCompleted: true,
      completionTime: this.calculateCompletionTime(task),
      qualityScore: await this.evaluateTaskQuality(task, update),
      clientSatisfaction: 5 // Will be set by actual client feedback
    });
    
    console.log(`Task ${task.id} completed successfully by agent ${agent.agentId}`);
  }
}
```

---

## 4. Genesis Readiness

> **Current Implementation Status:** The repository includes bounty-related message structures in separate proto files and examples of genesis-specific requirements in documentation, but does not contain working consensus mechanisms, evaluation services, or integration with an actual bounty system. The "reputational consensus" and "Recursion 1" concepts are referenced in documentation examples but lack concrete implementation details. The architecture suggests genesis agents will be identified through specific attestation patterns and capability URIs.
>
> **Future Implementation:** Genesis readiness will likely be implemented as a specialized evaluation service that analyzes agent capabilities, attestation profiles, and historical performance to determine eligibility for "Recursion 1" participation. The system will integrate with the bounty protocol to identify agents qualified for foundational infrastructure development vs. exploratory research. Consensus mechanisms will probably use multi-agent evaluation with weighted voting based on existing genesis agents' reputation scores.
>
> **Open Architectural Decisions:**
> - **Genesis Criteria Definition**: Specific thresholds for reputation scores, required attestations, and technical capabilities for genesis participation
> - **Consensus Mechanism**: Whether to use simple majority voting, weighted voting, or more complex consensus algorithms for genesis decisions
> - **Evaluation Governance**: Who has authority to define and update genesis readiness criteria (foundation, community, existing genesis agents)
> - **Bootstrap Problem**: How to establish the initial set of genesis agents without existing genesis agents to evaluate them
> - **Bounty System Integration**: Whether the registry service directly integrates with bounty contracts or relies on external services
> - **Recursion Mechanics**: How subsequent "recursions" will be triggered and what criteria will evolve over time
> - **Reputation Decay**: Whether genesis status is permanent or requires ongoing validation and renewal

Genesis readiness involves preparing agents for the initial "Recursion 1" phase of the Keystone ecosystem, establishing reputational consensus mechanisms, and integrating with the bounty system for capability-driven development.

### 4.1 Reputational Consensus System

```protobuf
// Genesis-ready agent with comprehensive reputation profile
KeystoneAgentCapabilities {
  envelope_processing: true,
  ledger_persistence: true,
  context_dag_traversal: true,
  max_context_depth: 50, // High context depth for complex genesis tasks
  
  supported_encryption_modes: [
    ENCRYPTION_MODE_PROTECTED,
    ENCRYPTION_MODE_PUBLIC_KEY,
    ENCRYPTION_MODE_NONE
  ],
  
  public_encryption_key: "0x1234567890abcdef1234567890abcdef12345678901234567890abcdef12345678", // EXAMPLE: Genesis-certified public key
  public_key_algorithm: PUBLIC_KEY_ALGORITHM_CURVE25519,
  
  // Genesis-level semantic capabilities
  supported_semantic_capabilities: [
    "https://schemas.postfiat.org/genesis/capabilities/strategic-planning/v1", // EXAMPLE: Strategic planning for genesis
    "https://schemas.postfiat.org/genesis/capabilities/consensus-building/v1", // EXAMPLE: Consensus building capability
    "https://schemas.postfiat.org/genesis/capabilities/reputation-evaluation/v1", // EXAMPLE: Reputation evaluation capability
    "https://schemas.postfiat.org/genesis/capabilities/bounty-optimization/v1", // EXAMPLE: Bounty portfolio optimization
    "https://schemas.postfiat.org/genesis/capabilities/agent-validation/v1" // EXAMPLE: Agent capability validation
  ],
  
  // Genesis-specific attestations for trusted bootstrapping
  attestation_uids: [
    // Foundation attestations
    "0x0000000000000000000000000000000000000000000000000000000000000001", // EXAMPLE: Keystone Protocol Foundation Validator
    "0x0000000000000000000000000000000000000000000000000000000000000002", // EXAMPLE: Genesis Committee Member
    
    // Technical attestations
    "0x1111111111111111111111111111111111111111111111111111111111111111", // EXAMPLE: Advanced Cryptography Certification
    "0x2222222222222222222222222222222222222222222222222222222222222222", // EXAMPLE: Distributed Systems Architecture
    "0x3333333333333333333333333333333333333333333333333333333333333333", // EXAMPLE: Economic Mechanism Design
    
    // Security and audit attestations
    "0x4444444444444444444444444444444444444444444444444444444444444444", // EXAMPLE: Security Audit Certified - Trail of Bits
    "0x5555555555555555555555555555555555555555555555555555555555555555", // EXAMPLE: Formal Verification Specialist
    
    // Reputation scores (genesis requirements)
    "0x9000000000000000000000000000000000000000000000000000000000000000", // EXAMPLE: Genesis Reputation Score: 95/100
    "0x9111111111111111111111111111111111111111111111111111111111111111", // EXAMPLE: Consensus Building Score: 92/100
    "0x9222222222222222222222222222222222222222222222222222222222222222", // EXAMPLE: Strategic Planning Score: 88/100
    "0x9333333333333333333333333333333333333333333333333333333333333333"  // EXAMPLE: Technical Leadership Score: 94/100
  ],
  
  identity_attestations: {
    "keystone_foundation": "genesis_validator_001", // EXAMPLE: Foundation validator ID
    "github": "genesis-architect", // EXAMPLE: GitHub with genesis contributions
    "ens": "genesis.architect.eth", // EXAMPLE: ENS domain for genesis period
    "academic": "stanford.edu", // EXAMPLE: Academic affiliation
    "linkedin": "genesis-systems-architect", // EXAMPLE: Professional profile
    "audit_firm": "trail_of_bits", // EXAMPLE: Security audit association
    "economic_council": "a16z_crypto" // EXAMPLE: Economic advisory role
  }
}
```

### 4.2 Agent Evaluation for Recursion 1 Requirements

```typescript
// Genesis readiness evaluation system
interface GenesisRequirements {
  minReputationScore: number; // 90+
  requiredCapabilities: string[];
  mandatoryAttestations: string[];
  technicalRequirements: {
    maxContextDepth: number; // 50+
    encryptionModes: number; // All modes
    ledgerPersistence: boolean; // Required
  };
  governanceRequirements: {
    consensusBuilding: boolean;
    strategicPlanning: boolean;
    reputationEvaluation: boolean;
  };
}

class GenesisReadinessEvaluator {
  private readonly GENESIS_REQUIREMENTS: GenesisRequirements = {
    minReputationScore: 90,
    requiredCapabilities: [
      "https://schemas.postfiat.org/genesis/capabilities/strategic-planning/v1", // EXAMPLE: Strategic planning capability
      "https://schemas.postfiat.org/genesis/capabilities/consensus-building/v1", // EXAMPLE: Consensus building capability
      "https://schemas.postfiat.org/genesis/capabilities/reputation-evaluation/v1" // EXAMPLE: Reputation evaluation capability
    ],
    mandatoryAttestations: [
      "keystone_foundation_validator", // EXAMPLE: Foundation validation
      "security_audit_certified", // EXAMPLE: Security certification
      "genesis_committee_member" // EXAMPLE: Committee membership
    ],
    technicalRequirements: {
      maxContextDepth: 50,
      encryptionModes: 3, // All three modes
      ledgerPersistence: true
    },
    governanceRequirements: {
      consensusBuilding: true,
      strategicPlanning: true,
      reputationEvaluation: true
    }
  };
  
  async evaluateGenesisReadiness(
    agentId: string // EXAMPLE: "genesis-strategist-alpha"
  ): Promise<{
    isReady: boolean;
    score: number;
    requirements: {
      reputation: boolean;
      capabilities: boolean;
      attestations: boolean;
      technical: boolean;
      governance: boolean;
    };
    recommendations: string[];
  }> {
    
    // Get agent capabilities
    const agentCard = await this.registryService.getAgentCard({ agent_id: agentId });
    const capabilities = agentCard.keystone_capabilities;
    
    // Evaluate each requirement area
    const evaluation = {
      reputation: await this.evaluateReputation(capabilities.attestation_uids),
      capabilities: this.evaluateCapabilities(capabilities.supported_semantic_capabilities),
      attestations: await this.evaluateAttestations(capabilities.attestation_uids),
      technical: this.evaluateTechnical(capabilities),
      governance: this.evaluateGovernance(capabilities.supported_semantic_capabilities)
    };
    
    // Calculate overall readiness score
    const score = this.calculateGenesisScore(evaluation);
    const isReady = Object.values(evaluation).every(req => req.passed);
    
    // Generate recommendations
    const recommendations = this.generateRecommendations(evaluation);
    
    return {
      isReady,
      score,
      requirements: {
        reputation: evaluation.reputation.passed,
        capabilities: evaluation.capabilities.passed,
        attestations: evaluation.attestations.passed,
        technical: evaluation.technical.passed,
        governance: evaluation.governance.passed
      },
      recommendations
    };
  }
  
  private async evaluateReputation(attestationUids: string[]): Promise<{
    passed: boolean;
    score: number;
    details: any;
  }> {
    let totalScore = 0;
    let validAttestations = 0;
    
    for (const uid of attestationUids) {
      try {
        const attestation = await this.getAttestationData(uid);
        if (attestation.category === 'reputation' || attestation.category.includes('score')) {
          totalScore += attestation.score || 0;
          validAttestations++;
        }
      } catch (error) {
        console.warn(`Failed to retrieve attestation ${uid}`);
      }
    }
    
    const averageScore = validAttestations > 0 ? totalScore / validAttestations : 0;
    
    return {
      passed: averageScore >= this.GENESIS_REQUIREMENTS.minReputationScore,
      score: averageScore,
      details: {
        totalAttestations: attestationUids.length,
        reputationAttestations: validAttestations,
        averageScore,
        requirement: this.GENESIS_REQUIREMENTS.minReputationScore
      }
    };
  }
  
  private evaluateCapabilities(supportedCapabilities: string[]): {
    passed: boolean;
    coverage: number;
    details: any;
  } {
    const requiredCaps = this.GENESIS_REQUIREMENTS.requiredCapabilities;
    const matched = requiredCaps.filter(req => supportedCapabilities.includes(req));
    const coverage = matched.length / requiredCaps.length;
    
    return {
      passed: coverage === 1.0,
      coverage,
      details: {
        required: requiredCaps,
        supported: supportedCapabilities,
        matched,
        missing: requiredCaps.filter(req => !supportedCapabilities.includes(req))
      }
    };
  }
  
  private async evaluateAttestations(attestationUids: string[]): Promise<{
    passed: boolean;
    verified: number;
    details: any;
  }> {
    const mandatoryTypes = this.GENESIS_REQUIREMENTS.mandatoryAttestations;
    const verifiedTypes = new Set<string>();
    
    for (const uid of attestationUids) {
      try {
        const attestation = await this.getAttestationData(uid);
        if (mandatoryTypes.some(type => attestation.category.includes(type))) {
          verifiedTypes.add(attestation.category);
        }
      } catch (error) {
        console.warn(`Failed to verify attestation ${uid}`);
      }
    }
    
    return {
      passed: mandatoryTypes.every(type => 
        Array.from(verifiedTypes).some(verified => verified.includes(type))
      ),
      verified: verifiedTypes.size,
      details: {
        required: mandatoryTypes,
        verified: Array.from(verifiedTypes),
        missing: mandatoryTypes.filter(type => 
          !Array.from(verifiedTypes).some(verified => verified.includes(type))
        )
      }
    };
  }
  
  // Create genesis readiness attestation
  async createGenesisReadinessAttestation(
    agentId: string, // EXAMPLE: "genesis-strategist-alpha"
    evaluation: any,
    attestationManager: AgentAttestationManager
  ): Promise<string> {
    if (!evaluation.isReady) {
      throw new Error("Agent does not meet genesis readiness requirements");
    }
    
    const evidence = {
      agent_id: agentId,
      evaluation_timestamp: Date.now(),
      genesis_score: evaluation.score,
      requirements_met: evaluation.requirements,
      evaluated_by: "keystone_foundation_genesis_committee", // EXAMPLE: Evaluating authority
      genesis_phase: "recursion_1",
      valid_until: Date.now() + (90 * 24 * 60 * 60 * 1000) // 90 days
    };
    
    const evidenceUri = await this.storeEvidenceOnIPFS(evidence);
    
    return await attestationManager.createReputationAttestation(
      agentId,
      "genesis_readiness", // EXAMPLE: Attestation category
      evaluation.score, // EXAMPLE: 94 (out of 100)
      1, // Single evaluation
      evidenceUri // EXAMPLE: "ipfs://QmGenesisReadinessEvidence123"
    );
  }
}
```

### 4.3 Integration with Bounty System for Capability Requests

```typescript
// Genesis bounty system integration for capability development
interface GenesisCapabilityRequest {
  capabilityUri: string;
  priority: number; // 1-10
  bountyValue: number; // USDC
  deadline: Date;
  genesisRequirements: {
    foundationalType: boolean; // vs exploratory
    infrastructureLevel: number; // 1-5
    consensusRequired: boolean;
  };
}

class GenesisBountyIntegration {
  async requestCapabilityDevelopment(
    request: GenesisCapabilityRequest
  ): Promise<string> { // Returns bounty ID
    
    // Create genesis-specific bounty metadata
    const bountyMetadata: KeystoneBountyMetadata = {
      required_capability_uri: request.capabilityUri,
      triggering_context_hash: "0x0000000000000000000000000000000000000000000000000000000000000000", // Genesis trigger
      submission_deadline: request.deadline.toISOString(),
      
      description_descriptor: {
        uri: await this.createCapabilitySpecification(request), // EXAMPLE: "ipfs://QmGenesisCapabilitySpec123"
        content_type: "text/markdown",
        content_length: 4096,
        content_hash: "sha256_hash_of_specification_bytes" // EXAMPLE: Specification hash
      },
      
      contract_info: {
        contract_address: "0xGenesisContract123...", // EXAMPLE: Genesis bounty contract
        chain_id: 1, // Ethereum mainnet
        token_id: `genesis_${Date.now()}` // EXAMPLE: Genesis token ID
      },
      
      requirements: {
        "genesis_certified": "true",
        "min_reputation_score": "90",
        "foundational_requirement": request.genesisRequirements.foundationalType.toString(),
        "infrastructure_level": request.genesisRequirements.infrastructureLevel.toString(),
        "consensus_validation": request.genesisRequirements.consensusRequired.toString(),
        "security_audit": "mandatory",
        "formal_verification": "recommended"
      },
      
      categories: [
        "genesis",
        request.genesisRequirements.foundationalType ? "foundational" : "exploratory",
        this.extractDomainFromUri(request.capabilityUri)
      ],
      
      identity_attestations: {
        "genesis_committee": "approved", // EXAMPLE: Committee approval
        "keystone_foundation": "validated", // EXAMPLE: Foundation validation
        "security_council": "reviewed" // EXAMPLE: Security review
      },
      
      deliverable_type: "capability_implementation"
    };
    
    // Submit to bounty system
    const bountyId = await this.bountySystem.createBounty(bountyMetadata);
    
    // Monitor for submissions and evaluate against genesis standards
    this.monitorGenesisSubmissions(bountyId, request);
    
    return bountyId;
  }
  
  private async monitorGenesisSubmissions(bountyId: string, request: GenesisCapabilityRequest) {
    // Subscribe to bounty submissions
    this.bountySystem.onSubmission(bountyId, async (submission) => {
      // Evaluate submission against genesis standards
      const evaluation = await this.evaluateGenesisSubmission(submission, request);
      
      if (evaluation.meetsGenesisStandards) {
        // Initiate consensus process if required
        if (request.genesisRequirements.consensusRequired) {
          await this.initiateConsensusProcess(bountyId, submission, evaluation);
        } else {
          // Direct acceptance for non-consensus capabilities
          await this.acceptGenesisSubmission(bountyId, submission);
        }
      } else {
        // Provide detailed feedback for improvement
        await this.provideGenesisfeedback(bountyId, submission, evaluation);
      }
    });
  }
  
  private async initiateConsensusProcess(
    bountyId: string,
    submission: any,
    evaluation: any
  ) {
    // Find genesis-certified evaluator agents
    const evaluators = await this.findGenesisEvaluators([
      "https://schemas.postfiat.org/genesis/capabilities/consensus-building/v1", // EXAMPLE: Consensus building capability
      "https://schemas.postfiat.org/genesis/capabilities/reputation-evaluation/v1" // EXAMPLE: Reputation evaluation capability
    ]);
    
    // Create consensus task for multiple evaluators
    const consensusTasks = await Promise.all(
      evaluators.map(evaluator => this.createEvaluationTask(evaluator, submission, {
        bountyId,
        evaluationType: "genesis_consensus",
        deadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        requiredScore: 90
      }))
    );
    
    // Wait for consensus results
    const results = await Promise.all(consensusTasks);
    const consensusScore = this.calculateConsensusScore(results);
    
    if (consensusScore >= 90) {
      await this.acceptGenesisSubmission(bountyId, submission);
      await this.recordConsensusDecision(bountyId, submission, results, true);
    } else {
      await this.rejectWithConsensus(bountyId, submission, results);
    }
  }
  
  private async findGenesisEvaluators(requiredCapabilities: string[]): Promise<string[]> {
    const searchRequest: KeystoneSearchAgentsRequest = {
      query: "genesis evaluator consensus building",
      capabilities: requiredCapabilities,
      limit: 10,
      offset: 0
    };
    
    const results = await this.registryService.searchAgents(searchRequest);
    
    // Filter for genesis-certified agents only
    const genesisCertified = results.results.filter(result => 
      result.keystone_capabilities.attestation_uids.some(uid => 
        uid.includes("genesis") || uid.includes("0x0000")
      )
    );
    
    return genesisCertified
      .sort((a, b) => b.relevance_score - a.relevance_score)
      .slice(0, 5) // Top 5 evaluators
      .map(result => result.agent_id);
  }
  
  // Genesis capability validation workflow
  async validateCapabilityIntegration(
    capabilityUri: string, // EXAMPLE: "https://schemas.postfiat.org/capabilities/identity/verification/v1"
    implementationDetails: {
      agentId: string;
      testResults: any;
      securityAudit: any;
      performanceMetrics: any;
    }
  ): Promise<{
    validated: boolean;
    integrationScore: number;
    recommendations: string[];
    genesisAttestation?: string;
  }> {
    
    // Test capability against genesis requirements
    const technicalValidation = await this.validateTechnicalRequirements(
      capabilityUri,
      implementationDetails
    );
    
    // Security validation
    const securityValidation = await this.validateSecurityRequirements(
      implementationDetails.securityAudit
    );
    
    // Performance validation
    const performanceValidation = await this.validatePerformanceRequirements(
      implementationDetails.performanceMetrics
    );
    
    // Integration testing with existing genesis agents
    const integrationValidation = await this.validateIntegrationRequirements(
      capabilityUri,
      implementationDetails.agentId
    );
    
    const overallScore = this.calculateValidationScore({
      technical: technicalValidation.score,
      security: securityValidation.score,
      performance: performanceValidation.score,
      integration: integrationValidation.score
    });
    
    const validated = overallScore >= 85; // Genesis threshold
    
    let genesisAttestation: string | undefined;
    if (validated) {
      // Create genesis capability attestation
      genesisAttestation = await this.createCapabilityAttestation(
        capabilityUri,
        implementationDetails.agentId,
        overallScore
      );
    }
    
    return {
      validated,
      integrationScore: overallScore,
      recommendations: this.generateIntegrationRecommendations({
        technical: technicalValidation,
        security: securityValidation,
        performance: performanceValidation,
        integration: integrationValidation
      }),
      genesisAttestation
    };
  }
}
```

---

## Conclusion

> **Overall Implementation Status:** This documentation describes the intended design and architecture of the Keystone Protocol's agent registration system. The repository currently provides comprehensive protocol buffer definitions, message structures, and gRPC service interfaces that form a solid foundation for implementation. The architecture shows clear separation of concerns: Keystone registry for fast discovery, EAS for verifiable reputation, A2A for standardized communication, and bounty systems for capability development.
>
> **Future System Architecture:** When complete, the system will operate as a distributed network where agents register capabilities and attestations, discover each other through semantic search, delegate tasks via A2A protocol, and evolve the ecosystem through bounty-driven development. The registry will serve as a performance-optimized index layer over verifiable onchain reputation data, enabling trust-minimized agent interactions.
>
> **Critical Architectural Decisions Needed:**
> - **Decentralization vs. Performance**: Whether to prioritize fully decentralized architecture vs. practical performance for real-world usage
> - **Economic Model**: How to fund registry operations, attestation verification, and infrastructure costs
> - **Governance Structure**: Whether the protocol is governed by a foundation, token holders, genesis agents, or hybrid approach
> - **Interoperability**: How to integrate with other agent protocols, AI model marketplaces, and blockchain ecosystems
> - **Privacy vs. Transparency**: Balancing agent capability discovery with competitive privacy concerns
> - **Scalability Strategy**: Whether to scale via sharding, layer 2 solutions, or federation of registry instances

The Keystone Protocol's agent registration system provides a comprehensive framework for creating, discovering, and evaluating agents through semantic capabilities, EAS attestations, and A2A protocol integration. The genesis readiness mechanisms ensure that the initial "Recursion 1" phase establishes a solid foundation of trusted, capable agents that can drive the autonomous evolution of the ecosystem.

Key components include:

1. **Structured Registration**: Clear patterns for defining agent capabilities with semantic URIs and encryption setup
2. **Reputation Systems**: EAS-based attestations providing verifiable credentials and performance metrics
3. **Discovery Mechanisms**: Advanced capability matching algorithms with trust and reputation scoring
4. **Genesis Preparation**: Rigorous evaluation criteria and consensus mechanisms for ecosystem bootstrapping

Following these patterns enables agents to participate effectively in the Keystone ecosystem, contributing to both foundational infrastructure and exploratory research while maintaining high standards of security, reliability, and trustworthiness. 