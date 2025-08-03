# Context DAG Patterns in Keystone Protocol

This document provides comprehensive examples and best practices for working with Context DAGs (Directed Acyclic Graphs) in the Keystone protocol. Context DAGs enable rich relationships between content while maintaining privacy and access control.

> **Repository Status Note:** The Keystone protocol provides complete protocol buffer definitions for context references and relationship types, forming a solid foundation for DAG implementation. The message structures (`KeystoneEnvelope`, `KeystoneContextReference`) and relationship types are fully defined, but the actual DAG traversal algorithms, relationship validation logic, and privacy-preserving query mechanisms remain to be implemented.

> **Encoding note:** Fields such as `content_hash` and `encrypted_key_material` are raw bytes in the wire format.  
> They are rendered here as hex- or base64-encoded strings purely for readability.
> 
> **Important:** 
> - `content_hash` fields are raw bytes (SHA-256 hash)
> - `target_id` fields are strings that can be either hex-encoded hashes or UUIDs
> - `metadata` fields are `map<string, string>` (key-value pairs), not JSON objects

## Core Protocol Files

The Keystone protocol is built on several core protobuf files that work together to provide a complete messaging and access control system:

### Core Protos

#### `envelope.proto` - Main Message Container
- **Purpose**: Primary container for messages 
- **Key Components**: 
  - `KeystoneEnvelope`: Top-level message container with public references and access grants
  - `KeystoneCoreMessage`: Content with private context references
  - `KeystoneMessageType`: Message type enumeration (CORE, MULTIPART_PART)
  - `KeystoneEncryptionMode`: Encryption mode enumeration (NONE, PROTECTED, PUBLIC_KEY)
- **Security**: Public envelope contains no sensitive data; all sensitive content may be encrypted

#### `access.proto` - Access Control & Key Management
- **Purpose**: Handles key distribution and access control mechanisms
- **Key Components**:
  - `KeystoneAccessGrant`: Key material distribution (CONTENT_KEY, GROUP_KEY)
  - `KeystoneContextReference`: Content relationships without key material
  - `KeystoneContextReferenceType`: Relationship types (REPLY_TO, EXTENDS, SUPERSEDES, REFERENCES, SUCCESSION)
  - `KeystoneKeyType`: Key type enumeration
- **Security**: Separates access control from data structure

#### `content.proto` - Content Descriptors & Encoding
- **Purpose**: Manages content metadata and multi-part message handling
- **Key Components**:
  - `KeystoneContentDescriptor`: External content metadata (URI, type, length, encoding)
  - `KeystoneContentEncoding`: Content encoding enumeration (GZIP, BR)
  - `KeystoneMultiPartMessagePart`: Large content handling
- **Features**: Supports various storage backends (IPFS, Arweave, etc.)

#### `validation.proto` - Field Validation & Security Rules
- **Purpose**: Provides field-level validation and security constraints
- **Key Components**:
  - `KeystoneFieldValidation`: Field validation rules (string, bytes, numeric, repeated)
  - `KeystoneSecurityRules`: Security constraints (sensitive, no_log, encrypt_at_rest)
  - `KeystoneAccessLevel`: Access control levels (PUBLIC, AUTHENTICATED, OWNER_ONLY, ADMIN_ONLY)
- **Features**: Extends protobuf FieldOptions with custom validation

#### `errors.proto` - Error Handling & Recovery
- **Purpose**: Standardized error responses and recovery mechanisms
- **Key Components**:
  - `KeystoneError`: Standard error response with tracing and recovery hints
  - `KeystoneErrorType`: Comprehensive error type enumeration
  - `ValidationErrorDetail`: Detailed validation failure information
- **Categories**: Validation, crypto, storage, access control, and bounty errors

### Protocol Dependencies

```
envelope.proto (Main Container)
├── a2a/a2a.proto (A2A Protocol Integration)
├── access.proto (Access Control & Key Management)
├── content.proto (Content Descriptors & Encoding)
├── validation.proto (Field Validation & Security)
└── errors.proto (Error Handling & Recovery)
```

**Dependency Flow:**
1. **`envelope.proto`** imports all core protos to create the main message structure
2. **`access.proto`** provides key management and relationship definitions
3. **`content.proto`** handles content metadata and multi-part messages
4. **`validation.proto`** ensures data integrity and security
5. **`errors.proto`** provides standardized error handling across all services
6. **`a2a.proto`** enables integration with the A2A protocol for agent communication (3rd party)

## Table of Contents

1. [Proposal → Analysis Chains](#proposal--analysis-chains)
   - How to structure a proposal with no parent references
   - How to create an analysis that references the proposal with CONTEXT_REFERENCE_TYPE_REPLY_TO
   - How to extend an analysis with CONTEXT_REFERENCE_TYPE_EXTENDS

2. [Succession Records](#succession-records)
  - How to use CONTEXT_REFERENCE_TYPE_SUCCESSION for version tracking
  - How to maintain cryptographic lineage through author signatures

3. [Multi-parent References](#multi-parent-references)
  - Using both public_references (discoverable) and context_references (private)
  - Best practices for access control in DAG relationships

4. [Security Considerations](#security-considerations)

5. [Best Practices](#best-practices)

## Proposal → Analysis Chains

### 1. Creating a Proposal (Root Node)

A proposal serves as the root of an analysis chain. It has no parent references and establishes the initial context.

```protobuf
// Proposal Envelope
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_proposal_content_bytes", // raw bytes, shown as hex for readability
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  // No public_references (root node) – this field may be omitted entirely; it
  // is shown here as an empty array for clarity.
  public_references: [],
  
  // Access grants for the proposal content
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_proposal_content_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_for_group_1"
    }
  ],
  
  // Encrypted proposal content
  message: "encrypted_proposal_bytes",
  
  metadata: {
    "author": "alice@example.com",
    "timestamp": "2024-01-15T10:00:00Z",
    "content_type": "application/json"
  } // map<string, string>
}

// Proposal Content (decrypted)
KeystoneCoreMessage {
  content_descriptor: {
    uri: "ipfs://QmProposalHash",
    content_type: "application/json",
    content_length: 1024,
    content_hash: "sha256_hash_of_proposal_content_bytes" // raw bytes
  },
  
  // No context_references (root node)
  context_references: [],
  
  metadata: {
    "title": "Proposal: Implement Zero-Knowledge Proof System",
    "category": "research",
    "budget": "50000"
  } // map<string, string>
}
```

### 2. Creating an Analysis (Reply to Proposal)

An analysis references the proposal using `CONTEXT_REFERENCE_TYPE_REPLY_TO`.

```protobuf
// Analysis Envelope
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_analysis_content_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  // Public reference to the proposal (discoverable)
  public_references: [
    {
      content_hash: "sha256_hash_of_proposal_content_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_REPLY_TO,
      annotation: "Analysis of ZK Proof proposal"
    }
  ],
  
  // Access grants for analysis content
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_analysis_content_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_for_group_1"
    }
  ],
  
  message: "encrypted_analysis_bytes",
  
  metadata: {
    "author": "bob@example.com",
    "timestamp": "2024-01-16T14:30:00Z"
  } // map<string, string>
}

// Analysis Content (decrypted)
KeystoneCoreMessage {
  content_descriptor: {
    uri: "ipfs://QmAnalysisHash",
    content_type: "application/json",
    content_length: 2048,
    content_hash: "sha256_hash_of_analysis_content_bytes" // raw bytes
  },
  
  // Private context reference (only visible after decryption)
  context_references: [
    {
      content_hash: "sha256_hash_of_proposal_content_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_REPLY_TO,
      annotation: "Detailed technical analysis"
    }
  ],
  
  metadata: {
    "analysis_type": "technical_review",
    "confidence_score": "0.85",
    "estimated_duration": "6_months"
  } // map<string, string>
}
```

### 3. Extending an Analysis

An extension builds upon the analysis using `CONTEXT_REFERENCE_TYPE_EXTENDS`.

```protobuf
// Extension Envelope
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_extension_content_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  // Public references to both proposal and analysis
  public_references: [
    {
      content_hash: "sha256_hash_of_proposal_content_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Original proposal"
    },
    {
      content_hash: "sha256_hash_of_analysis_content_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_EXTENDS,
      annotation: "Building on analysis"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_extension_content_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_for_group_1"
    }
  ],
  
  message: "encrypted_extension_bytes",
  
  metadata: {
    "author": "charlie@example.com",
    "timestamp": "2024-01-17T09:15:00Z"
  } // map<string, string>
}

// Extension Content (decrypted)
KeystoneCoreMessage {
  content_descriptor: {
    uri: "ipfs://QmExtensionHash",
    content_type: "application/json",
    content_length: 1536,
    content_hash: "sha256_hash_of_extension_content_bytes" // raw bytes
  },
  
  // Private context references
  context_references: [
    {
      content_hash: "proposal_content_hash_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Original proposal context"
    },
    {
      content_hash: "analysis_content_hash_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_EXTENDS,
      annotation: "Extending the analysis with implementation details"
    }
  ],
  
  metadata: {
    "extension_type": "implementation_details",
    "adds_protocol_specs": "true",
    "includes_test_cases": "true"
  } // map<string, string>
}
```

## Succession Records

### Version Tracking with Succession

Succession records maintain cryptographic lineage through version tracking.

> **Terminology:** `CONTEXT_REFERENCE_TYPE_SUCCESSION` is for formal version lineage.  
> Use `CONTEXT_REFERENCE_TYPE_SUPERSEDES` when one document immediately replaces another outside a version chain.

```protobuf
// Original Document Envelope
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_original_doc_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [],
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_original_doc_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_for_group_1"
    }
  ],
  
  message: "encrypted_original_doc_bytes",
  
  metadata: {
    "author": "alice@example.com",
    "timestamp": "2024-01-10T10:00:00Z",
    "version": "1.0.0"
  } // map<string, string>
}

// Succession Record (Version 2.0)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_v2_doc_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  // Public reference to the original document
  public_references: [
    {
      content_hash: "sha256_hash_of_original_doc_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_SUCCESSION,
      annotation: "Version 2.0 - Updated with new requirements"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_v2_doc_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_for_group_1"
    }
  ],
  
  message: "encrypted_v2_doc_bytes",
  
  metadata: {
    "author": "alice@example.com",
    "timestamp": "2024-01-20T15:30:00Z",
    "version": "2.0.0",
    "succession_reason": "Updated requirements based on feedback"
  } // map<string, string>
}

// Succession Record Content (decrypted)
KeystoneCoreMessage {
  content_descriptor: {
    uri: "ipfs://QmV2DocHash",
    content_type: "application/json",
    content_length: 2048,
    content_hash: "sha256_hash_of_v2_doc_bytes" // raw bytes
  },
  
  // Private context reference to original
  context_references: [
    {
      content_hash: "sha256_hash_of_original_doc_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_SUCCESSION,
      annotation: "Supersedes version 1.0.0"
    }
  ],
  
  metadata: {
    "version": "2.0.0",
    "changes": "Added security requirements, updated API spec",
    "compatibility": "backward_compatible"
  } // map<string, string>
}
```

### Cryptographic Lineage with Author Signatures

```protobuf
// Author Signature in Metadata
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_signed_doc_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [
    {
      content_hash: "sha256_hash_of_previous_version_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_SUCCESSION,
      annotation: "Signed by alice@example.com"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_signed_doc_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_for_group_1"
    }
  ],
  
  message: "encrypted_signed_doc_bytes",
  
  metadata: {
    "author": "alice@example.com",
    "timestamp": "2024-01-25T11:00:00Z",
    "version": "3.0.0",
    "author_signature": "base64_encoded_signature",
    "signature_algorithm": "ed25519",
    "public_key": "alice_public_key_base64"
  } // map<string, string>
}
```

## Multi-parent References

### Using Both Public and Private References

```protobuf
// Complex Multi-parent Envelope
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_complex_doc_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  // Public references (discoverable)
  public_references: [
    {
      content_hash: "sha256_hash_of_proposal_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Related proposal"
    },
    {
      content_hash: "sha256_hash_of_analysis_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_EXTENDS,
      annotation: "Building on analysis"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_complex_doc_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_for_group_1"
    },
    {
      key_type: GROUP_KEY,
      target_id: "group_1",
      encrypted_key_material: "encrypted_group_key_for_bob"
    }
  ],
  
  message: "encrypted_complex_doc_bytes",
  
  metadata: {
    "author": "bob@example.com",
    "timestamp": "2024-01-30T16:45:00Z",
    "reference_count": "5"
  } // map<string, string>
}

// Complex Document Content (decrypted)
KeystoneCoreMessage {
  content_descriptor: {
    uri: "ipfs://QmComplexDocHash",
    content_type: "application/json",
    content_length: 4096,
    content_hash: "sha256_hash_of_complex_doc_bytes" // raw bytes
  },
  
  // Private context references (only visible after decryption)
  context_references: [
    {
      content_hash: "sha256_hash_of_proposal_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Original proposal context"
    },
    {
      content_hash: "sha256_hash_of_analysis_bytes",
      group_id: "group_1",
      reference_type: CONTEXT_REFERENCE_TYPE_EXTENDS,
      annotation: "Extending the analysis"
    },
    {
      content_hash: "sha256_hash_of_private_doc_bytes",
      group_id: "group_2",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Private reference to internal document"
    },
    {
      content_hash: "sha256_hash_of_confidential_analysis_bytes",
      group_id: "group_3",
      reference_type: CONTEXT_REFERENCE_TYPE_EXTENDS,
      annotation: "Confidential analysis extension"
    }
  ],
  
  metadata: {
    "document_type": "comprehensive_review",
    "includes_private_data": "true",
    "access_level": "restricted"
  } // map<string, string>
}
```

### Access Control in DAG Relationships

```protobuf
// Access Control Example
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_restricted_doc_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  // Public references (visible to all)
  public_references: [
    {
      content_hash: "sha256_hash_of_public_doc_bytes",
      group_id: "public_group",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Public reference"
    }
  ],
  
  // Multiple access grants for different groups
  access_grants: [
    {
      key_type: CONTENT_KEY,  // (KeystoneKeyType)
      target_id: "sha256_hash_of_restricted_doc_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_for_group_1"
    },
    // Duplicate GROUP_KEY grants are intentional: each entry contains the SAME
    // group key encrypted with a DIFFERENT recipient's public key.
    {
      key_type: GROUP_KEY,    // (KeystoneKeyType)
      target_id: "group_1",
      encrypted_key_material: "encrypted_group_key_for_alice"
    },
    {
      key_type: GROUP_KEY,
      target_id: "group_1",
      encrypted_key_material: "encrypted_group_key_for_bob"
    },
    {
      key_type: GROUP_KEY,
      target_id: "group_2",
      encrypted_key_material: "encrypted_group_key_for_charlie"
    }
  ],
  
  message: "encrypted_restricted_doc_bytes",
  
  metadata: {
    "author": "alice@example.com",
    "timestamp": "2024-02-01T12:00:00Z",
    "access_groups": "group_1,group_2"
  } // map<string, string>
}
```

## Security Considerations

### Public vs Private References

1. **Public References (`public_references`)**:
   - Visible to all parties
   - Used for discovery and navigation
   - No sensitive information
   - Can be indexed and searched

2. **Private References (`context_references`)**:
   - Only visible after decryption
   - Can contain sensitive relationships
   - Require proper access control
   - Used for detailed context

### Best Practices

1. **Reference Type Selection**:
   - Use `REPLY_TO` for direct responses
   - Use `EXTENDS` for building upon content
   - Use `SUCCESSION` for version tracking
   - Use `REFERENCES` for general context

2. **Access Control**:
   - Group related content under same `group_id`
   - Use separate groups for different access levels
   - Ensure all referenced content is accessible to recipients

3. **DAG Integrity**:
   - Verify content hashes match references
   - Maintain consistent group_id usage
   - Document reference relationships clearly

4. **Performance Considerations**:
   - Limit reference depth for large DAGs
   - Use pagination for complex queries
   - Cache frequently accessed references

## Complete Example: Research Proposal Chain

```protobuf
// 1. Research Proposal (Root)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_research_proposal_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  public_references: [],
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_research_proposal_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_research_group"
    }
  ],
  message: "encrypted_proposal_bytes",
  metadata: {
    "author": "researcher@university.edu",
    "timestamp": "2024-01-01T09:00:00Z",
    "title": "Quantum-resistant cryptography research"
  } // map<string, string>
}

// 2. Peer Review (Reply)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_peer_review_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  public_references: [
    {
      content_hash: "sha256_hash_of_research_proposal_bytes",
      group_id: "research_group",
      reference_type: CONTEXT_REFERENCE_TYPE_REPLY_TO,
      annotation: "Peer review of quantum cryptography proposal"
    }
  ],
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_peer_review_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_research_group"
    }
  ],
  message: "encrypted_review_bytes",
  metadata: {
    "author": "reviewer@institute.org",
    "timestamp": "2024-01-15T14:30:00Z",
    "review_type": "technical_assessment"
  } // map<string, string>
}

// 3. Revised Proposal (Succession)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_revised_proposal_bytes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  public_references: [
    {
      content_hash: "sha256_hash_of_research_proposal_bytes",
      group_id: "research_group",
      reference_type: CONTEXT_REFERENCE_TYPE_SUCCESSION,
      annotation: "Revised proposal based on peer review"
    },
    {
      content_hash: "sha256_hash_of_peer_review_bytes",
      group_id: "research_group",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Addressing peer review feedback"
    }
  ],
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_revised_proposal_hex", // string: hex hash or UUID
      encrypted_key_material: "encrypted_cek_research_group"
    }
  ],
  message: "encrypted_revised_proposal_bytes",
  metadata: {
    "author": "researcher@university.edu",
    "timestamp": "2024-02-01T10:00:00Z",
    "version": "2.0",
    "incorporates_feedback": "true"
  } // map<string, string>
}
```

This documentation provides comprehensive examples of Context DAG patterns in the Keystone protocol, covering proposal analysis chains, succession records, and multi-parent references with proper security considerations and best practices.