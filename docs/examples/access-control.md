# Access Control in Keystone Protocol

This document provides comprehensive examples and best practices for implementing access control in the Keystone protocol. The protocol uses a sophisticated two-layer encryption scheme combining Content Encryption Keys (CEK) with Group Keys to provide flexible, secure access management.

> **Repository Status Note:** The repository provides comprehensive protocol buffer definitions for the access control system (`KeystoneAccessGrant`, `KeystoneKeyType`, access levels) and encryption modes, establishing a complete foundation for implementation. The two-layer encryption architecture (CEK + Group Keys) is well-defined structurally, but the actual cryptographic implementations, key management services, and access grant distribution mechanisms are not provided.

> **Encoding note:** Fields such as `content_hash` and `encrypted_key_material` are raw bytes in the wire format.  
> They are rendered here as hex- or base64-encoded strings purely for readability.
> 
> **Important:** 
> - `content_hash` fields are raw bytes (SHA-256 hash)
> - `target_id` fields are strings that can be either hex-encoded hashes or UUIDs
> - `metadata` fields are `map<string, string>` (key-value pairs), not JSON objects
> - `encrypted_key_material` contains encrypted binary data
> 
> **Examples and Placeholders:** All values marked with `// EXAMPLE:` comments are placeholder data for documentation purposes only. This includes:
> - Email addresses (e.g., `alice@research.org`)
> - URLs (e.g., `https://schemas.postfiat.org/...`) 
> - Ethereum addresses and attestation UIDs (e.g., `0x1234...`)
> - UUIDs, timestamps, and other identifiers
> - Replace these with your actual production values when implementing.

## Table of Contents

1. [Group Key Setup](#1-group-key-setup)
   - How to create and distribute group keys via KeystoneAccessGrant
   - Best practices for key rotation and group management

2. [Content Encryption Flow](#2-content-encryption-flow)
   - How to encrypt content with CEK
   - How to encrypt CEK with group key
   - How to structure KeystoneContextReference with proper group_id

3. [Multi-Group Access](#3-multi-group-access)
   - Granting access to multiple groups for the same content
   - Using different access levels (PUBLIC, AUTHENTICATED, OWNER_ONLY)

4. [EAS Integration](#4-eas-integration)
   - How registry attestations integrate with access control
   - Using attestation_uids for reputation-based access

5. [Best Practices](#5-best-practices)
   - Document key management best practices
   - Performance optimization guidelines
   - Development and security considerations

## Overview

The Keystone Protocol implements a hierarchical access control system with the following key components:

- **Content Encryption Keys (CEK)**: Symmetric keys that encrypt the actual message content
- **Group Keys**: Symmetric keys that encrypt CEKs, shared among group members
- **Public Key Encryption**: Used to distribute group keys to individual users
- **Access Grants**: Protocol messages that distribute encrypted key material
- **Access Levels**: Standardized security classifications (PUBLIC, AUTHENTICATED, OWNER_ONLY, ADMIN_ONLY)

## Core Access Control Components

### KeystoneAccessGrant Structure

```protobuf
message KeystoneAccessGrant {
  KeystoneKeyType key_type = 1;          // CONTENT_KEY or GROUP_KEY
  string target_id = 2;                  // Content hash (hex) or group UUID
  bytes encrypted_key_material = 3;      // Encrypted key data
}

enum KeystoneKeyType {
  KEY_TYPE_UNSPECIFIED = 0;
  CONTENT_KEY = 1;    // CEK encrypted with group key
  GROUP_KEY = 2;      // Group key encrypted with user's public key
}
```

### Access Levels

```protobuf
enum KeystoneAccessLevel {
  KEYSTONE_ACCESS_LEVEL_UNSPECIFIED = 0;
  KEYSTONE_ACCESS_LEVEL_PUBLIC = 1;         // Accessible to anyone
  KEYSTONE_ACCESS_LEVEL_AUTHENTICATED = 2;  // Requires valid identity
  KEYSTONE_ACCESS_LEVEL_OWNER_ONLY = 3;     // Content creator only
  KEYSTONE_ACCESS_LEVEL_ADMIN_ONLY = 4;     // System administrators
}
```

## 1. Group Key Setup

> **Current Implementation Status:** The repository defines complete message structures for access grants and key distribution (`KeystoneAccessGrant` with `CONTENT_KEY` and `GROUP_KEY` types), access levels, and integration with envelope encryption modes. The protocol clearly separates access control from data structure, providing a solid architectural foundation.
>
> **Future Implementation:** The access control system will require implementing cryptographic services for CEK/Group Key generation, secure key distribution mechanisms, user key management, and group membership management. Integration with identity systems and automated key rotation services will be needed for production use.
>
> **Open Architectural Decisions:**
> - **Cryptographic Implementation**: Choice of encryption algorithms (AES-256, ChaCha20-Poly1305) and key derivation functions
> - **Key Management**: Centralized vs. distributed key servers, hardware security module integration
> - **Group Management**: Who can create groups, add/remove members, and rotate keys
> - **Key Rotation**: Automatic vs. manual rotation, rotation frequency, and forward secrecy guarantees
> - **Identity Integration**: How to link access grants to verified identities and handle key recovery
> - **Performance**: Caching strategies for frequently accessed keys and batch key operations

### Creating a New Group

Before encrypting content, you must establish a group and distribute group keys to authorized members.

```protobuf
// Step 1: Generate group key and group ID
group_id = "550e8400-e29b-41d4-a716-446655440000"  // EXAMPLE: UUID format
group_key = generate_symmetric_key()  // 32 bytes for AES-256

// Step 2: Create access grants for each group member
// Alice's access grant
KeystoneAccessGrant {
  key_type: GROUP_KEY,
  target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Same group UUID
  encrypted_key_material: encrypt_with_public_key(group_key, alice_public_key) // EXAMPLE: Encrypted for Alice
}

// Bob's access grant  
KeystoneAccessGrant {
  key_type: GROUP_KEY,
  target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Same group UUID
  encrypted_key_material: encrypt_with_public_key(group_key, bob_public_key) // EXAMPLE: Encrypted for Bob
}

// Charlie's access grant
KeystoneAccessGrant {
  key_type: GROUP_KEY,
  target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Same group UUID
  encrypted_key_material: encrypt_with_public_key(group_key, charlie_public_key) // EXAMPLE: Encrypted for Charlie
}
```

### Group Key Distribution Message

```protobuf
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_group_setup_message", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [],
  
  // Distribute group key to all members
  access_grants: [
    {
      key_type: GROUP_KEY,
      target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Group UUID
      encrypted_key_material: "alice_encrypted_group_key_bytes" // EXAMPLE: Alice's encrypted group key
    },
    {
      key_type: GROUP_KEY, 
      target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Same group UUID
      encrypted_key_material: "bob_encrypted_group_key_bytes" // EXAMPLE: Bob's encrypted group key
    },
    {
      key_type: GROUP_KEY,
      target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Same group UUID
      encrypted_key_material: "charlie_encrypted_group_key_bytes" // EXAMPLE: Charlie's encrypted group key
    }
  ],
  
  message: "encrypted_group_welcome_message", // EXAMPLE: Encrypted welcome content
  
  metadata: {
    "group_name": "Research Team Alpha", // EXAMPLE: Group display name
    "created_by": "alice@research.org", // EXAMPLE: Creator email
    "timestamp": "2024-02-15T10:00:00Z", // EXAMPLE: ISO 8601 timestamp
    "group_purpose": "confidential_research" // EXAMPLE: Group purpose
  }
}
```

### Key Rotation Best Practices

```protobuf
// When rotating group keys
new_group_key = generate_symmetric_key()
rotation_timestamp = current_timestamp()

// Create rotation message
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_rotation_message", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  // Reference to old group for continuity
  public_references: [
    {
      content_hash: "sha256_hash_of_previous_setup", // EXAMPLE: Hash of previous setup message
      group_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Same group UUID
      reference_type: CONTEXT_REFERENCE_TYPE_SUPERSEDES,
      annotation: "Key rotation - replaces previous group setup" // EXAMPLE: Human-readable note
    }
  ],
  
  // Distribute new group key
  access_grants: [
    {
      key_type: GROUP_KEY,
      target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Same group UUID
      encrypted_key_material: "alice_new_encrypted_group_key" // EXAMPLE: Alice's new encrypted key
    },
    {
      key_type: GROUP_KEY,
      target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Same group UUID
      encrypted_key_material: "bob_new_encrypted_group_key" // EXAMPLE: Bob's new encrypted key
    }
    // Note: Charlie removed from group during rotation
  ],
  
  metadata: {
    "rotation_reason": "scheduled_quarterly_rotation", // EXAMPLE: Rotation reason
    "previous_key_expiry": "2024-02-15T23:59:59Z", // EXAMPLE: When old key expires
    "member_changes": "removed_charlie" // EXAMPLE: Membership changes
  }
}
```

## 2. Content Encryption Flow

### Two-Layer Encryption Process

The protocol uses a two-layer approach for maximum security and flexibility:

1. **Layer 1**: Content encrypted with CEK (symmetric)
2. **Layer 2**: CEK encrypted with group key (symmetric)  
3. **Distribution**: Group key encrypted with each user's public key (asymmetric)

```protobuf
// Step 1: Encrypt content with CEK
content = "This is sensitive research data..." // EXAMPLE: Plain text content
content_encryption_key = generate_symmetric_key()  // 32 bytes
encrypted_content = aes_encrypt(content, content_encryption_key)
content_hash = sha256(content)

// Step 2: Encrypt CEK with group key
group_key = get_group_key("550e8400-e29b-41d4-a716-446655440000") // EXAMPLE: Get group key by UUID
encrypted_cek = aes_encrypt(content_encryption_key, group_key)

// Step 3: Create envelope with access grants
KeystoneEnvelope {
  version: 1,
  content_hash: content_hash, // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [],
  
  access_grants: [
    // Grant access to content for group members
    {
      key_type: CONTENT_KEY,
      target_id: hex_encode(content_hash), // hex-encoded hash
      encrypted_key_material: encrypted_cek // EXAMPLE: CEK encrypted with group key
    },
    // Ensure group members have group key (may be omitted if already distributed)
    {
      key_type: GROUP_KEY,
      target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Group UUID
      encrypted_key_material: "alice_encrypted_group_key" // EXAMPLE: Group key encrypted for Alice
    },
    {
      key_type: GROUP_KEY,
      target_id: "550e8400-e29b-41d4-a716-446655440000", // EXAMPLE: Same group UUID
      encrypted_key_material: "bob_encrypted_group_key" // EXAMPLE: Group key encrypted for Bob
    }
  ],
  
  message: encrypted_content, // EXAMPLE: Content encrypted with CEK
  
  metadata: {
    "author": "alice@research.org", // EXAMPLE: Author email
    "timestamp": "2024-02-15T14:30:00Z", // EXAMPLE: ISO 8601 timestamp
    "content_type": "research_data", // EXAMPLE: Content type
    "classification": "confidential" // EXAMPLE: Security classification
  }
}
```

### Decryption Process

```pseudocode
// Recipient's decryption process
function decrypt_message(envelope, user_private_key) {
  // Step 1: Find and decrypt group key
  group_key = null
  for grant in envelope.access_grants {
    if grant.key_type == GROUP_KEY {
      group_key = decrypt_with_private_key(grant.encrypted_key_material, user_private_key)
      break
    }
  }
  
  // Step 2: Find and decrypt content key
  content_key = null
  content_hash_hex = hex_encode(envelope.content_hash)
  for grant in envelope.access_grants {
    if grant.key_type == CONTENT_KEY && grant.target_id == content_hash_hex {
      content_key = aes_decrypt(grant.encrypted_key_material, group_key)
      break
    }
  }
  
  // Step 3: Decrypt main content
  decrypted_content = aes_decrypt(envelope.message, content_key)
  
  // Step 4: Verify integrity
  if sha256(decrypted_content) != envelope.content_hash {
    throw IntegrityCheckFailed
  }
  
  return decrypted_content
}
```

## 3. Multi-Group Access

### Granting Access to Multiple Groups

You can grant access to the same content for multiple groups with different access levels:

```protobuf
// Content accessible by research team, reviewers, and administrators
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_research_paper", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [
    {
      content_hash: "sha256_hash_of_public_abstract",
      group_id: "public",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Public abstract available to all"
    }
  ],
  
  // Multiple access grants for different groups
  access_grants: [
    // Research team (full access)
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_research_paper_hex",
      encrypted_key_material: "encrypted_cek_for_research_group"
    },
    {
      key_type: GROUP_KEY,
      target_id: "research_team_uuid",
      encrypted_key_material: "alice_research_group_key"
    },
    {
      key_type: GROUP_KEY, 
      target_id: "research_team_uuid",
      encrypted_key_material: "bob_research_group_key"
    },
    
    // Peer reviewers (review access)
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_research_paper_hex", 
      encrypted_key_material: "encrypted_cek_for_reviewer_group"
    },
    {
      key_type: GROUP_KEY,
      target_id: "reviewer_group_uuid",
      encrypted_key_material: "reviewer1_group_key"
    },
    {
      key_type: GROUP_KEY,
      target_id: "reviewer_group_uuid", 
      encrypted_key_material: "reviewer2_group_key"
    },
    
    // Administrators (audit access)
    {
      key_type: GROUP_KEY,
      target_id: "admin_group_uuid",
      encrypted_key_material: "admin_encrypted_group_key"
    }
  ],
  
  message: "encrypted_research_paper_content",
  
  metadata: {
    "title": "Quantum Cryptography Advances",
    "access_groups": "research_team,reviewers,administrators",
    "classification": "KEYSTONE_ACCESS_LEVEL_AUTHENTICATED", 
    "review_deadline": "2024-03-15T23:59:59Z"
  }
}
```

### Hierarchical Access Levels

```protobuf
// Executive summary (PUBLIC access)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_exec_summary", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_NONE, // Public content
  
  public_references: [],
  access_grants: [], // No access grants needed for public content
  message: "unencrypted_executive_summary",
  
  metadata: {
    "access_level": "KEYSTONE_ACCESS_LEVEL_PUBLIC",
    "document_type": "executive_summary"
  }
}

// Detailed analysis (AUTHENTICATED access)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_detailed_analysis", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [
    {
      content_hash: "sha256_hash_of_exec_summary",
      group_id: "public",
      reference_type: CONTEXT_REFERENCE_TYPE_EXTENDS,
      annotation: "Detailed analysis of public summary"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_detailed_analysis_hex",
      encrypted_key_material: "encrypted_cek_for_authenticated_users"
    },
    {
      key_type: GROUP_KEY,
      target_id: "authenticated_users_group",
      encrypted_key_material: "user1_group_key"
    }
  ],
  
  message: "encrypted_detailed_analysis",
  
  metadata: {
    "access_level": "KEYSTONE_ACCESS_LEVEL_AUTHENTICATED",
    "requires_identity_verification": "true"
  }
}

// Confidential data (OWNER_ONLY access)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_confidential_data", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [],
  
  access_grants: [
    {
      key_type: CONTENT_KEY, 
      target_id: "sha256_hash_of_confidential_data_hex",
      encrypted_key_material: "encrypted_cek_for_owner_only"
    },
    {
      key_type: GROUP_KEY,
      target_id: "owner_only_group",
      encrypted_key_material: "owner_encrypted_group_key"
    }
  ],
  
  message: "encrypted_confidential_data",
  
  metadata: {
    "access_level": "KEYSTONE_ACCESS_LEVEL_OWNER_ONLY",
    "created_by": "alice@research.org",
    "confidentiality_level": "top_secret"
  }
}
```

### Complete End-to-End Example

#### Scenario: Collaborative Research with Multi-Level Access

A research team wants to collaborate on a sensitive project with the following access requirements:
- Public abstract (open access)
- Detailed methodology (authenticated researchers only)  
- Raw data (team members only)
- Personal notes (owner only)

```protobuf
// 1. Public Abstract
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_abstract", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_NONE,
  
  public_references: [],
  access_grants: [], // Public content needs no access grants
  
  message: "unencrypted_research_abstract_content",
  
  metadata: {
    "title": "Quantum Key Distribution Security Analysis", // EXAMPLE: Research paper title
    "authors": "Alice Chen, Bob Williams", // EXAMPLE: Author names
    "access_level": "KEYSTONE_ACCESS_LEVEL_PUBLIC", // EXAMPLE: Access level
    "publication_date": "2024-02-20", // EXAMPLE: Publication date
    "doi": "10.1000/xyz123" // EXAMPLE: DOI identifier
  }
}

// 2. Detailed Methodology (Authenticated Researchers)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_methodology", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [
    {
      content_hash: "sha256_hash_of_abstract",
      group_id: "public",
      reference_type: CONTEXT_REFERENCE_TYPE_EXTENDS,
      annotation: "Detailed methodology for public abstract"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_methodology_hex",
      encrypted_key_material: "encrypted_cek_for_researchers"
    },
    {
      key_type: GROUP_KEY,
      target_id: "authenticated_researchers_group",
      encrypted_key_material: "researcher1_group_key"
    },
    {
      key_type: GROUP_KEY,
      target_id: "authenticated_researchers_group",
      encrypted_key_material: "researcher2_group_key"
    },
    {
      key_type: GROUP_KEY,
      target_id: "authenticated_researchers_group", 
      encrypted_key_material: "researcher3_group_key"
    }
  ],
  
  message: "encrypted_methodology_content",
  
  metadata: {
    "access_level": "KEYSTONE_ACCESS_LEVEL_AUTHENTICATED", // EXAMPLE: Access level
    "required_attestations": "researcher_credential,institution_affiliation", // EXAMPLE: Required attestations
    "content_type": "methodology" // EXAMPLE: Content type
  }
}

// 3. Raw Data (Team Members Only)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_raw_data", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [
    {
      content_hash: "sha256_hash_of_methodology",
      group_id: "authenticated_researchers_group",
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Raw data supporting the methodology"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_raw_data_hex",
      encrypted_key_material: "encrypted_cek_for_team"
    },
    // Team-only access
    {
      key_type: GROUP_KEY,
      target_id: "research_team_alpha",
      encrypted_key_material: "alice_team_group_key"
    },
    {
      key_type: GROUP_KEY,
      target_id: "research_team_alpha",
      encrypted_key_material: "bob_team_group_key"
    }
  ],
  
  message: "encrypted_raw_data_content",
  
  metadata: {
    "access_level": "KEYSTONE_ACCESS_LEVEL_AUTHENTICATED", // EXAMPLE: Access level
    "team_id": "research_team_alpha", // EXAMPLE: Team identifier
    "data_classification": "confidential", // EXAMPLE: Data classification
    "retention_period": "7_years" // EXAMPLE: Data retention period
  }
}

// 4. Personal Research Notes (Owner Only)
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_personal_notes", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_personal_notes_hex",
      encrypted_key_material: "encrypted_cek_for_alice_only"
    },
    {
      key_type: GROUP_KEY,
      target_id: "alice_personal_group",
      encrypted_key_material: "alice_personal_group_key"
    }
  ],
  
  message: "encrypted_personal_notes_content",
  
  metadata: {
    "access_level": "KEYSTONE_ACCESS_LEVEL_OWNER_ONLY", // EXAMPLE: Access level
    "owner": "alice@research.org", // EXAMPLE: Owner email
    "note_type": "personal_research_journal", // EXAMPLE: Note type
    "privacy_level": "maximum" // EXAMPLE: Privacy level
  }
}
```

## 4. EAS Integration

### Registry with Attestation-Based Access

The Keystone Protocol integrates with Ethereum Attestation Service (EAS) to provide reputation-based access control:

```protobuf
// Agent capabilities with EAS attestations
KeystoneAgentCapabilities {
  envelope_processing: true,
  ledger_persistence: true,
  context_dag_traversal: true,
  max_context_depth: 10,
  supported_encryption_modes: [ENCRYPTION_MODE_PROTECTED, ENCRYPTION_MODE_PUBLIC_KEY],
  
  public_encryption_key: "curve25519_public_key_32_bytes",
  public_key_algorithm: PUBLIC_KEY_ALGORITHM_CURVE25519,
  
  supported_semantic_capabilities: [
    "https://schemas.postfiat.org/tasks/research-analysis/v1", // EXAMPLE: Research analysis capability URI
    "https://schemas.postfiat.org/tasks/peer-review/v1" // EXAMPLE: Peer review capability URI
  ],
  
  // EAS attestation UIDs for reputation/credentials
  attestation_uids: [
    "0x1234567890abcdef1234567890abcdef12345678", // EXAMPLE: PhD credential attestation UID
    "0xabcdef1234567890abcdef1234567890abcdef12", // EXAMPLE: Research institution membership UID
    "0x9876543210fedcba9876543210fedcba98765432"  // EXAMPLE: Peer review reputation score UID
  ]
}
```

### Attestation-Based Access Control

```protobuf
// Content restricted to users with specific attestations
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_academic_paper", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_academic_paper_hex",
      encrypted_key_material: "encrypted_cek_for_verified_academics"
    },
    // Only users with PhD attestation can access
    {
      key_type: GROUP_KEY,
      target_id: "phd_verified_group",
      encrypted_key_material: "phd_holder1_group_key"
    },
    {
      key_type: GROUP_KEY,
      target_id: "phd_verified_group", 
      encrypted_key_material: "phd_holder2_group_key"
    }
  ],
  
  message: "encrypted_academic_paper",
  
  metadata: {
    "required_attestations": "phd_credential,institution_membership", // EXAMPLE: Required attestation types
    "min_reputation_score": "85", // EXAMPLE: Minimum reputation threshold
    "attestation_verification_required": "true", // EXAMPLE: Verification flag
    "academic_field": "cryptography" // EXAMPLE: Academic field restriction
  }
}
```

### Reputation-Based Content Access

```protobuf
// High-value content requiring high reputation scores
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_advanced_research", // raw bytes
  message_type: MESSAGE_TYPE_CORE,
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [
    {
      content_hash: "sha256_hash_of_basic_research",
      group_id: "authenticated_researchers", 
      reference_type: CONTEXT_REFERENCE_TYPE_EXTENDS,
      annotation: "Advanced extension of basic research"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_advanced_research_hex",
      encrypted_key_material: "encrypted_cek_for_high_reputation"
    },
    // Access only for users with reputation score > 90
    {
      key_type: GROUP_KEY,
      target_id: "high_reputation_researchers",
      encrypted_key_material: "top_researcher1_group_key"
    },
    {
      key_type: GROUP_KEY,
      target_id: "high_reputation_researchers",
      encrypted_key_material: "top_researcher2_group_key"
    }
  ],
  
  message: "encrypted_advanced_research_content",
  
  metadata: {
    "min_reputation_attestation": "0x9876543210fedcba9876543210fedcba98765432", // EXAMPLE: Attestation UID for reputation
    "required_score": "90", // EXAMPLE: Required reputation score
    "verification_contract": "0xReputationVerifier123...", // EXAMPLE: Reputation verification contract address
    "access_tier": "premium" // EXAMPLE: Access tier classification
  }
}
```
## 5. Best Practices

### Key Management

1. **Group Key Rotation**
   - Rotate group keys regularly (recommended: quarterly)
   - Use secure random number generation for all keys
   - Implement key escrow for critical groups
   - Maintain audit logs of key operations

2. **Access Grant Management**
   - Always include both CONTENT_KEY and GROUP_KEY grants when needed
   - Verify recipient public keys before encryption
   - Use consistent group_id formats (UUIDs recommended)
   - Implement access grant revocation mechanisms

3. **Security Considerations**
   - Validate all content hashes during decryption
   - Use secure channels for initial key distribution
   - Implement perfect forward secrecy where possible
   - Monitor for unauthorized access attempts

### Performance Optimization

1. **Key Caching**
   - Cache decrypted group keys securely in memory
   - Implement key expiration and refresh policies
   - Use secure memory wiping when keys are no longer needed

2. **Access Grant Efficiency**
   - Batch multiple content access grants together
   - Avoid redundant group key distribution
   - Use compression for large access grant lists

3. **EAS Integration**
   - Cache attestation verification results
   - Implement offline attestation validation where possible
   - Use event-based attestation updates

### Development Guidelines

1. **Error Handling**
   - Implement specific error codes for access control failures
   - Never expose sensitive key material in error messages
   - Log access attempts for security auditing

2. **Testing**
   - Test all access level combinations
   - Verify key rotation scenarios
   - Test attestation-based access controls
   - Validate multi-group access patterns

3. **Documentation**
   - Document all group_id conventions
   - Maintain access control policy documentation
   - Keep EAS integration schemas up to date
   - Document key rotation procedures

## Conclusion

> **Overall Implementation Status:** This documentation describes a sophisticated and well-architected access control system with complete protocol definitions that provide excellent implementation guidance. The repository establishes clear patterns for two-layer encryption, key distribution, and access management, but the actual cryptographic services, key management infrastructure, and EAS integration remain to be built.
>

The Keystone Protocol's access control system provides a flexible, secure foundation for collaborative content management. By combining symmetric encryption for performance with asymmetric encryption for key distribution, and integrating with EAS for reputation-based access, it enables sophisticated access control patterns while maintaining strong security guarantees.

The two-layer encryption approach ensures that content remains secure even as group membership changes, while the integration with Ethereum Attestation Service enables trust-based access decisions. Following the patterns and best practices outlined in this document will help you implement robust access control for your Keystone Protocol applications. 