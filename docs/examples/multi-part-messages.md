# Multi-Part Messages in Keystone Protocol

This document provides comprehensive examples and best practices for implementing multi-part message support in the Keystone protocol. Multi-part messages enable transmission of large content that exceeds storage backend limitations while maintaining integrity and supporting efficient assembly patterns.

> **Repository Status Note:** The repository provides comprehensive protocol buffer definitions for multi-part messages (`KeystoneMultiPartMessagePart`) and integration with the envelope system, establishing the complete message structure foundation. However, the actual splitting algorithms, assembly logic, storage backend integrations, and error recovery mechanisms described in this documentation remain to be implemented.

> **Examples and Placeholders:** All values marked with `// EXAMPLE:` comments are placeholder data for documentation purposes only. This includes:
> - Message IDs (e.g., `msg_abc123def456`)
> - Content hashes (e.g., `0x1234567890abcdef...`)
> - Storage URIs (e.g., `ipfs://QmXxx...`, `arweave://Ary...`)
> - Part numbers, sizes, and timestamps
> - Agent addresses and group identifiers
> - Replace these with your actual production values when implementing.

## Table of Contents

1. [Message Splitting](#1-message-splitting)
   - Splitting algorithms and strategies
   - Complete message hash calculation
   - Optimal part sizing for different backends

2. [Message Assembly](#2-message-assembly)
   - Message reconstruction from parts
   - Handling missing or out-of-order parts
   - Integrity verification against complete_message_hash

3. [Storage Backend Considerations](#3-storage-backend-considerations)
   - IPFS, Arweave, and XRPL memo field distribution
   - Backend-specific size limitations and strategies
   - Redundancy and availability patterns

4. [Error Handling for Incomplete Messages](#4-error-handling-for-incomplete-messages)
   - Comprehensive error recovery patterns
   - Missing parts, corruption, and timeout handling
   - Recovery strategies and retry mechanisms

---

## 1. Message Splitting

> **Current Implementation Status:** The repository defines the `KeystoneMultiPartMessagePart` structure with all necessary fields (message_id, part_number, total_parts, content, complete_message_hash) and integration with the envelope system through `MESSAGE_TYPE_MULTIPART_PART`. The protocol supports content splitting concepts but provides no actual implementation.
>
> **Future Implementation:** Multi-part message functionality will require implementing content splitting algorithms, storage backend adapters, integrity verification systems, and assembly coordination services. Each storage backend (IPFS, Arweave, XRPL) will need specialized handlers that understand size limits and optimization strategies.
>
> **Open Architectural Decisions:**
> - **Storage Backend Priority**: Whether to optimize for a primary backend vs. supporting all backends equally
> - **Part Size Strategy**: Dynamic sizing based on content type vs. fixed sizes per backend vs. adaptive sizing based on network conditions
> - **Assembly Coordination**: Centralized vs. peer-to-peer part discovery and assembly coordination
> - **Redundancy Strategy**: How many copies of each part to store across different backends and locations
> - **Performance vs. Cost**: Trade-offs between storage costs, retrieval speed, and redundancy levels

### 1.1 Content Splitting Algorithm

Large content must be split into `KeystoneMultiPartMessagePart` messages that can fit within storage backend constraints.

```typescript
// Content Splitting Implementation
class KeystoneMessageSplitter {
  static async splitContent(
    content: Uint8Array,
    maxPartSize: number = 32768, // EXAMPLE: 32KB default part size
    messageId: string = generateMessageId() // EXAMPLE: Generate unique message ID
  ): Promise<KeystoneMultiPartMessagePart[]> {
    
    // 1. Calculate complete message hash BEFORE splitting
    const completeMessageHash = await calculateSHA256(content);
    const completeHashHex = bytesToHex(completeMessageHash);
    
    // 2. Calculate optimal part count and size
    const totalSize = content.length;
    const totalParts = Math.ceil(totalSize / maxPartSize);
    
    console.log(`Splitting ${totalSize} bytes into ${totalParts} parts`);
    
    const parts: KeystoneMultiPartMessagePart[] = [];
    
    // 3. Create parts with 1-based indexing
    for (let i = 0; i < totalParts; i++) {
      const partNumber = i + 1; // 1-based indexing
      const startOffset = i * maxPartSize;
      const endOffset = Math.min(startOffset + maxPartSize, totalSize);
      const partContent = content.slice(startOffset, endOffset);
      
      const part: KeystoneMultiPartMessagePart = {
        message_id: messageId, // EXAMPLE: "msg_abc123def456"
        part_number: partNumber, // EXAMPLE: 1, 2, 3, etc.
        total_parts: totalParts, // EXAMPLE: 5 total parts
        content: partContent, // Raw bytes for this part
        complete_message_hash: completeHashHex // EXAMPLE: "0x1234567890abcdef..."
      };
      
      parts.push(part);
      
      console.log(`Created part ${partNumber}/${totalParts}, size: ${partContent.length} bytes`);
    }
    
    return parts;
  }
}

// Usage Example
async function splitLargeMessage(originalContent: string): Promise<KeystoneMultiPartMessagePart[]> {
  const contentBytes = new TextEncoder().encode(originalContent);
  const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`; // EXAMPLE: Generate unique ID
  
  // Split with backend-appropriate part size
  const parts = await KeystoneMessageSplitter.splitContent(
    contentBytes,
    getOptimalPartSize('STORAGE_BACKEND_IPFS'), // EXAMPLE: 32KB for IPFS
    messageId
  );
  
  return parts;
}
```

### 1.2 Complete Message Hash Calculation

The `complete_message_hash` provides integrity verification for the reassembled message.

```protobuf
// Multi-Part Message Part Structure
message KeystoneMultiPartMessagePart {
  // Unique identifier for the complete multi-part message
  string message_id = 1; // EXAMPLE: "msg_research_data_2024_01_15"
  
  // Part number (1-based indexing)
  uint32 part_number = 2; // EXAMPLE: 3 (third part)
  
  // Total number of parts in this message
  uint32 total_parts = 3; // EXAMPLE: 3 total parts
  
  // Content bytes for this part
  bytes content = 4; // EXAMPLE: Raw bytes (0x48656c6c6f20776f726c64...)
  
  // SHA-256 hash of the complete reassembled message (hex string)
  string complete_message_hash = 5; // EXAMPLE: "0x1234567890abcdef1234567890abcdef12345678"
}
```

```typescript
// Hash Calculation Implementation
async function calculateCompleteMessageHash(originalContent: Uint8Array): Promise<string> {
  // Use SHA-256 to hash the complete, unsplit content
  const hashBuffer = await crypto.subtle.digest('SHA-256', originalContent);
  const hashArray = new Uint8Array(hashBuffer);
  
  // Convert to hex string with 0x prefix
  const hashHex = '0x' + Array.from(hashArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return hashHex; // EXAMPLE: "0x1234567890abcdef1234567890abcdef12345678"
}

// Verification Example
async function verifyContentIntegrity(
  reassembledContent: Uint8Array,
  expectedHash: string // EXAMPLE: "0x1234567890abcdef..."
): Promise<boolean> {
  const actualHash = await calculateCompleteMessageHash(reassembledContent);
  return actualHash === expectedHash;
}
```

### 1.3 Backend-Specific Part Sizing

Different storage backends have varying size limitations that affect optimal part sizing.

```typescript
// Storage Backend Size Limits and Optimal Part Sizes
interface StorageBackendLimits {
  maxContentSize: number;
  optimalPartSize: number;
  compressionSupported: boolean;
  redundancyFactor: number;
}

const STORAGE_BACKEND_LIMITS: Record<string, StorageBackendLimits> = {
  'STORAGE_BACKEND_IPFS': {
    maxContentSize: 1048576, // EXAMPLE: 1MB per IPFS block
    optimalPartSize: 262144,  // EXAMPLE: 256KB for efficient distribution
    compressionSupported: true,
    redundancyFactor: 3 // EXAMPLE: Triple redundancy
  },
  
  'STORAGE_BACKEND_ARWEAVE': {
    maxContentSize: 12582912, // EXAMPLE: 12MB per Arweave transaction
    optimalPartSize: 2097152,  // EXAMPLE: 2MB for cost efficiency
    compressionSupported: true,
    redundancyFactor: 1 // EXAMPLE: Single storage (permanent)
  },
  
  'STORAGE_BACKEND_XRPL_MEMO': {
    maxContentSize: 1024,     // EXAMPLE: 1KB XRPL memo limit
    optimalPartSize: 512,     // EXAMPLE: 512 bytes for metadata overhead
    compressionSupported: false,
    redundancyFactor: 1 // EXAMPLE: On-ledger storage
  },
  
  'STORAGE_BACKEND_EVM_CALLDATA': {
    maxContentSize: 131072,   // EXAMPLE: 128KB practical calldata limit
    optimalPartSize: 32768,   // EXAMPLE: 32KB for gas efficiency
    compressionSupported: false,
    redundancyFactor: 1 // EXAMPLE: On-chain storage
  }
};

function getOptimalPartSize(backend: string): number {
  const limits = STORAGE_BACKEND_LIMITS[backend];
  if (!limits) {
    throw new Error(`Unknown storage backend: ${backend}`);
  }
  return limits.optimalPartSize;
}

// Dynamic Part Sizing Based on Content and Backend
function calculateOptimalPartSize(
  totalContentSize: number,
  targetBackend: string,
  maxParts: number = 100 // EXAMPLE: Limit to 100 parts for manageable assembly
): number {
  const limits = STORAGE_BACKEND_LIMITS[targetBackend];
  
  // Calculate size needed per part
  const minPartSize = Math.ceil(totalContentSize / maxParts);
  const backendOptimal = limits.optimalPartSize;
  
  // Use the larger of minimum required or backend optimal
  return Math.max(minPartSize, backendOptimal);
}
```

### 1.4 Multi-Part Message Envelope Structure

Each part is wrapped in a `KeystoneEnvelope` with `MESSAGE_TYPE_MULTIPART_PART`.

```protobuf
// Multi-Part Message Part Envelope
KeystoneEnvelope {
  version: 1,
  content_hash: "sha256_hash_of_part_content_bytes", // EXAMPLE: Hash of this specific part
  message_type: MESSAGE_TYPE_MULTIPART_PART, // EXAMPLE: Type = 2 for multi-part
  encryption: ENCRYPTION_MODE_PROTECTED,
  
  public_references: [
    {
      content_hash: "sha256_hash_of_original_message_bytes", // EXAMPLE: Reference to original complete message
      group_id: "multipart_group_1", // EXAMPLE: Group for multi-part message
      reference_type: CONTEXT_REFERENCE_TYPE_REFERENCES,
      annotation: "Part 2 of 5 - Research data analysis"
    }
  ],
  
  access_grants: [
    {
      key_type: CONTENT_KEY,
      target_id: "sha256_hash_of_part_content_hex", // EXAMPLE: Hex-encoded part hash
      encrypted_key_material: "encrypted_cek_for_multipart_group" // EXAMPLE: Encrypted content key
    },
    {
      key_type: GROUP_KEY,
      target_id: "multipart_group_1", // EXAMPLE: Group UUID
      encrypted_key_material: "alice_encrypted_group_key" // EXAMPLE: Group key for Alice
    }
  ],
  
  message: "encrypted_multipart_message_part_bytes", // EXAMPLE: Encrypted KeystoneMultiPartMessagePart
  
  metadata: {
    "author": "alice@research.org", // EXAMPLE: Original message author
    "timestamp": "2024-02-15T10:30:00Z", // EXAMPLE: ISO 8601 timestamp
    "part_number": "2", // EXAMPLE: This is part 2
    "total_parts": "5", // EXAMPLE: Total of 5 parts
    "message_id": "msg_research_data_2024_01_15", // EXAMPLE: Complete message ID
    "backend_target": "STORAGE_BACKEND_IPFS" // EXAMPLE: Target storage backend
  }
}
```

---

## 2. Message Assembly

### 2.1 Part Collection and Ordering

Receivers must collect all parts and reassemble them in the correct order.

```typescript
// Message Assembly Implementation
class KeystoneMessageAssembler {
  private partCache: Map<string, KeystoneMultiPartMessagePart[]> = new Map();
  
  async addPart(part: KeystoneMultiPartMessagePart): Promise<AssemblyResult> {
    const messageId = part.message_id;
    
    // Initialize part collection for this message
    if (!this.partCache.has(messageId)) {
      this.partCache.set(messageId, []);
    }
    
    const parts = this.partCache.get(messageId)!;
    
    // Check for duplicate parts
    const existingPart = parts.find(p => p.part_number === part.part_number);
    if (existingPart) {
      console.warn(`Duplicate part ${part.part_number} for message ${messageId}`);
      return { status: 'DUPLICATE_PART', messageId };
    }
    
    // Add part to collection
    parts.push(part);
    
    // Sort parts by part_number for correct ordering
    parts.sort((a, b) => a.part_number - b.part_number);
    
    console.log(`Added part ${part.part_number}/${part.total_parts} for message ${messageId}`);
    
    // Check if we have all parts
    if (parts.length === part.total_parts) {
      const assembledMessage = await this.assembleMessage(messageId);
      return { status: 'COMPLETE', messageId, assembledMessage };
    } else {
      const missingParts = this.findMissingParts(parts, part.total_parts);
      return { status: 'INCOMPLETE', messageId, missingParts };
    }
  }
  
  private findMissingParts(parts: KeystoneMultiPartMessagePart[], totalParts: number): number[] {
    const presentParts = new Set(parts.map(p => p.part_number));
    const missingParts: number[] = [];
    
    for (let i = 1; i <= totalParts; i++) {
      if (!presentParts.has(i)) {
        missingParts.push(i);
      }
    }
    
    return missingParts;
  }
  
  async assembleMessage(messageId: string): Promise<Uint8Array> {
    const parts = this.partCache.get(messageId);
    if (!parts) {
      throw new Error(`No parts found for message ${messageId}`);
    }
    
    // Verify we have all parts
    const totalParts = parts[0]?.total_parts;
    if (!totalParts || parts.length !== totalParts) {
      throw new Error(`Incomplete parts for message ${messageId}: have ${parts.length}, need ${totalParts}`);
    }
    
    // Concatenate parts in order
    const contentBuffers = parts.map(part => part.content);
    const totalLength = contentBuffers.reduce((sum, buffer) => sum + buffer.length, 0);
    
    const assembledContent = new Uint8Array(totalLength);
    let offset = 0;
    
    for (const buffer of contentBuffers) {
      assembledContent.set(buffer, offset);
      offset += buffer.length;
    }
    
    // Verify integrity against complete_message_hash
    const expectedHash = parts[0].complete_message_hash;
    const actualHash = await calculateCompleteMessageHash(assembledContent);
    
    if (actualHash !== expectedHash) {
      throw new Error(`Integrity check failed for message ${messageId}: expected ${expectedHash}, got ${actualHash}`);
    }
    
    console.log(`Successfully assembled message ${messageId}: ${assembledContent.length} bytes`);
    
    // Clean up cache
    this.partCache.delete(messageId);
    
    return assembledContent;
  }
}

// Assembly Result Types
interface AssemblyResult {
  status: 'COMPLETE' | 'INCOMPLETE' | 'DUPLICATE_PART' | 'ERROR';
  messageId: string;
  assembledMessage?: Uint8Array;
  missingParts?: number[];
  error?: string;
}
```

### 2.2 Handling Missing or Out-of-Order Parts

Robust assembly must handle network delays, missing parts, and delivery order variations.

```typescript
// Advanced Assembly with Timeout and Retry Logic
class RobustMessageAssembler extends KeystoneMessageAssembler {
  private assemblyTimeouts: Map<string, NodeJS.Timeout> = new Map();
  private partRequests: Map<string, Set<number>> = new Map();
  
  constructor(
    private timeoutMs: number = 300000, // EXAMPLE: 5-minute timeout
    private maxRetries: number = 3 // EXAMPLE: Maximum retry attempts
  ) {
    super();
  }
  
  async addPart(part: KeystoneMultiPartMessagePart): Promise<AssemblyResult> {
    const result = await super.addPart(part);
    const messageId = part.message_id;
    
    if (result.status === 'INCOMPLETE') {
      // Set up timeout for this message if not already set
      if (!this.assemblyTimeouts.has(messageId)) {
        const timeout = setTimeout(() => {
          this.handleAssemblyTimeout(messageId);
        }, this.timeoutMs);
        
        this.assemblyTimeouts.set(messageId, timeout);
      }
      
      // Request missing parts if we have specific missing part numbers
      if (result.missingParts && result.missingParts.length > 0) {
        await this.requestMissingParts(messageId, result.missingParts);
      }
    } else if (result.status === 'COMPLETE') {
      // Clear timeout on successful assembly
      this.clearAssemblyTimeout(messageId);
    }
    
    return result;
  }
  
  private async requestMissingParts(messageId: string, missingParts: number[]): Promise<void> {
    if (!this.partRequests.has(messageId)) {
      this.partRequests.set(messageId, new Set());
    }
    
    const requested = this.partRequests.get(messageId)!;
    
    for (const partNumber of missingParts) {
      if (!requested.has(partNumber)) {
        console.log(`Requesting missing part ${partNumber} for message ${messageId}`);
        
        // Send request to network/storage layer
        await this.sendPartRequest(messageId, partNumber);
        requested.add(partNumber);
      }
    }
  }
  
  private async sendPartRequest(messageId: string, partNumber: number): Promise<void> {
    // Example: Request part from storage network
    try {
      // This would integrate with your storage/network layer
      await requestPartFromNetwork({
        messageId, // EXAMPLE: "msg_research_data_2024_01_15"
        partNumber, // EXAMPLE: 3
        timeout: 30000 // EXAMPLE: 30-second timeout per part
      });
    } catch (error) {
      console.error(`Failed to request part ${partNumber} for message ${messageId}:`, error);
    }
  }
  
  private handleAssemblyTimeout(messageId: string): void {
    console.warn(`Assembly timeout for message ${messageId}`);
    
    const parts = this.partCache.get(messageId);
    if (parts && parts.length > 0) {
      const totalParts = parts[0].total_parts;
      const missingParts = this.findMissingParts(parts, totalParts);
      
      console.error(`Message ${messageId} incomplete after timeout. Missing parts: ${missingParts.join(', ')}`);
      
      // Emit timeout event for application handling
      this.emitTimeoutEvent(messageId, missingParts);
    }
    
    // Clean up
    this.clearAssemblyTimeout(messageId);
    this.partCache.delete(messageId);
    this.partRequests.delete(messageId);
  }
  
  private clearAssemblyTimeout(messageId: string): void {
    const timeout = this.assemblyTimeouts.get(messageId);
    if (timeout) {
      clearTimeout(timeout);
      this.assemblyTimeouts.delete(messageId);
    }
  }
  
  private emitTimeoutEvent(messageId: string, missingParts: number[]): void {
    // Application-specific timeout handling
    console.log(`Emitting timeout event for message ${messageId}, missing parts: ${missingParts}`);
  }
}
```

### 2.3 Integrity Verification

All assembled messages must be verified against the `complete_message_hash`.

```typescript
// Comprehensive Integrity Verification
class MessageIntegrityVerifier {
  static async verifyAssembledMessage(
    assembledContent: Uint8Array,
    parts: KeystoneMultiPartMessagePart[]
  ): Promise<VerificationResult> {
    const messageId = parts[0]?.message_id;
    const expectedHash = parts[0]?.complete_message_hash;
    
    if (!messageId || !expectedHash) {
      return {
        valid: false,
        error: 'Missing message ID or expected hash',
        messageId
      };
    }
    
    try {
      // 1. Verify part ordering and completeness
      const orderingResult = this.verifyPartOrdering(parts);
      if (!orderingResult.valid) {
        return {
          valid: false,
          error: `Part ordering error: ${orderingResult.error}`,
          messageId
        };
      }
      
      // 2. Verify content hash
      const actualHash = await calculateCompleteMessageHash(assembledContent);
      if (actualHash !== expectedHash) {
        return {
          valid: false,
          error: `Hash mismatch: expected ${expectedHash}, got ${actualHash}`,
          messageId,
          expectedHash,
          actualHash
        };
      }
      
      // 3. Verify content length matches sum of parts
      const expectedLength = parts.reduce((sum, part) => sum + part.content.length, 0);
      if (assembledContent.length !== expectedLength) {
        return {
          valid: false,
          error: `Length mismatch: expected ${expectedLength}, got ${assembledContent.length}`,
          messageId
        };
      }
      
      return {
        valid: true,
        messageId,
        contentLength: assembledContent.length,
        partCount: parts.length
      };
      
    } catch (error) {
      return {
        valid: false,
        error: `Verification exception: ${error.message}`,
        messageId
      };
    }
  }
  
  private static verifyPartOrdering(parts: KeystoneMultiPartMessagePart[]): { valid: boolean; error?: string } {
    if (parts.length === 0) {
      return { valid: false, error: 'No parts provided' };
    }
    
    const totalParts = parts[0].total_parts;
    const messageId = parts[0].message_id;
    
    // Check all parts have same message_id and total_parts
    for (const part of parts) {
      if (part.message_id !== messageId) {
        return { valid: false, error: `Message ID mismatch: ${part.message_id} vs ${messageId}` };
      }
      if (part.total_parts !== totalParts) {
        return { valid: false, error: `Total parts mismatch: ${part.total_parts} vs ${totalParts}` };
      }
    }
    
    // Check for correct part numbering (1-based, sequential)
    const partNumbers = parts.map(p => p.part_number).sort((a, b) => a - b);
    
    if (partNumbers.length !== totalParts) {
      return { valid: false, error: `Part count mismatch: have ${partNumbers.length}, expected ${totalParts}` };
    }
    
    for (let i = 0; i < totalParts; i++) {
      if (partNumbers[i] !== i + 1) {
        return { valid: false, error: `Missing or duplicate part number: expected ${i + 1}, found ${partNumbers[i]}` };
      }
    }
    
    return { valid: true };
  }
}

interface VerificationResult {
  valid: boolean;
  messageId?: string;
  error?: string;
  expectedHash?: string;
  actualHash?: string;
  contentLength?: number;
  partCount?: number;
}
```

---

## 3. Storage Backend Considerations

### 3.1 IPFS Distribution Strategy

IPFS excels at content-addressed storage with natural deduplication and distributed availability.

```typescript
// IPFS Multi-Part Distribution
class IPFSMultiPartHandler {
  constructor(private ipfsClient: IPFSClient) {}
  
  async distributeMultiPartMessage(
    parts: KeystoneMultiPartMessagePart[]
  ): Promise<IPFSDistributionResult> {
    const distributionMap = new Map<number, string>();
    const pinPromises: Promise<void>[] = [];
    
    for (const part of parts) {
      try {
        // Store each part as separate IPFS content
        const partContent = this.serializeMultiPartMessage(part);
        const result = await this.ipfsClient.add(partContent, {
          pin: true, // EXAMPLE: Pin content for availability
          cidVersion: 1, // EXAMPLE: Use CIDv1 for better compatibility
          hashAlg: 'sha2-256' // EXAMPLE: SHA-256 hashing
        });
        
        const ipfsUri = `ipfs://${result.cid.toString()}`; // EXAMPLE: "ipfs://bafkreiabcd..."
        distributionMap.set(part.part_number, ipfsUri);
        
        // Ensure content is pinned across multiple nodes
        pinPromises.push(this.ensureRedundancy(result.cid.toString(), 3)); // EXAMPLE: 3-node redundancy
        
        console.log(`Stored part ${part.part_number} at ${ipfsUri}`);
        
      } catch (error) {
        console.error(`Failed to store part ${part.part_number}:`, error);
        throw new Error(`IPFS storage failed for part ${part.part_number}: ${error.message}`);
      }
    }
    
    // Wait for redundancy setup
    await Promise.all(pinPromises);
    
    return {
      messageId: parts[0].message_id,
      partURIs: distributionMap,
      totalParts: parts.length,
      redundancyLevel: 3 // EXAMPLE: Triple redundancy achieved
    };
  }
  
  private async ensureRedundancy(cid: string, targetNodes: number): Promise<void> {
    // Pin content across multiple IPFS nodes for redundancy
    const pinningServices = [
      'https://api.pinata.cloud', // EXAMPLE: Pinata pinning service
      'https://ipfs.infura.io', // EXAMPLE: Infura IPFS service
      'https://ipfs.fleek.co' // EXAMPLE: Fleek IPFS service
    ];
    
    const pinPromises = pinningServices.slice(0, targetNodes).map(async (service) => {
      try {
        await this.pinToService(service, cid);
        console.log(`Pinned ${cid} to ${service}`);
      } catch (error) {
        console.warn(`Failed to pin ${cid} to ${service}:`, error);
      }
    });
    
    await Promise.allSettled(pinPromises);
  }
  
  private async pinToService(serviceUrl: string, cid: string): Promise<void> {
    // Implementation would depend on specific pinning service API
    // This is a placeholder for the actual pinning logic
    console.log(`Pinning ${cid} to ${serviceUrl}`);
  }
  
  private serializeMultiPartMessage(part: KeystoneMultiPartMessagePart): Uint8Array {
    // Serialize the protobuf message to bytes
    // This would use your protobuf library's serialization
    return new Uint8Array(); // Placeholder
  }
}

interface IPFSDistributionResult {
  messageId: string;
  partURIs: Map<number, string>;
  totalParts: number;
  redundancyLevel: number;
}
```

### 3.2 Arweave Permanent Storage Strategy

Arweave provides permanent storage with larger capacity per transaction, ideal for fewer, larger parts.

```typescript
// Arweave Multi-Part Storage
class ArweaveMultiPartHandler {
  constructor(private arweaveClient: ArweaveClient, private wallet: JWKInterface) {}
  
  async storeMultiPartMessage(
    parts: KeystoneMultiPartMessagePart[]
  ): Promise<ArweaveStorageResult> {
    const transactions: ArweaveTransaction[] = [];
    const partURIs = new Map<number, string>();
    
    for (const part of parts) {
      try {
        // Create Arweave transaction for each part
        const partData = this.serializeMultiPartMessage(part);
        const transaction = await this.arweaveClient.createTransaction({
          data: partData
        }, this.wallet);
        
        // Add tags for discoverability
        transaction.addTag('Content-Type', 'application/x-protobuf');
        transaction.addTag('Keystone-Message-ID', part.message_id); // EXAMPLE: Message identifier
        transaction.addTag('Keystone-Part-Number', part.part_number.toString()); // EXAMPLE: Part number
        transaction.addTag('Keystone-Total-Parts', part.total_parts.toString()); // EXAMPLE: Total parts
        transaction.addTag('Keystone-Protocol-Version', '1.0'); // EXAMPLE: Protocol version
        
        // Sign and post transaction
        await this.arweaveClient.transactions.sign(transaction, this.wallet);
        const response = await this.arweaveClient.transactions.post(transaction);
        
        if (response.status === 200) {
          const arweaveUri = `arweave://${transaction.id}`; // EXAMPLE: "arweave://abc123def456"
          partURIs.set(part.part_number, arweaveUri);
          transactions.push(transaction);
          
          console.log(`Stored part ${part.part_number} with transaction ID: ${transaction.id}`);
        } else {
          throw new Error(`Arweave transaction failed with status ${response.status}`);
        }
        
      } catch (error) {
        console.error(`Failed to store part ${part.part_number} on Arweave:`, error);
        throw new Error(`Arweave storage failed for part ${part.part_number}: ${error.message}`);
      }
    }
    
    return {
      messageId: parts[0].message_id,
      transactions,
      partURIs,
      totalParts: parts.length,
      estimatedConfirmationTime: 600000 // EXAMPLE: 10 minutes for confirmation
    };
  }
  
  async waitForConfirmations(
    transactions: ArweaveTransaction[],
    requiredConfirmations: number = 5 // EXAMPLE: Wait for 5 confirmations
  ): Promise<boolean> {
    const confirmationPromises = transactions.map(async (tx) => {
      let confirmations = 0;
      const maxAttempts = 60; // EXAMPLE: Maximum 60 attempts (30 minutes)
      
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
          const status = await this.arweaveClient.transactions.getStatus(tx.id);
          
          if (status.confirmed && status.confirmed.number_of_confirmations >= requiredConfirmations) {
            console.log(`Transaction ${tx.id} confirmed with ${status.confirmed.number_of_confirmations} confirmations`);
            return true;
          }
          
          // Wait 30 seconds before next check
          await new Promise(resolve => setTimeout(resolve, 30000));
          
        } catch (error) {
          console.warn(`Error checking transaction status for ${tx.id}:`, error);
        }
      }
      
      console.error(`Transaction ${tx.id} not confirmed after maximum attempts`);
      return false;
    });
    
    const results = await Promise.all(confirmationPromises);
    return results.every(confirmed => confirmed);
  }
  
  private serializeMultiPartMessage(part: KeystoneMultiPartMessagePart): Uint8Array {
    // Serialize the protobuf message to bytes
    return new Uint8Array(); // Placeholder
  }
}

interface ArweaveStorageResult {
  messageId: string;
  transactions: ArweaveTransaction[];
  partURIs: Map<number, string>;
  totalParts: number;
  estimatedConfirmationTime: number;
}
```

### 3.3 XRPL Memo Field Distribution

XRPL memo fields have strict size limits, requiring very small parts and careful encoding.

```typescript
// XRPL Memo Field Multi-Part Handler
class XRPLMemoMultiPartHandler {
  constructor(private xrplClient: XRPLClient, private wallet: XRPLWallet) {}
  
  private readonly MAX_MEMO_SIZE = 1024; // EXAMPLE: 1KB XRPL memo limit
  private readonly EFFECTIVE_PART_SIZE = 512; // EXAMPLE: 512 bytes after encoding overhead
  
  async distributeViaXRPLMemos(
    parts: KeystoneMultiPartMessagePart[]
  ): Promise<XRPLDistributionResult> {
    const transactions: XRPLTransaction[] = [];
    
    // XRPL parts need to be much smaller due to memo size limits
    const xrplParts = await this.createXRPLCompatibleParts(parts);
    
    for (const xrplPart of xrplParts) {
      try {
        // Create XRPL transaction with memo containing part data
        const transaction: XRPLTransaction = {
          TransactionType: 'Payment',
          Account: this.wallet.address, // EXAMPLE: Sender address
          Destination: this.wallet.address, // EXAMPLE: Self-send for memo storage
          Amount: '1', // EXAMPLE: Minimal XRP amount (1 drop)
          Memos: [
            {
              Memo: {
                MemoType: this.hexEncode('KeystoneMultiPart'), // EXAMPLE: Keystone identifier
                MemoFormat: this.hexEncode('application/x-protobuf'), // EXAMPLE: Content format
                MemoData: this.hexEncode(xrplPart.data) // EXAMPLE: Hex-encoded part data
              }
            }
          ],
          Fee: '12' // EXAMPLE: Standard XRPL fee
        };
        
        // Sign and submit transaction
        const prepared = await this.xrplClient.autofill(transaction);
        const signed = this.wallet.sign(prepared);
        const result = await this.xrplClient.submitAndWait(signed.tx_blob);
        
        if (result.result.meta.TransactionResult === 'tesSUCCESS') {
          transactions.push({
            ...transaction,
            hash: result.result.hash, // EXAMPLE: Transaction hash
            ledger: result.result.ledger_index // EXAMPLE: Ledger index
          });
          
          console.log(`Stored XRPL part ${xrplPart.partNumber} in transaction ${result.result.hash}`);
        } else {
          throw new Error(`XRPL transaction failed: ${result.result.meta.TransactionResult}`);
        }
        
      } catch (error) {
        console.error(`Failed to store XRPL part ${xrplPart.partNumber}:`, error);
        throw new Error(`XRPL storage failed for part ${xrplPart.partNumber}: ${error.message}`);
      }
    }
    
    return {
      messageId: parts[0].message_id,
      transactions,
      totalXRPLParts: xrplParts.length,
      totalOriginalParts: parts.length
    };
  }
  
  private async createXRPLCompatibleParts(
    originalParts: KeystoneMultiPartMessagePart[]
  ): Promise<XRPLPartData[]> {
    const xrplParts: XRPLPartData[] = [];
    let xrplPartNumber = 1;
    
    for (const originalPart of originalParts) {
      const partData = this.serializeMultiPartMessage(originalPart);
      
      // Split large parts into XRPL-compatible chunks
      const chunks = this.chunkData(partData, this.EFFECTIVE_PART_SIZE);
      
      for (const chunk of chunks) {
        xrplParts.push({
          partNumber: xrplPartNumber++,
          originalPartNumber: originalPart.part_number,
          data: chunk,
          messageId: originalPart.message_id
        });
      }
    }
    
    return xrplParts;
  }
  
  private chunkData(data: Uint8Array, chunkSize: number): Uint8Array[] {
    const chunks: Uint8Array[] = [];
    
    for (let i = 0; i < data.length; i += chunkSize) {
      const chunk = data.slice(i, i + chunkSize);
      chunks.push(chunk);
    }
    
    return chunks;
  }
  
  private hexEncode(data: string | Uint8Array): string {
    if (typeof data === 'string') {
      return Buffer.from(data, 'utf8').toString('hex').toUpperCase();
    } else {
      return Buffer.from(data).toString('hex').toUpperCase();
    }
  }
  
  private serializeMultiPartMessage(part: KeystoneMultiPartMessagePart): Uint8Array {
    return new Uint8Array(); // Placeholder
  }
}

interface XRPLPartData {
  partNumber: number;
  originalPartNumber: number;
  data: Uint8Array;
  messageId: string;
}

interface XRPLDistributionResult {
  messageId: string;
  transactions: XRPLTransaction[];
  totalXRPLParts: number;
  totalOriginalParts: number;
}
```

### 3.4 Hybrid Storage Strategy with Failover

Combine multiple storage backends for maximum reliability and availability.

```typescript
// Hybrid Multi-Backend Storage Strategy
class HybridMultiPartStorage {
  private handlers: Map<string, any> = new Map();
  
  constructor() {
    // Initialize storage backend handlers
    this.handlers.set('IPFS', new IPFSMultiPartHandler(ipfsClient));
    this.handlers.set('ARWEAVE', new ArweaveMultiPartHandler(arweaveClient, wallet));
    this.handlers.set('XRPL', new XRPLMemoMultiPartHandler(xrplClient, xrplWallet));
  }
  
  async distributeWithRedundancy(
    parts: KeystoneMultiPartMessagePart[],
    primaryBackend: string = 'IPFS', // EXAMPLE: Primary storage backend
    fallbackBackends: string[] = ['ARWEAVE'], // EXAMPLE: Fallback options
    redundancyLevel: number = 2 // EXAMPLE: Store on 2 different backends
  ): Promise<HybridDistributionResult> {
    
    const results: StorageResult[] = [];
    const allBackends = [primaryBackend, ...fallbackBackends];
    
    // Attempt storage on multiple backends for redundancy
    for (let i = 0; i < Math.min(redundancyLevel, allBackends.length); i++) {
      const backend = allBackends[i];
      const handler = this.handlers.get(backend);
      
      if (!handler) {
        console.warn(`No handler available for backend: ${backend}`);
        continue;
      }
      
      try {
        console.log(`Attempting storage on ${backend}...`);
        
        // Adjust parts based on backend limitations
        const adjustedParts = await this.adjustPartsForBackend(parts, backend);
        
        let result: any;
        switch (backend) {
          case 'IPFS':
            result = await handler.distributeMultiPartMessage(adjustedParts);
            break;
          case 'ARWEAVE':
            result = await handler.storeMultiPartMessage(adjustedParts);
            break;
          case 'XRPL':
            result = await handler.distributeViaXRPLMemos(adjustedParts);
            break;
          default:
            throw new Error(`Unknown backend: ${backend}`);
        }
        
        results.push({
          backend,
          success: true,
          result,
          timestamp: new Date().toISOString() // EXAMPLE: ISO 8601 timestamp
        });
        
        console.log(`Successfully stored on ${backend}`);
        
      } catch (error) {
        console.error(`Storage failed on ${backend}:`, error);
        
        results.push({
          backend,
          success: false,
          error: error.message,
          timestamp: new Date().toISOString() // EXAMPLE: ISO 8601 timestamp
        });
      }
    }
    
    // Check if we achieved minimum redundancy
    const successfulStores = results.filter(r => r.success).length;
    
    if (successfulStores === 0) {
      throw new Error('All storage backends failed');
    }
    
    if (successfulStores < redundancyLevel) {
      console.warn(`Only achieved ${successfulStores}/${redundancyLevel} redundancy level`);
    }
    
    return {
      messageId: parts[0].message_id,
      results,
      achievedRedundancy: successfulStores,
      targetRedundancy: redundancyLevel
    };
  }
  
  private async adjustPartsForBackend(
    parts: KeystoneMultiPartMessagePart[],
    backend: string
  ): Promise<KeystoneMultiPartMessagePart[]> {
    
    const limits = STORAGE_BACKEND_LIMITS[`STORAGE_BACKEND_${backend}`];
    if (!limits) {
      return parts; // No adjustment needed
    }
    
    // If parts are too large for this backend, re-split them
    const maxPartSize = limits.optimalPartSize;
    const needsResplit = parts.some(part => part.content.length > maxPartSize);
    
    if (!needsResplit) {
      return parts; // Parts are already appropriate size
    }
    
    console.log(`Re-splitting parts for ${backend} backend (max size: ${maxPartSize})`);
    
    // Reassemble original content and re-split for this backend
    const assembledContent = this.assembleContentFromParts(parts);
    const messageId = `${parts[0].message_id}_${backend.toLowerCase()}`; // EXAMPLE: Backend-specific message ID
    
    return await KeystoneMessageSplitter.splitContent(
      assembledContent,
      maxPartSize,
      messageId
    );
  }
  
  private assembleContentFromParts(parts: KeystoneMultiPartMessagePart[]): Uint8Array {
    // Sort parts by part number
    const sortedParts = [...parts].sort((a, b) => a.part_number - b.part_number);
    
    // Concatenate content
    const totalLength = sortedParts.reduce((sum, part) => sum + part.content.length, 0);
    const assembled = new Uint8Array(totalLength);
    
    let offset = 0;
    for (const part of sortedParts) {
      assembled.set(part.content, offset);
      offset += part.content.length;
    }
    
    return assembled;
  }
}

interface HybridDistributionResult {
  messageId: string;
  results: StorageResult[];
  achievedRedundancy: number;
  targetRedundancy: number;
}

interface StorageResult {
  backend: string;
  success: boolean;
  result?: any;
  error?: string;
  timestamp: string;
}
```

---

## 4. Error Handling for Incomplete Messages

### Comprehensive Error Recovery Patterns

```typescript
// Error Handling and Recovery System
class MultiPartErrorHandler {
  
  static async handleAssemblyError(
    error: AssemblyError,
    availableParts: KeystoneMultiPartMessagePart[]
  ): Promise<RecoveryAction> {
    
    switch (error.type) {
      case 'MISSING_PARTS':
        return await this.handleMissingParts(error, availableParts);
      
      case 'INTEGRITY_FAILURE':
        return await this.handleIntegrityFailure(error, availableParts);
      
      case 'TIMEOUT':
        return await this.handleTimeout(error, availableParts);
      
      case 'CORRUPTED_PART':
        return await this.handleCorruptedPart(error, availableParts);
      
      default:
        return {
          action: 'ABORT',
          reason: `Unknown error type: ${error.type}`,
          retryable: false
        };
    }
  }
  
  private static async handleMissingParts(
    error: AssemblyError,
    availableParts: KeystoneMultiPartMessagePart[]
  ): Promise<RecoveryAction> {
    
    const messageId = availableParts[0]?.message_id;
    const totalParts = availableParts[0]?.total_parts || 0;
    const presentParts = new Set(availableParts.map(p => p.part_number));
    const missingParts: number[] = [];
    
    // Identify missing parts
    for (let i = 1; i <= totalParts; i++) {
      if (!presentParts.has(i)) {
        missingParts.push(i);
      }
    }
    
    console.warn(`Message ${messageId} missing parts: ${missingParts.join(', ')}`);
    
    // Attempt recovery based on missing part count
    const missingPercentage = (missingParts.length / totalParts) * 100;
    
    if (missingPercentage <= 10) {
      // Less than 10% missing - attempt targeted recovery
      return {
        action: 'RETRY_MISSING',
        reason: `Attempting to recover ${missingParts.length} missing parts`,
        retryable: true,
        missingParts,
        strategy: 'TARGETED_REQUEST'
      };
    } else if (missingPercentage <= 50) {
      // 10-50% missing - attempt broader recovery
      return {
        action: 'RETRY_MISSING',
        reason: `High missing parts (${missingPercentage.toFixed(1)}%), attempting broad recovery`,
        retryable: true,
        missingParts,
        strategy: 'BROADCAST_REQUEST'
      };
    } else {
      // More than 50% missing - recommend abort
      return {
        action: 'ABORT',
        reason: `Too many missing parts (${missingPercentage.toFixed(1)}%), recovery unlikely`,
        retryable: false,
        missingParts
      };
    }
  }
  
  private static async handleIntegrityFailure(
    error: AssemblyError,
    availableParts: KeystoneMultiPartMessagePart[]
  ): Promise<RecoveryAction> {
    
    const messageId = availableParts[0]?.message_id;
    console.error(`Integrity check failed for message ${messageId}: ${error.details}`);
    
    // Check if all parts have consistent hash expectations
    const expectedHashes = new Set(availableParts.map(p => p.complete_message_hash));
    
    if (expectedHashes.size > 1) {
      // Parts have different expected hashes - critical error
      return {
        action: 'ABORT',
        reason: 'Parts have inconsistent expected hashes - possible corruption or tampering',
        retryable: false,
        evidence: Array.from(expectedHashes)
      };
    }
    
    // Single expected hash but integrity failed - possible part corruption
    return {
      action: 'RETRY_ALL',
      reason: 'Integrity failure with consistent hashes - requesting fresh parts',
      retryable: true,
      strategy: 'FRESH_RETRIEVAL'
    };
  }
  
  private static async handleTimeout(
    error: AssemblyError,
    availableParts: KeystoneMultiPartMessagePart[]
  ): Promise<RecoveryAction> {
    
    const messageId = availableParts[0]?.message_id;
    const completionPercentage = availableParts.length / (availableParts[0]?.total_parts || 1) * 100;
    
    console.warn(`Assembly timeout for message ${messageId} (${completionPercentage.toFixed(1)}% complete)`);
    
    if (completionPercentage >= 80) {
      // Close to complete - extend timeout and continue
      return {
        action: 'EXTEND_TIMEOUT',
        reason: `Near completion (${completionPercentage.toFixed(1)}%), extending timeout`,
        retryable: true,
        extendedTimeoutMs: 600000 // EXAMPLE: Extend by 10 minutes
      };
    } else if (completionPercentage >= 50) {
      // Moderate progress - retry with longer timeout
      return {
        action: 'RETRY_WITH_TIMEOUT',
        reason: `Moderate progress (${completionPercentage.toFixed(1)}%), retrying with extended timeout`,
        retryable: true,
        timeoutMs: 900000 // EXAMPLE: 15-minute timeout
      };
    } else {
      // Little progress - likely network issues
      return {
        action: 'ABORT',
        reason: `Insufficient progress (${completionPercentage.toFixed(1)}%) after timeout`,
        retryable: false,
        suggestion: 'Check network connectivity and storage backend availability'
      };
    }
  }
  
  private static async handleCorruptedPart(
    error: AssemblyError,
    availableParts: KeystoneMultiPartMessagePart[]
  ): Promise<RecoveryAction> {
    
    const corruptedPartNumber = error.partNumber;
    const messageId = availableParts[0]?.message_id;
    
    console.error(`Corrupted part ${corruptedPartNumber} detected for message ${messageId}`);
    
    return {
      action: 'RETRY_SPECIFIC',
      reason: `Replacing corrupted part ${corruptedPartNumber}`,
      retryable: true,
      specificParts: [corruptedPartNumber],
      strategy: 'ALTERNATIVE_SOURCE'
    };
  }
}

// Error Types and Recovery Actions
interface AssemblyError {
  type: 'MISSING_PARTS' | 'INTEGRITY_FAILURE' | 'TIMEOUT' | 'CORRUPTED_PART';
  messageId: string;
  details: string;
  partNumber?: number;
  timestamp: string;
}

interface RecoveryAction {
  action: 'RETRY_MISSING' | 'RETRY_ALL' | 'RETRY_SPECIFIC' | 'EXTEND_TIMEOUT' | 'RETRY_WITH_TIMEOUT' | 'ABORT';
  reason: string;
  retryable: boolean;
  missingParts?: number[];
  specificParts?: number[];
  strategy?: 'TARGETED_REQUEST' | 'BROADCAST_REQUEST' | 'FRESH_RETRIEVAL' | 'ALTERNATIVE_SOURCE';
  timeoutMs?: number;
  extendedTimeoutMs?: number;
  evidence?: any[];
  suggestion?: string;
}
```

## Best Practices Summary

### 1. Message Splitting Best Practices
- **Calculate `complete_message_hash` before splitting** to ensure integrity verification
- **Use backend-appropriate part sizes** to optimize storage efficiency and costs
- **Implement consistent part numbering** with 1-based indexing for clear ordering
- **Include redundant metadata** in each part for recovery and verification

### 2. Message Assembly Best Practices  
- **Implement timeout and retry logic** for handling network delays and failures
- **Verify part ordering and completeness** before attempting assembly
- **Always verify integrity** against `complete_message_hash` after assembly
- **Handle out-of-order delivery** with proper sorting and buffering

### 3. Storage Backend Best Practices
- **Choose backends based on content characteristics**: IPFS for medium files, Arweave for permanent storage, XRPL for small critical data
- **Implement hybrid strategies** with multiple backends for redundancy
- **Monitor backend availability** and implement failover mechanisms
- **Consider costs and confirmation times** when selecting storage strategies

### 4. Error Handling Best Practices
- **Implement comprehensive error recovery** for missing, corrupted, or delayed parts
- **Log assembly progress and errors** for debugging and monitoring
- **Provide clear error messages** with actionable recovery suggestions
- **Set reasonable timeouts** based on content size and network conditions

This comprehensive documentation provides the foundation for implementing robust multi-part message support in the Keystone Protocol, ensuring reliable transmission of large content across diverse storage backends while maintaining integrity and enabling efficient assembly patterns. 