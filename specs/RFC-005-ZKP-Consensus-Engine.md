# RFC 005: ZKP-Enabled Context Consensus Engine

## Status
Draft (RFC-005)

## 1. Introduction & Objectives
In the Memact Protocol framework, users interact with multiple federated applications. Under the **Context Contribution Protocol (CCP)**, these applications contribute claims and evidence (e.g. location data, email verification, credit ratings) to update the user's unified context. 

When multiple applications write to the user's context concurrently, two core problems arise:
1. **Privacy Leakage**: Reconciling and storing raw contribution histories exposes user activity to the Identity Provider (IdP) and auditors.
2. **State Conflict & Consensus**: Different applications may submit conflicting values for the same claim (e.g. App A asserts user location is `US`, App B asserts it is `DE`). 

This RFC proposes a **Zero-Knowledge Proof (ZKP) Consensus Engine**. It acts as a privacy-preserving state reconciliation engine that processes context transitions in batches (rollup-style), resolves conflicts cryptographically according to trust policies, and yields verifiable proofs of context progression.

---

## 2. Context State Representation

A user's context state is organized as a **Sparse Merkle Tree (SMT)** of depth 256, where leaf indices are derived from the cryptographic hash of claim keys.

```
                  [ Context State Root (CSR) ]
                            /     \
                          ...     ...
                          /         \
                 [Hash Node]       [Hash Node]
                   /     \           /     \
                 ...     ...       ...     ...
                 /
            [Leaf Claim] 
         H(Key, Value, Salt)
```

### 2.1. Leaf Structure
Each leaf in the SMT contains a hash representing a single context attribute:
$$\text{Leaf}_i = \text{Poseidon}(\text{claim\_key}, \text{claim\_value}, \text{salt})$$
* **`claim_key`**: Field element representing the claim path (e.g., hash of `"user.location"`).
* **`claim_value`**: Field element representing the value of the attribute.
* **`salt`**: A cryptographically random field element to protect against dictionary scanning attacks.

The root of this tree represents the **Context State Root (CSR)**.

---

## 3. Context Transition Transaction (CTT)

Applications contribute to the context by submitting a **Context Transition Transaction (CTT)** to the consensus pool (mempool).

### 3.1. Structure of a CTT
```json
{
  "sender_identity": "app_client_id_1234",
  "old_state_root": "0x12a3f...",
  "new_state_root": "0x5b7d9...",
  "claim_key": "0x98f21...",
  "proof": {
    "pi_a": ["0x...", "0x..."],
    "pi_b": [["0x...", "0x..."], ["0x...", "0x..."]],
    "pi_c": ["0x...", "0x..."]
  },
  "public_inputs": {
    "old_state_root": "0x12a3f...",
    "new_state_root": "0x5b7d9...",
    "claim_key_hash": "0x98f21...",
    "contributor_authority_hash": "0x32b5e..."
  }
}
```

### 3.2. Circuit Verification Rules
The transition ZK circuit proves that:
1. **Membership Verification**: The leaf at `claim_key` in the SMT with root `old_state_root` has a value corresponding to the previous state.
2. **Authority Verification**: The `sender_identity` is authorized to update the claim at `claim_key` (proves possession of a valid signature matching an authorized public key stored in the tree's access control leaves).
3. **State Transition**: Replacing the old leaf with the new leaf hash correctly recalculates the Merkle path and yields `new_state_root`.

---

## 4. Consensus Engine & Batch Prover (ZK-Rollup)

To achieve scalability and resolve disputes across multiple federated nodes, validators collect CTTs and run a **Batch Prover** that consolidates updates.

```
+-------------------------------------------------------------+
|                     Consensus Engine                        |
|                                                             |
|   [CTT 1]  [CTT 2]  [CTT 3] ... [CTT N]                     |
|      \        |        /                                    |
|       v       v       v                                     |
|    +---------------------+                                  |
|    | Conflict Resolution | -> Eval trust weights / timestamps|
|    +----------+----------+                                  |
|               |                                             |
|               v (Batched updates)                           |
|    +---------------------+                                  |
|    | Batch Prover Circuit| -> Computes multi-level SMT logic|
|    +----------+----------+                                  |
|               |                                             |
+---------------|---------------------------------------------+
                v
  [ Batch Consensus Block ]
    - CSR_old (0x12a...)
    - CSR_new (0x9ef...)
    - Batch Transition Proof
```

### 4.1. Conflict Resolution Logic (CRP Integration)
If the mempool contains conflicting updates for the same `claim_key` (e.g. different locations from different apps), the consensus engine resolves them prior to batch proving:
1. **Trust Weight Evaluation**: Each contributor application has a registered trust weight stored in the tree. The circuit selects the value from the contributor with the highest weight.
2. **Timestamp/Sequence Evaluation**: If trust weights are identical, the update with the latest verified timestamp is selected.
3. The Batch Prover verifies that the conflict resolution logic was correctly executed by evaluating the weights inside the circuit, generating a proof that the winner was selected mathematically.

### 4.2. Batch Proof Execution
The batch circuit processes $N$ updates sequentially:
* Inputs: $CSR_{0}, CTT_{1}, CTT_{2}, \dots, CTT_{N}$.
* Output: $CSR_{N}$ and a single zk-SNARK proof demonstrating the valid progression of the state root through the $N$ transitions.

---

## 5. Ledger Synchronization & Verification

The output of the consensus engine is a **Consensus Block**. It is submitted to the federated consensus network (e.g., validator nodes running Proof of Authority).

### 5.1. Validator Block Validation Algorithm
Upon receiving a new block proposal, validators verify the block without accessing raw database states:
1. **Verify State Transition**:
   ```typescript
   import { verifyBatchProof } from '@memact/contracts/zk-consensus';

   const isTransitionValid = await verifyBatchProof(
     validationKey,
     block.old_state_root,
     block.new_state_root,
     block.batch_proof
   );

   if (!isTransitionValid) {
     throw new Error("Invalid consensus block state transition proof");
   }
   ```
2. **Sign Block**: If the proof is valid, the validator signs the block header.
3. **Commit State**: Once a supermajority of signatures is collected, the state root $CSR_{new}$ is committed as the canonical context root.
