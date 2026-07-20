# Epic: Zero Knowledge Proofs (ZKP) OAuth Flow
## Repository: Protocol
## Epic Mapping Document

This document outlines the specific implementation issues to be created in the issue trackers of the four repositories of the Memact family: `Protocol`, `Contracts`, `Access` (Identity Provider), and `SDK`.

---

## 1. Protocol Repository (`Protocol`)

### Issue PROTOCOL-101: Draft RFC-004: ZKP-Enabled CAP OAuth 2.0 Flow
* **Type**: Feature / Specification
* **Priority**: High
* **Description**:
  Create the formal protocol specification (RFC-004) detailing how clients request cryptographic zero-knowledge claims during a CAP context assertion request. Define URL parameters, JWT/Token structures, validation logic, and anti-replay nonce protocols.
* **Acceptance Criteria**:
  * RFC-004 markdown document is merged in `specs/`.
  * Describes the cryptographic curves (BN254) and proof models (Groth16).
  * Covers the detailed sequencing of interactions between the Client App, User Agent, Identity Provider, and Verification registry.

### Issue PROTOCOL-102: Define JSON Schemas for Request and Response payloads
* **Type**: Feature / Schema Definition
* **Priority**: High
* **Description**:
  Author JSON schemas for `zkp-request` and `zkp-response` to validate the structures for incoming client queries and outgoing token assertions.
* **Acceptance Criteria**:
  * JSON schema files created in `schemas/zkp-request.schema.json` and `schemas/zkp-response.schema.json`.
  * Validate that fields like `circuit_id`, `assertion`, `proof` (containing `pi_a`, `pi_b`, `pi_c`), and `public_inputs` have strict types, min/max values, and regex matching.

---

## 2. Contracts Repository (`Contracts`)

### Issue CONTRACTS-201: Implement Core ZK-SNARK Verification Library
* **Type**: Feature
* **Priority**: Critical (Blocker for SDK verification)
* **Description**:
  Implement a helper utility module in the contracts repository to verify Groth16 zk-SNARK proofs. The verification library should accept a verification key (`vk`), a list of public inputs, and a proof, returning a boolean indicating validity.
* **Acceptance Criteria**:
  * Provide functions compiling to JS/TS or WASM wrapper interface: `verifyProof(vk, publicInputs, proof): Promise<boolean>`.
  * Add unit tests using simulated valid/invalid proof inputs on BN254.

### Issue CONTRACTS-202: Create Circuit Verification Key Registry
* **Type**: Task
* **Priority**: Medium
* **Description**:
  Create a workspace storage or config directory containing JSON verification keys (`vkey.json`) for the baseline supported circuits:
  1. `range_proof_date`: verifying date comparisons (LT, GT).
  2. `membership_proof`: verifying array membership (IN, NOT_IN).
  3. `string_equality`: verifying exact attribute matches (EQ, NEQ).
* **Acceptance Criteria**:
  * Registry files loaded into the build/dist bundle.
  * Endpoint/Assets created allowing IdP and SDK to reference keys using deterministic URLs.

---

## 3. Access Repository (Reference IdP: `Access`)

### Issue ACCESS-301: Implement Authorization Endpoint Claims Parser
* **Type**: Feature
* **Priority**: High
* **Description**:
  Modify the authorization endpoint `/authorize` to check for `scope=cap:zkp` and parse the URL-encoded `zkp_request` JSON parameter.
* **Acceptance Criteria**:
  * Parse and validate `zkp_request` parameter against `zkp-request.schema.json` upon receiving authorization requests.
  * Store the parsed request parameters along with the session state.

### Issue ACCESS-302: Integrate ZK Proving Pipeline
* **Type**: Feature
* **Priority**: High
* **Description**:
  Implement the proving engine inside the IdP. When generating the context token, fetch the user's private attribute value, the attribute salt, and the public comparison target. Run the prover (e.g. `snarkjs` or an off-process rust/go microservice) using the Proving Key corresponding to `circuit_id` to generate the proof.
* **Acceptance Criteria**:
  * Proof is generated successfully for matching assertions.
  * Correct witness generation incorporating the private attribute and salt.

### Issue ACCESS-303: Format `/token` response claims
* **Type**: Feature
* **Priority**: High
* **Description**:
  Modify the JWT token builder or `/token` endpoint response to inject the generated proof and public inputs structure under the token field `cap_zkp_assertion`.
* **Acceptance Criteria**:
  * Response conforms to `zkp-response.schema.json`.
  * The field `verification_key_uri` is correctly resolved dynamically to point to the host's key registry location.

---

## 4. Client SDK Repository (`SDK`)

### Issue SDK-401: Support ZKP Parameter Builders in Authorization Client
* **Type**: Feature
* **Priority**: High
* **Description**:
  Extend the CAP SDK Authorization Request client builder to accept ZK assertion constraints and serialise them into standard request structures.
* **Acceptance Criteria**:
  * Add builder functions like `.withZKPAgeProof(dateLimit, operator)` or `.withZKPClaimConstraint(claim, operator, value)`.
  * Ensure a high-entropy cryptographically random `nonce` is auto-generated and stored in the client session storage when building requests.

### Issue SDK-402: Implement Client-Side Token Verification Interceptor
* **Type**: Feature
* **Priority**: High
* **Description**:
  Implement client-side off-chain validation of the token's ZKP claim. When receiving the tokens at the redirect callback, intercept the token validation and perform ZKP verification using the Contracts verification library.
* **Acceptance Criteria**:
  * The SDK checks if `cap_zkp_assertion` is present.
  * If present, fetches the VK from `verification_key_uri` (or hits a local cached copy) and calls the verification library.
  * Ensure the verification fails if the assertion nonce does not match the stored session nonce.
  * Rejects token usage/onboarding if the proof is invalid.
