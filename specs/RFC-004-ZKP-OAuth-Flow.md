# RFC 004: ZKP-Enabled CAP OAuth 2.0 Flow

## Status
Draft (RFC-004)

## 1. Introduction & Objectives
In standard federated identity and context sharing protocols (e.g. OpenID Connect and CAP), the Client (Relying Party) requests specific user attributes (claims) from the Identity Provider (IdP). The IdP then returns these raw values (e.g. date of birth, residential address, group membership list). 

This model exposes personal data, allowing Clients to profile users and track them across sessions. 

This RFC introduces a **Zero Knowledge Proof (ZKP) extension** for the **Context Access Protocol (CAP)**. It allows clients to query and verify user attributes using relational assertions (e.g., "is older than 18", "lives in US", "is a member of the admin group") without requiring the IdP to return raw data values to the Client.

### Objectives
* **Privacy by Design**: Hide raw attribute values from Client applications.
* **Integrity & Authenticity**: Ensure assertions are cryptographically linked to values signed/managed by a trusted IdP.
* **OAuth Compatibility**: Build on top of standard OAuth 2.0 and OIDC flow semantics.
* **Off-chain Verification**: Enable Clients to verify proofs locally on client-side SDKs or backend servers.

---

## 2. Cryptographic Architecture

The protocol uses a delegated proving model based on **zk-SNARKs** (specifically Groth16 over the BN254 elliptic curve).

```
+--------------------------------------------------------+
|                      IdP (Access)                      |
|                                                        |
|   Private Witness:                                     |
|     - user_attribute_value (e.g., "1995-05-10")        |
|     - attribute_salt                                   |
|                                                        |
|   Public Inputs:                                       |
|     - H(attribute_salt, claim_name)                    |
|     - target_value (e.g., "2008-07-11")                |
|     - nonce                                            |
|                                                        |
|   Proving Key (PK)  -->  Generates Cryptographic Proof  |
+--------------------------+-----------------------------+
                           |
                           v  (Delivered via token)
+--------------------------+-----------------------------+
|                     Client (SDK)                       |
|                                                        |
|   Verify(Proof, Public Inputs, Verification Key)       |
|   ==> True/False                                       |
+--------------------------------------------------------+
```

### Proving System Parameters
* **Schema Scheme**: BN254 Pairing-Friendly Elliptic Curve.
* **Proving System**: Groth16 zk-SNARK.
* **Circuit Registry**: Supported assertions are mapped to specific circuits (e.g., `range_proof`, `membership_proof`, `string_equality`).

---

## 3. Protocol Flow

### 3.1. Authorization Request
The Client initiates the flow by redirecting the User Agent to the IdP's `/authorize` endpoint. The client specifies `scope=cap:zkp` and includes a custom `zkp_request` JSON payload (URL-encoded).

#### Parameters
* `scope`: MUST contain `cap:zkp`.
* `zkp_request`: A JSON object matching the `zkp-request.schema.json` schema.

#### Example Authorization Request URI
```http
GET /authorize?
    response_type=code
    &client_id=client_98234
    &redirect_uri=https%3A%2F%2Fclient.app%2Fcallback
    &scope=openid%20cap%3Azkp
    &zkp_request=%7B%22circuit_id%22%3A%22range_proof_date%22%2C%22assertion%22%3A%7B%22claim%22%3A%22date_of_birth%22%2C%22operator%22%3A%22LT%22%2C%22value%22%3A%222008-07-11%22%7D%2C%22nonce%22%3A%22d3b07384d113edec%22%7D
    &state=xyz123 HTTP/1.1
Host: identity.memact.org
```

#### JSON Representation of `zkp_request`
```json
{
  "circuit_id": "range_proof_date",
  "assertion": {
    "claim": "date_of_birth",
    "operator": "LT",
    "value": "2008-07-11"
  },
  "nonce": "d3b07384d113edec"
}
```

### 3.2. Consent & Proof Generation
1. The IdP authenticates the user and verifies that the user document contains the requested `claim` (e.g. `date_of_birth`).
2. The IdP presents the user with a consent screen:
   > *"Client App wants to verify that your date of birth is before 2008-07-11 (over 18). Your actual date of birth will not be shared."*
3. Upon approval, the IdP executes the zk-SNARK prover for the specified `circuit_id`:
   - **Private Inputs (Witness)**:
     - `private_attribute_value`: The actual attribute (e.g. `1995-05-10`).
     - `attribute_salt`: A cryptographically secure random salt associated with the attribute to prevent dictionary attacks on public inputs.
   - **Public Inputs**:
     - `attribute_hash`: Cryptographic hash of the attribute name combined with the salt, e.g., `SHA-256(attribute_salt || "date_of_birth")`.
     - `operator`: Numeric code representing the operator (e.g., `LT` = 1).
     - `comparison_value`: Numerical/hashed representation of the comparison target (`2008-07-11`).
     - `nonce`: The client's unique nonce.
4. The IdP generates the proof (`pi_a`, `pi_b`, `pi_c`) and associates it with the temporary authorization code.

### 3.3. Token Response
The Client exchanges the authorization code for tokens using a POST request to `/token`. 

The response returns an Access Token containing a custom claims parameter `cap_zkp_assertion`.

#### Example Token Response Body
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "cap_zkp_assertion": {
    "circuit_id": "range_proof_date",
    "verification_key_uri": "https://identity.memact.org/circuits/range_proof_date/vkey.json",
    "public_inputs": {
      "attribute_hash": "0x1a2b3c4d5e...",
      "operator": "LT",
      "value": "2008-07-11",
      "nonce": "d3b07384d113edec"
    },
    "proof": {
      "pi_a": ["0x123...", "0x456..."],
      "pi_b": [
        ["0x789...", "0xabc..."],
        ["0xdef...", "0x012..."]
      ],
      "pi_c": ["0x345...", "0x678..."]
    }
  }
}
```

### 3.4. SDK Verification Verification Algorithm
Upon receiving the token, the Client SDK validates the assertion offline:

1. **Nonce Verification**: Ensure the `public_inputs.nonce` matches the `nonce` originally generated and stored in the client session.
2. **Key Retrieval**: Fetch the verification key (`vk`) from `verification_key_uri` (or load it from a local trusted cache).
3. **Verify ZKP**:
   ```typescript
   import { verifyProof } from '@memact/contracts/zkp';

   const isValid = await verifyProof(
     vk,
     response.cap_zkp_assertion.public_inputs,
     response.cap_zkp_assertion.proof
   );

   if (!isValid) {
     throw new Error("Invalid cryptographic zero-knowledge proof");
   }
   ```

---

## 4. Security & Privacy Considerations

### 4.1. Replay Attacks
To prevent verification replay attacks, the Client MUST include a cryptographically random `nonce` in the authorization request. The IdP binds this nonce as a public input to the ZK circuit. The Client must reject any proof verification response whose public input nonce does not match the requested nonce.

### 4.2. Dictionary Attacks
If an attribute has a small value space (e.g. standard country codes or boolean values), a client could try to guess the raw value by running verification against multiple candidate public inputs.
* To mitigate this, attributes are hashed with a unique, high-entropy `attribute_salt` managed by the IdP.
* The public input contains the `attribute_hash = SHA-256(attribute_salt || claim_name)`, hiding the raw value space structure.

### 4.3. Prover Side-Channel
Prover generation occurs entirely within the secure environment of the IdP (Access). This protects client devices from resource exhaustion due to proof generation, and shields user private attributes from malicious code executing on the client device.
