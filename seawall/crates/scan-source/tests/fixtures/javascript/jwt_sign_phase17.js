// Phase 17 fixture — jwt.sign argument-value disambiguation.
//
// Pre-Phase-17, every jwt.sign call routed to CRYPTO-360 with
// algorithm_id=rsa-pkcs1-sha256-2048. Phase 17 inspects the key argument
// and the `algorithm:` option to pick the right rule:
//   - string key, no options       → CRYPTO-382 (HMAC default)
//   - {algorithm: 'HS256'}         → CRYPTO-361
//   - {algorithm: 'RS256'}         → CRYPTO-364
//   - {algorithm: 'PS256'}         → CRYPTO-367
//   - {algorithm: 'ES256'}         → CRYPTO-378
//   - {algorithm: 'none'}          → CRYPTO-381 (CWE-347)
//   - non-string key, no options   → CRYPTO-360 fallback (medium)

const jwt = require("jsonwebtoken");

// HMAC by key shape (string secret)
jwt.sign({ foo: "bar" }, "shhhh");                              // CRYPTO-382

// Explicit HMAC variants
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "HS256" });   // CRYPTO-361
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "HS384" });   // CRYPTO-362
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "HS512" });   // CRYPTO-363

// Explicit RSA-PKCS1 variants
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "RS256" });   // CRYPTO-364
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "RS384" });   // CRYPTO-365
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "RS512" });   // CRYPTO-366

// Explicit RSA-PSS variants
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "PS256" });   // CRYPTO-367
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "PS384" });   // CRYPTO-368
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "PS512" });   // CRYPTO-369

// Explicit ECDSA variants
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "ES256" });   // CRYPTO-378
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "ES384" });   // CRYPTO-379
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "ES512" });   // CRYPTO-380

// alg=none (CWE-347 class)
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "none" });    // CRYPTO-381

// Non-string key, no explicit algorithm → fallback CRYPTO-360 (medium)
jwt.sign({ foo: "bar" }, privateKey);                            // CRYPTO-360
