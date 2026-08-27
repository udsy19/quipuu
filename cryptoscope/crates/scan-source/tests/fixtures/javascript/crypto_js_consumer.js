// Fixture: a downstream consumer of the crypto-js library.
//
// The crypto-js repo itself is a library — its source only defines
// algorithms. The call-site patterns below are what we expect to find in
// thousands of npm projects that depend on crypto-js (12M downloads/week).
//
// Pre-Phase-8 fix, scanning this produced ZERO findings: match_js_callee()
// didn't handle two-level member expressions (CryptoJS.<Algo>.<method>).

const CryptoJS = require("crypto-js");

// Symmetric encryption
CryptoJS.AES.encrypt(message, key);     // CRYPTO-370
CryptoJS.DES.encrypt(message, key);     // CRYPTO-371
CryptoJS.TripleDES.encrypt(msg, key);   // CRYPTO-372
CryptoJS.RC4.encrypt(msg, key);         // CRYPTO-373

// One-level helpers
const hash1 = CryptoJS.MD5(message);    // CRYPTO-374
const hash2 = CryptoJS.SHA1(message);   // CRYPTO-375

// HMAC variants
const mac1 = CryptoJS.HmacMD5(msg, k);  // CRYPTO-376
const mac2 = CryptoJS.HmacSHA1(msg, k); // CRYPTO-377
