// Fixture: jsonwebtoken/test's own idiom for asserting a call fails —
// `expect(() => jwt.sign(...)).to.throw(...)` (chai) — is low-signal
// (SiteContext::TestAssertion) because the test requires the call to fail.
// A jwt.sign call outside any such wrapper is a genuine positive and must
// still be reported, mirroring the C/C++ ExpectNull/ExpectNotNull split.

const jwt = require("jsonwebtoken");
const expect = require("chai").expect;

// suppressed — the test requires this call to throw
expect(function () {
  jwt.sign({ foo: "bar" }, privateKey, { algorithm: "HS256" });
}).to.throw(Error, "must be a symmetric key");

// suppressed — jest spelling of the same idiom
expect(() => {
  jwt.sign({ foo: "bar" }, privateKey, { algorithm: "RS256" });
}).toThrow("minimum key size");

// real positive — no throw assertion wraps this call
jwt.sign({ foo: "bar" }, privateKey, { algorithm: "ES256" });
