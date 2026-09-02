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

// real positive — the sign() call here succeeds; only the verify() call one
// line below it is the one the assertion requires to throw (`#Y119`, the
// jsonwebtoken corpus shape at test/wrong_alg.tests.js:44-49)
expect(function () {
  var token = jwt.sign({ foo: "bar" }, "secret", { algorithm: "HS256" });
  jwt.verify(token, "some secret", { algorithms: ["HS384"] });
}).to.throw(JsonWebTokenError, "invalid algorithm");
