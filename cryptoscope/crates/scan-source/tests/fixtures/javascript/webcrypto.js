"use strict";
// Fixture: WebCrypto (SubtleCrypto) call sites.
//
// Two things are under test here. First, that the algorithm is read from
// argument 0 rather than assumed — Node has accepted ML-DSA and ML-KEM in
// subtle.generateKey/sign since v24.7.0, so assuming a classical algorithm
// reports a migrated call site as quantum-vulnerable. Second, that the rules
// fire through every receiver real code uses to reach `subtle`, not only the
// destructured one.

const { subtle } = require("node:crypto");

// --- PQC, through a destructured receiver ---------------------------------

async function pqcSignKey() {
    return subtle.generateKey({ name: "ML-DSA-65" }, true, ["sign", "verify"]);
}

async function pqcKemKey() {
    return crypto.subtle.generateKey({ name: "ML-KEM-768" }, true, ["encapsulateKey"]);
}

// --- Classical, through the receivers real code actually uses -------------

async function ecdsaP384() {
    return window.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, false, ["sign"]);
}

async function rsaPss(key, data) {
    return self.crypto.subtle.sign({ name: "RSA-PSS", hash: { name: "SHA-256" }, saltLength: 32 }, key, data);
}

// Bare-string algorithm form.
async function ed25519(key, data) {
    return globalThis.crypto.subtle.sign("Ed25519", key, data);
}

// The curve lives on the key, not on the algorithm object a sign() call takes.
async function ecdsaNoCurve(key, data) {
    return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data);
}

async function aesGcm256() {
    return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

// --- Not determinable from the call site ----------------------------------

// Algorithm arrives in a variable: no capture, no assertion.
async function fromVariable(algorithm) {
    return crypto.subtle.generateKey(algorithm, true, ["sign"]);
}

// Named, but no row in the algorithm table.
async function hmac(key, data) {
    return crypto.subtle.sign("HMAC", key, data);
}

// --- Negative controls ----------------------------------------------------

// Not WebCrypto: the receiver only ends in "Subtle", not ".subtle".
async function notWebCrypto(key, data) {
    return mySubtle.sign({ name: "ECDSA" }, key, data);
}
