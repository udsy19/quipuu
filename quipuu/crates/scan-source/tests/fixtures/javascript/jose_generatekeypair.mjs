// Fixture: jose (panva/jose) generateKeyPair(alg, options) — every literal
// JWA identifier jose's own generate_key_pair.ts switch statement recognises
// (RFC 9964's three IANA-final ML-DSA identifiers plus the full classical
// set), plus the non-literal shape that must not produce a finding (a
// variable algorithm carries no capturable literal).
import { generateKeyPair } from "jose";

async function mlDsa44KeyPair() {
    return generateKeyPair("ML-DSA-44", { extractable: true });
}

async function mlDsa65KeyPair() {
    return generateKeyPair("ML-DSA-65", { extractable: true });
}

async function mlDsa87KeyPair() {
    return generateKeyPair("ML-DSA-87", { extractable: true });
}

async function ps256KeyPair() {
    return generateKeyPair("PS256");
}

async function ps384KeyPair() {
    return generateKeyPair("PS384");
}

async function ps512KeyPair() {
    return generateKeyPair("PS512");
}

async function rs256KeyPair() {
    return generateKeyPair("RS256");
}

async function rs384KeyPair() {
    return generateKeyPair("RS384");
}

async function rs512KeyPair() {
    return generateKeyPair("RS512");
}

async function rsaOaepKeyPair() {
    return generateKeyPair("RSA-OAEP");
}

async function rsaOaep256KeyPair() {
    return generateKeyPair("RSA-OAEP-256");
}

async function rsaOaep384KeyPair() {
    return generateKeyPair("RSA-OAEP-384");
}

async function rsaOaep512KeyPair() {
    return generateKeyPair("RSA-OAEP-512");
}

async function es256KeyPair() {
    return generateKeyPair("ES256");
}

async function es384KeyPair() {
    return generateKeyPair("ES384");
}

async function es512KeyPair() {
    return generateKeyPair("ES512");
}

async function ed25519KeyPair() {
    return generateKeyPair("Ed25519");
}

async function eddsaKeyPair() {
    return generateKeyPair("EdDSA");
}

async function ecdhEsKeyPair() {
    return generateKeyPair("ECDH-ES");
}

async function ecdhEsA128KwKeyPair() {
    return generateKeyPair("ECDH-ES+A128KW");
}

async function variableAlgYieldsNoFinding(alg) {
    return generateKeyPair(alg, { extractable: true });
}
