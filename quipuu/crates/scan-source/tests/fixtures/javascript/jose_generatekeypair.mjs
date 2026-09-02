// Fixture: jose (panva/jose) generateKeyPair(alg, options) — RFC 9964's three
// IANA-final ML-DSA JWA identifiers, plus the non-literal shape that must not
// produce a finding (a variable algorithm carries no capturable literal).
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

async function variableAlgYieldsNoFinding(alg) {
    return generateKeyPair(alg, { extractable: true });
}
