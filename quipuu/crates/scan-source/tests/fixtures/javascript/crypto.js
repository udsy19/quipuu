"use strict";
// Fixture: JS/TS crypto API calls for quipuu scanner tests.

const crypto = require("node:crypto");
const jwt = require("jsonwebtoken");
const { subtle } = globalThis.crypto;

// JST-001 / CRYPTO-300 — DES in createCipheriv
function cipherDes() {
    const c = crypto.createCipheriv("des-cbc", key, iv);
}

// JST-001 / CRYPTO-301 — RC4 in createCipheriv
function cipherRc4() {
    const c = crypto.createCipheriv("rc4", key, null);
}

// JST-001 / CRYPTO-302 — AES-GCM in createCipheriv (good)
function cipherAesGcm() {
    const c = crypto.createCipheriv("aes-256-gcm", key, iv);
}

// JST-001 / CRYPTO-303 — AES-ECB in createCipheriv
function cipherAesEcb() {
    const c = crypto.createCipheriv("aes-128-ecb", key, null);
}

// JST-010 / CRYPTO-310 — MD5 in createHash
function hashMd5() {
    const h = crypto.createHash("md5");
}

// JST-010 / CRYPTO-311 — SHA-1 in createHash
function hashSha1() {
    const h = crypto.createHash("sha1");
}

// JST-010 / CRYPTO-312 — SHA-256 in createHash (good)
function hashSha256() {
    const h = crypto.createHash("sha256");
}

// JST-010 / CRYPTO-904..908 — the remaining OpenSSL digest names createHash accepts
function hashWiderDigests() {
    const h1 = crypto.createHash("sha224");
    const h2 = crypto.createHash("sha384");
    const h3 = crypto.createHash("sha512");
    const h4 = crypto.createHash("sha3-256");
    const h5 = crypto.createHash("sha3-512");
}

// JST-010 / CRYPTO-969 — the last remaining OpenSSL digest name, sha3-384
function hashSha3_384() {
    const h = crypto.createHash("sha3-384");
}

// JST-020 / CRYPTO-320 — RSA generateKeyPair
function keyPairRsa() {
    crypto.generateKeyPair("rsa", { modulusLength: 2048 }, (err, pub, priv) => {});
}

// JST-020 / CRYPTO-321 — EC generateKeyPair
function keyPairEc() {
    crypto.generateKeyPair("ec", { namedCurve: "P-256" }, (err, pub, priv) => {});
}

// JST-020 / CRYPTO-322 — Ed25519 generateKeyPair
function keyPairEd25519() {
    crypto.generateKeyPairSync("ed25519");
}

// JST-020 / CRYPTO-1202..1204 — ML-KEM generateKeyPair
function keyPairMlKem() {
    crypto.generateKeyPairSync("ml-kem-512");
    crypto.generateKeyPairSync("ml-kem-768");
    crypto.generateKeyPairSync("ml-kem-1024");
}

// JST-020 / CRYPTO-1205..1207 — ML-DSA generateKeyPair
function keyPairMlDsa() {
    crypto.generateKeyPairSync("ml-dsa-44");
    crypto.generateKeyPairSync("ml-dsa-65");
    crypto.generateKeyPairSync("ml-dsa-87");
}

// JST-030 / CRYPTO-330 — RSA-SHA256 createSign
function signRsa() {
    const sign = crypto.createSign("RSA-SHA256");
}

// JST-030 / CRYPTO-970..972 — the remaining OpenSSL RSA signature digest names
function signRsaWiderDigests() {
    const s1 = crypto.createSign("RSA-SHA1");
    const s2 = crypto.createSign("RSA-SHA384");
    const s3 = crypto.createSign("RSA-SHA512");
}

// JST-040 / CRYPTO-340 — WebCrypto subtle.generateKey
async function webCryptoGenerateKey() {
    const key = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

// JST-050 / CRYPTO-350 — WebCrypto subtle.sign
async function webCryptoSign() {
    const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, data);
}

// JST-060 / CRYPTO-360 — jsonwebtoken jwt.sign
function jwtSign() {
    const token = jwt.sign({ sub: "1234" }, secretKey, { algorithm: "RS256" });
}
