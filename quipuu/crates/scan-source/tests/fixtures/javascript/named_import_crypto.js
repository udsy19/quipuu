"use strict";
// Fixture: name-imported (not module-qualified) node:crypto calls — `#Y4`.
// Every call below reaches the same api as its qualified sibling in
// crypto.js, through a require/import binding instead of `crypto.<method>`.

const { generateKeyPair: generateKeyPair_ } = require("node:crypto");
const { createHash } = require("crypto");

// Aliased destructuring from `require`.
function keyPairRsaAliased() {
    generateKeyPair_("rsa", { modulusLength: 2048 }, (err, pub, priv) => {});
}

// Unaliased destructuring from `require`.
function hashMd5Bare() {
    const h = createHash("md5");
}

function hashSha1Bare() {
    const h = createHash("sha1");
}
