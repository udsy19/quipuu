// Fixture: ESM named import of node:crypto — `#Y4`.
import { generateKeyPair } from "node:crypto";

function keyPairRsaEsm() {
    generateKeyPair("rsa", { modulusLength: 2048 }, (err, pub, priv) => {});
}
