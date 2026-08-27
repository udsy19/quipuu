// Broken-classical Java call sites. Every one of these is a textbook finding
// that the scanner reported as zero before the reachability work: RC4 and
// Signature.getInstance had no matcher at all, and DESede was misattributed
// to single DES.
package fixtures;

import javax.crypto.Cipher;
import java.security.Signature;

public class Legacy {
    // CRYPTO-214 — 3DES, not DES.
    public static Cipher tripleDes() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    // CRYPTO-213 — RC4.
    public static Cipher rc4() throws Exception {
        return Cipher.getInstance("RC4");
    }

    // CRYPTO-291 — SHA-1 signature.
    public static Signature sha1WithRsa() throws Exception {
        return Signature.getInstance("SHA1withRSA");
    }
}
