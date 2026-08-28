import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;

/**
 * Fixture: Java crypto API calls for quipuu scanner tests.
 */
public class Main {

    // JAV-001 / CRYPTO-200 — DES in Cipher.getInstance
    public static void cipherDes() throws Exception {
        Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, null);
    }

    // JAV-001 / CRYPTO-201 — AES-ECB in Cipher.getInstance. The plain `AES`
    // form states no key size (it comes from the SecretKey), so the expected
    // algorithm-id is the aes-unattributed-ecb sentinel, not a guessed width.
    public static void cipherAesEcb() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, null);
    }

    // JAV-001 / CRYPTO-207 — the JCE `AES_128` standard name does state the
    // key size, so this one resolves to aes-128-ecb.
    public static void cipherAes128Ecb() throws Exception {
        Cipher c = Cipher.getInstance("AES_128/ECB/NoPadding");
    }

    // JAV-001 / CRYPTO-202 — RSA PKCS1Padding
    public static void cipherRsaPkcs1() throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    // JAV-001 / CRYPTO-203 — AES-GCM, key size not stated at the call site.
    public static void cipherAesGcm() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    }

    // JAV-001 / CRYPTO-206 — AES-256-GCM, key size stated by the JCE
    // standard name.
    public static void cipherAes256Gcm() throws Exception {
        Cipher c = Cipher.getInstance("AES_256/GCM/NoPadding");
    }

    // JAV-010 / CRYPTO-210 — RSA KeyPairGenerator
    public static void kpgRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }

    // JAV-010 / CRYPTO-211 — EC KeyPairGenerator
    public static void kpgEc() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    }

    // JAV-020 / CRYPTO-220 — MD5
    public static void hashMd5() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
    }

    // JAV-020 / CRYPTO-221 — SHA-1
    public static void hashSha1() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
    }

    // JAV-020 / CRYPTO-222 — SHA-256 (good)
    public static void hashSha256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }

    // JAV-030 / CRYPTO-233 — BouncyCastle provider
    public static void bcProvider() {
        BouncyCastleProvider prov = new BouncyCastleProvider();
    }

    // JAV-030 / CRYPTO-230 — BouncyCastle RSAKeyPairGenerator
    public static void bcRsaKpg() {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
    }

    public static void main(String[] args) throws Exception {
        cipherDes();
        cipherAesEcb();
        cipherRsaPkcs1();
        cipherAesGcm();
        kpgRsa();
        kpgEc();
        hashMd5();
        hashSha1();
        hashSha256();
        bcProvider();
        bcRsaKpg();
    }
}
