import javax.crypto.Cipher;
import javax.crypto.KEM;
import java.security.KeyPairGenerator;
import java.security.Signature;

/**
 * Fixture: Java PQC API calls (JDK 24+, JEP 496/497), quipuu scanner tests.
 */
public class Pqc {

    // JAV-010 / CRYPTO-216 — ML-KEM-768 keypair generation
    public static void kemKeypair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM-768");
    }

    // JAV-010 / CRYPTO-219 — ML-DSA-65 keypair generation
    public static void dsaKeypair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ML-DSA-65");
    }

    // JAV-090 / CRYPTO-225 — ML-DSA-65 signature
    public static void dsaSignature() throws Exception {
        Signature s = Signature.getInstance("ML-DSA-65");
    }

    // JAV-040 / CRYPTO-228 — ML-KEM-768 encapsulation object
    public static void kem() throws Exception {
        KEM kem = KEM.getInstance("ML-KEM-768");
    }

    // JAV-041 / CRYPTO-1168 — ML-KEM encapsulator operation (parameter set
    // not traceable to this call site; see java.toml's comment above JAV-041)
    public static void kemEncapsulate(java.security.PublicKey pub) throws Exception {
        KEM kem = KEM.getInstance("ML-KEM-768");
        KEM.Encapsulator enc = kem.newEncapsulator(pub);
    }

    // JAV-042 / CRYPTO-1169 — ML-KEM decapsulator operation (parameter set
    // not traceable to this call site; see java.toml's comment above JAV-042)
    public static void kemDecapsulate(java.security.PrivateKey priv) throws Exception {
        KEM kem = KEM.getInstance("ML-KEM-768");
        KEM.Decapsulator dec = kem.newDecapsulator(priv);
    }

    // JAV-010 / CRYPTO-770 — SLH-DSA-SHA2-128S keypair generation (BouncyCastle)
    public static void slhDsaKeypair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", "BC");
    }

    // JAV-010 / CRYPTO-782 — SLH-DSA family-generic name, no parameter set stated
    public static void slhDsaKeypairUnattributed() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("SLH-DSA", "BC");
    }

    // JAV-090 / CRYPTO-790 — SLH-DSA-SHAKE-128S signature
    public static void slhDsaSignature() throws Exception {
        Signature s = Signature.getInstance("SLH-DSA-SHAKE-128S", "BC");
    }

    // JAV-010 / CRYPTO-1006 — HQC-128 keypair generation (BouncyCastle)
    public static void hqcKeypair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("HQC-128", "BCPQC");
    }

    // JAV-010 / CRYPTO-1009 — HQC family-generic name, no parameter set stated
    public static void hqcKeypairUnattributed() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("HQC", "BCPQC");
    }

    // JAV-040 / CRYPTO-1011 — HQC-192 encapsulation object
    public static void hqcKem() throws Exception {
        KEM kem = KEM.getInstance("HQC-192");
    }

    // JAV-001 / CRYPTO-1004 — HQC-256 cipher
    public static void hqcCipher() throws Exception {
        Cipher c = Cipher.getInstance("HQC-256");
    }

    // JAV-001 / CRYPTO-1014 — BIKE128 cipher (BouncyCastle)
    public static void bikeCipher() throws Exception {
        Cipher c = Cipher.getInstance("BIKE128");
    }

    // JAV-010 / CRYPTO-1018 — BIKE family-generic name, no parameter set stated
    public static void bikeKeypairUnattributed() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("BIKE", "BCPQC");
    }

    // JAV-010 / CRYPTO-1019 — Classic McEliece keypair generation, family sentinel
    public static void cmceKeypair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("mceliece6960119", "BCPQC");
    }

    // JAV-040 / CRYPTO-1020 — Classic McEliece encapsulation object, family sentinel
    public static void cmceKem() throws Exception {
        KEM kem = KEM.getInstance("CMCE");
    }

    // JAV-010 / CRYPTO-1021 — XMSS (single-tree) keypair generation
    public static void xmssKeypair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("XMSS", "BCPQC");
    }

    // JAV-010 / CRYPTO-1022 — XMSSMT (multi-tree) keypair generation
    public static void xmssMtKeypair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");
    }

    // JAV-090 / CRYPTO-1025 — XMSS signature, digest-qualified name
    public static void xmssSignature() throws Exception {
        Signature s = Signature.getInstance("XMSS-SHA256", "BCPQC");
    }

    // JAV-090 / CRYPTO-1029 — XMSSMT signature, digest-qualified name
    public static void xmssMtSignature() throws Exception {
        Signature s = Signature.getInstance("XMSSMT-SHA256", "BCPQC");
    }
}
