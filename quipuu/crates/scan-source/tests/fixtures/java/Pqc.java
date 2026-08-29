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
}
