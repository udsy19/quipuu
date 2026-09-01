import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;

/**
 * Fixture: BouncyCastle 1.85.2 Composite ML-KEM (draft-ietf-lamps-pq-composite-kem), quipuu
 * scanner tests, backlog #Y101. `CompositeKEMs.Mappings` registers every pairing under both
 * `KeyPairGenerator.<name>` (already-covered `jca-unattributed` fallback) and
 * `KeyGenerator.<name>` (previously zero coverage — no extract rule existed for
 * javax.crypto.KeyGenerator.getInstance at all).
 */
public class CompositeKem {

    // JAV-010 / CRYPTO-234 — falls through to the generic jca-unattributed fallback
    public static void keyPairGenerator() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("MLKEM768-X25519-SHA3-256", "BC");
    }

    // JAV-110 / CRYPTO-1082..1093 — the 12 real Composite ML-KEM pairings BC 1.85.2 registers
    // under KeyGenerator, verified against bc-java tag r1rv85v2's own
    // compositekem/CompositeIndex.java.
    public static void keyGenerator768RsaOaep2048() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM768-RSA2048-SHA3-256", "BC");
    }

    public static void keyGenerator768RsaOaep3072() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM768-RSA3072-SHA3-256", "BC");
    }

    public static void keyGenerator768RsaOaep4096() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM768-RSA4096-SHA3-256", "BC");
    }

    public static void keyGenerator768X25519() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM768-X25519-SHA3-256", "BC");
    }

    public static void keyGenerator768EcdhP256() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM768-ECDH-P256-SHA3-256", "BC");
    }

    public static void keyGenerator768EcdhP384() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM768-ECDH-P384-SHA3-256", "BC");
    }

    public static void keyGenerator768EcdhBp256() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM768-ECDH-BP256-SHA3-256", "BC");
    }

    public static void keyGenerator1024RsaOaep3072() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM1024-RSA3072-SHA3-256", "BC");
    }

    public static void keyGenerator1024EcdhP384() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM1024-ECDH-P384-SHA3-256", "BC");
    }

    public static void keyGenerator1024EcdhBp384() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM1024-ECDH-BP384-SHA3-256", "BC");
    }

    public static void keyGenerator1024X448() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM1024-X448-SHA3-256", "BC");
    }

    public static void keyGenerator1024EcdhP521() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("MLKEM1024-ECDH-P521-SHA3-256", "BC");
    }

    // No classify arm matches an ordinary symmetric-key KeyGenerator call — this is not a
    // general KeyGenerator extraction, and this call site must produce no finding at all.
    public static void keyGeneratorAesIsNotExtracted() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
    }
}
