/**
 * Fixture: BouncyCastle lightweight-API PQC classes (`#Y39`), quipuu scanner tests.
 * These classes live at org.bouncycastle.crypto.* since the 2026-04 relocation
 * and at org.bouncycastle.pqc.crypto.* before it; the bare class name is
 * identical in both locations, so no import statement is needed here.
 */
public class BcLightweight {

    // JAV-030 / CRYPTO-230 — classical control, already covered before this fixture
    public static void classicalControl() {
        Object g = new RSAKeyPairGenerator();
    }

    // JAV-030 / CRYPTO-811 — ML-KEM keypair generation
    public static void mlKemKeypair() {
        Object g = new MLKEMKeyPairGenerator();
    }

    // JAV-030 / CRYPTO-812 — ML-DSA keypair generation
    public static void mlDsaKeypair() {
        Object g = new MLDSAKeyPairGenerator();
    }

    // JAV-030 / CRYPTO-813 — SLH-DSA keypair generation
    public static void slhDsaKeypair() {
        Object g = new SLHDSAKeyPairGenerator();
    }

    // JAV-030 / CRYPTO-814 — ML-KEM encapsulation
    public static void mlKemEncap() {
        Object g = new MLKEMGenerator(null);
    }

    // JAV-030 / CRYPTO-815 — ML-KEM decapsulation
    public static void mlKemDecap() {
        Object g = new MLKEMExtractor(null);
    }

    // JAV-030 / CRYPTO-816 — ML-DSA signing
    public static void mlDsaSign() {
        Object g = new MLDSASigner();
    }

    // JAV-030 / CRYPTO-817 — SLH-DSA signing
    public static void slhDsaSign() {
        Object g = new SLHDSASigner();
    }

    // JAV-030 / CRYPTO-818 — ML-DSA pre-hash signing
    public static void hashMlDsaSign() {
        Object g = new HashMLDSASigner();
    }

    // JAV-030 / CRYPTO-819 — SLH-DSA pre-hash signing
    public static void hashSlhDsaSign() {
        Object g = new HashSLHDSASigner();
    }

    // JAV-030 / CRYPTO-958 — ML-DSA signing under BC's pre-finalization class name
    public static void dilithiumSign() {
        Object g = new DilithiumSigner();
    }

    // JAV-030 / CRYPTO-959 — SLH-DSA signing under BC's pre-finalization class name
    public static void sphincsPlusSign() {
        Object g = new SPHINCSPlusSigner();
    }
}
