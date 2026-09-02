import javax.net.ssl.SSLParameters;

// Backlog #Y24: SSLParameters.setNamedGroups probe. The PQC opt-in case names
// a hybrid group among classical ones; the downgrade case names only
// classical/FFDHE groups, the shape that silently blocks JDK 27's default-on
// PQC upgrade. The RSA control asserts the matcher does not fire on an
// unrelated KeyPairGenerator call.
public class TlsGroups {
    void pqcOptIn(SSLParameters sslParams) {
        sslParams.setNamedGroups(new String[]{"X25519MLKEM768", "x25519", "secp256r1"});
    }

    void classicalOnlyDowngrade(SSLParameters params) {
        params.setNamedGroups(
                new String[]{"secp256r1", "secp384r1", "secp521r1", "x448", "ffdhe2048", "ffdhe3072", "ffdhe4096"});
    }

    void rsaControl(java.security.KeyPairGenerator kpg) throws Exception {
        kpg.initialize(2048);
    }

    // The delegating-helper shape corpus B's own conscrypt test suite uses:
    // the array is the second of two arguments, not the sole argument on an
    // instance call.
    static void setNamedGroups(SSLParameters parameters, String[] groups) {
        parameters.setNamedGroups(groups);
    }

    void viaHelper(SSLParameters parameters) {
        setNamedGroups(parameters, new String[]{"X25519MLKEM768"});
    }

    // #Y24 part (b): the same setting via a JVM-wide system property, a
    // single comma-delimited string rather than one array element per group.
    // Includes stray whitespace around a comma (a real Java style, never an
    // issue for the array form) to exercise trimming.
    void viaSystemProperty() {
        System.setProperty("jdk.tls.namedGroups", "secp256r1, ffdhe2048,X25519MLKEM768");
    }

    // Control: an unrelated system property must not fire.
    void unrelatedSystemProperty() {
        System.setProperty("http.agent", "quipuu-test");
    }

    // #Y122: the pre-standard Kyber draft name, go.toml's CRYPTO-048 sibling
    // for the JSSE call shape.
    void preStandardKyber(SSLParameters params) {
        params.setNamedGroups(new String[]{"X25519Kyber768Draft00"});
    }
}
