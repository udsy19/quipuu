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
}
