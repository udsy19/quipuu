// Fixture: BouncyCastle raw (non-JSSE) TLS key-exchange group preference
// list (#Y62d) — `TlsUtils.addIfSupported(supportedGroups, crypto, new
// int[]{ NamedGroup.X, ... })`, the shape an `AbstractTlsClient` subclass
// passes when overriding `getSupportedGroups`. Mirrors bc-java's own
// `AbstractTlsClient.getSupportedGroups` default implementation, the only
// real corpus-B call site found for this shape.

package example;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsCrypto;

import java.util.Vector;

public class BcNamedGroups {
    void pqcOptIn(Vector supportedGroups, TlsCrypto crypto) {
        TlsUtils.addIfSupported(supportedGroups, crypto,
            new int[]{ NamedGroup.X25519MLKEM768, NamedGroup.SecP256r1MLKEM768, NamedGroup.x25519 });
    }

    void classicalOnlyDowngrade(Vector supportedGroups, TlsCrypto crypto) {
        TlsUtils.addIfSupported(supportedGroups, crypto,
            new int[]{ NamedGroup.secp256r1, NamedGroup.secp384r1, NamedGroup.secp521r1,
                NamedGroup.x448, NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096 });
    }

    // Control: netty's SslUtils carries an unrelated, statically-imported
    // addIfSupported(Set, List, String...) for cipher suites, not TLS groups
    // — no "TlsUtils." receiver, so this must NOT fire.
    void unrelatedNettyHelper(java.util.Set<String> supported, java.util.List<String> enabled) {
        addIfSupported(supported, enabled, "TLS_AES_128_GCM_SHA256");
    }

    static void addIfSupported(java.util.Set<String> supported, java.util.List<String> enabled, String... names) {
    }

    // Control: the single-group overload names no list to compare against —
    // must NOT fire.
    void singleGroupOverload(Vector supportedGroups, TlsCrypto crypto) {
        TlsUtils.addIfSupported(supportedGroups, crypto, NamedGroup.x25519);
    }
}
