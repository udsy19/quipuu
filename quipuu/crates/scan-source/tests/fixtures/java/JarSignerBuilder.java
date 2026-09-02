// Backlog #Y124: JDK 26's `jarsigner` API (JDK-8371079, RFC 9882) for
// ML-DSA-signed JARs. `JarSigner.Builder.signatureAlgorithm(String)` is a
// call shape `Signature.getInstance`'s existing rules cannot see — no
// `Signature.getInstance` call exists anywhere in this chain.
import java.security.KeyStore;
import jdk.security.jarsigner.JarSigner;

class JarSignerBuilder {
    void sign(KeyStore.PrivateKeyEntry entry, java.util.List<java.security.cert.Certificate> certPath)
            throws Exception {
        JarSigner signer44 = new JarSigner.Builder(entry)
                .digestAlgorithm("SHA-256")
                .signatureAlgorithm("ML-DSA-44")
                .build();

        JarSigner signer65 = new JarSigner.Builder(entry)
                .signatureAlgorithm("ML-DSA-65")
                .build();

        JarSigner signer87 = new JarSigner.Builder(entry)
                .signatureAlgorithm("ML-DSA-87")
                .build();

        // JDK-8371079 states jarsigner auto-infers the signature algorithm
        // from the key type; a classical digest passed to the sibling
        // `digestAlgorithm` setter must not classify as PQC.
        JarSigner signerClassical = new JarSigner.Builder(entry)
                .digestAlgorithm("SHA-256")
                .build();

        // A same-named setter on an unrelated builder must not fire: this is
        // not a `new JarSigner.Builder(...)` chain, so the receiver check
        // must reject it even though the method name and argument shape are
        // identical.
        NimbusJwtDecoder.withPublicKey(null).signatureAlgorithm("ML-DSA-65").build();
    }
}
