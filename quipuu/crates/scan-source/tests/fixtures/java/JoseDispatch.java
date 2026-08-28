// Fixture: the Java JOSE-dispatch shapes. `PRECISION_AUDIT_V4.md § 2` measured
// this as the largest single false-positive class in the corpus — an enum
// constant that is compared against, collected into a supported-algorithm set,
// or used as a lookup-table key, reported as if the line signed something.
//
// The top half is operational and must keep firing; the bottom half is the
// dispatch class and must not fire at all. Both halves are load-bearing: a
// change that silences the bottom by silencing the top is a recall loss, not
// a precision gain.

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Jwts;
import org.jose4j.jws.AlgorithmIdentifiers;

public class JoseDispatch extends AlgorithmInfo {

    // ---- operational: the algorithm is bound to something that uses it ----

    // A declaration binds the algorithm exactly as Go's `const RS256 = "RS256"`
    // does; the consumer of the variable is where the signing happens.
    private final JWSAlgorithm chosen = JWSAlgorithm.RS384;          // CRYPTO-259

    void sign(java.security.Key key) {
        // Argument to a configuring call — the canonical operational site.
        Jwts.builder().signWith(key, SignatureAlgorithm.PS384);      // CRYPTO-243
        setAlgorithmIdentifier(AlgorithmIdentifiers.NONE);           // CRYPTO-264
    }

    // A constructor argument yields the object the operation is performed
    // with. `PRECISION_AUDIT_V4.md § 5` row 91 labels this shape TP.
    JoseDispatch() {
        super(AlgorithmIdentifiers.RSA_USING_SHA256, "SHA256withRSA"); // CRYPTO-260
    }

    // ---- dispatch: naming an algorithm without performing it ----

    // Comparison, both spellings. The branch this guards performs the
    // operation and cites its own line.
    boolean argSide(JWSAlgorithm alg) {
        return alg.equals(JWSAlgorithm.ES512);
    }

    boolean receiverSide(JWSAlgorithm alg) {
        return JWSAlgorithm.EdDSA.equals(alg);
    }

    boolean operator(JWEAlgorithm alg) {
        return alg == JWEAlgorithm.RSA_OAEP_256;
    }

    // Collection membership — a SUPPORTED_ALGORITHMS set is a capability
    // declaration, not a use.
    void supported(java.util.Set<JWSAlgorithm> algs) {
        algs.add(JWSAlgorithm.HS512);
    }

    static final java.util.List<SignatureAlgorithm> PREFERRED =
        java.util.Collections.unmodifiableList(java.util.Arrays.asList(
            SignatureAlgorithm.HS384, SignatureAlgorithm.HS256));

    // A resolver table keyed by algorithm — the call spelling of the keyed
    // literal SiteContext::MapEntry already covered.
    void resolver(java.util.Map<SignatureAlgorithm, String> hashes) {
        hashes.put(SignatureAlgorithm.ES256, "SHA-256");
    }

    // Test scaffolding. The Java arm of `is_test_assertion_callee` had never
    // fired, because it was reached through a `function` field that Java's
    // `method_invocation` does not have.
    void asserts(JWSAlgorithm alg) {
        assertEquals(JWSAlgorithm.RS512, alg);
    }
}
