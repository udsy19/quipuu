// Fixture: JWT-library enum-constant references the V2 corpus run revealed
// the scanner was missing. Pre-Phase-1 fix, scanning this produced ZERO
// findings — the scanner only handled method_invocation and
// object_creation_expression, not field_access. Phase 1 adds field_access
// detection for known crypto-enum classes.
//
// Every line that triggers a finding has an inline comment with the rule
// ID. Test asserts each rule fires.

import com.auth0.jwt.algorithms.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;

public class Jwt {
    public static void main(String[] args) {
        // jjwt — quantum-vulnerable
        Jwts.builder().signWith(null, SignatureAlgorithm.RS256);     // CRYPTO-242
        Jwts.builder().signWith(null, SignatureAlgorithm.RS512);     // CRYPTO-242
        Jwts.builder().signWith(null, SignatureAlgorithm.ES256);     // CRYPTO-244
        Jwts.builder().signWith(null, SignatureAlgorithm.PS384);     // CRYPTO-243

        // jjwt — broken classically (alg=none)
        Jwts.builder().signWith(null, SignatureAlgorithm.NONE);      // CRYPTO-240

        // jjwt — symmetric (low severity, confirm key entropy)
        Jwts.builder().signWith(null, SignatureAlgorithm.HS256);     // CRYPTO-241

        // nimbus-jose-jwt — RSA signing
        JWSAlgorithm ns = JWSAlgorithm.RS384;                         // CRYPTO-250
        // nimbus-jose-jwt — ECDSA signing
        JWSAlgorithm es = JWSAlgorithm.ES512;                         // CRYPTO-251
        // nimbus-jose-jwt — Ed25519
        JWSAlgorithm ed = JWSAlgorithm.EdDSA;                         // CRYPTO-253
        // nimbus-jose-jwt — RSA key wrapping for encryption
        JWEAlgorithm enc = JWEAlgorithm.RSA_OAEP_256;                 // CRYPTO-254

        // jose4j — RSA
        String alg1 = AlgorithmIdentifiers.RSA_USING_SHA256;          // CRYPTO-260
        // jose4j — RSA-PSS
        String alg2 = AlgorithmIdentifiers.RSA_PSS_USING_SHA256;      // CRYPTO-261
        // jose4j — ECDSA
        String alg3 = AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256; // CRYPTO-262
        // jose4j — alg=none
        String alg4 = AlgorithmIdentifiers.NONE;                      // CRYPTO-264
    }
}
