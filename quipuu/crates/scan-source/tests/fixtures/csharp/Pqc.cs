// Fixture: BouncyCastle.Cryptography ML-KEM / ML-DSA calls (release-2.7.0+),
// quipuu scanner tests.
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pqc.Crypto.Bike;
using Org.BouncyCastle.Pqc.Crypto.Hqc;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using Org.BouncyCastle.Security;

public class PqcFixture
{
    // CSH-050 / CRYPTO-662 — ML-KEM-768 key-generation parameters
    public static void MlKemKeyPair()
    {
        var random = new SecureRandom();
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768));
        var keyPair = generator.GenerateKeyPair();
    }

    // CSH-050 / CRYPTO-664 — parameter set read from a variable, not a literal
    public static void MlKemKeyPairUnattributed(MLKemParameters chosen)
    {
        var random = new SecureRandom();
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(random, chosen));
        var keyPair = generator.GenerateKeyPair();
    }

    // CSH-051 / CRYPTO-666 — ML-DSA-65 key-generation parameters
    public static void MlDsaKeyPair()
    {
        var random = new SecureRandom();
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65));
        var keyPair = generator.GenerateKeyPair();
    }

    // CSH-051 / CRYPTO-667 — HashML-DSA-87 pre-hash variant, same parameter set
    public static void HashMlDsaKeyPair()
    {
        var random = new SecureRandom();
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_87_with_sha512));
        var keyPair = generator.GenerateKeyPair();
    }

    // CSH-055 / CRYPTO-827 — ML-KEM-768 encapsulation, operation site
    public static void MlKemEncapsulate(MLKemPublicKeyParameters pub)
    {
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(pub);
    }

    // CSH-056 / CRYPTO-830 — ML-KEM-512 decapsulation, operation site
    public static void MlKemDecapsulate(MLKemPrivateKeyParameters priv)
    {
        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_512);
        decapsulator.Init(priv);
    }

    // CSH-057 / CRYPTO-836 — ML-DSA-87 sign/verify, operation site
    public static void MlDsaSignVerify(MLDsaPrivateKeyParameters priv)
    {
        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_87, false);
        signer.Init(true, priv);
    }

    // CSH-080 / CRYPTO-1080 — single-tree LMS key generation (#Y100)
    public static void LmsKeyPair(LmsParameters lmsParameters)
    {
        var random = new SecureRandom();
        var generator = new LmsKeyPairGenerator();
        generator.Init(new LmsKeyGenerationParameters(lmsParameters, random));
        var keyPair = generator.GenerateKeyPair();
    }

    // CSH-081 / CRYPTO-1081 — multi-tree HSS key generation (#Y100)
    public static void HssKeyPair(LmsParameters[] lmsParameters)
    {
        var random = new SecureRandom();
        var generator = new HssKeyPairGenerator();
        generator.Init(new HssKeyGenerationParameters(lmsParameters, random));
        var keyPair = generator.GenerateKeyPair();
    }

    // CSH-083 / CRYPTO-1182 — HQC-128 key-generation parameters (#Y131)
    public static void HqcKeyPair()
    {
        var random = new SecureRandom();
        var keyGenParameters = new HqcKeyGenerationParameters(random, HqcParameters.hqc128);
    }

    // CSH-083 / CRYPTO-1185 — parameter set read from a variable, not a literal
    public static void HqcKeyPairUnattributed(HqcParameters chosen)
    {
        var random = new SecureRandom();
        var keyGenParameters = new HqcKeyGenerationParameters(random, chosen);
    }

    // CSH-084 / CRYPTO-1186 — BIKE-128 key-generation parameters (#Y131)
    public static void BikeKeyPair()
    {
        var random = new SecureRandom();
        var keyGenParameters = new BikeKeyGenerationParameters(random, BikeParameters.bike128);
    }

    // CSH-084 / CRYPTO-1189 — parameter set read from a variable, not a literal
    public static void BikeKeyPairUnattributed(BikeParameters chosen)
    {
        var random = new SecureRandom();
        var keyGenParameters = new BikeKeyGenerationParameters(random, chosen);
    }
}
