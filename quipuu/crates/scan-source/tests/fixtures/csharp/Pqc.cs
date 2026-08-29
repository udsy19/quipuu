// Fixture: BouncyCastle.Cryptography ML-KEM / ML-DSA calls (release-2.7.0+),
// quipuu scanner tests.
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
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
}
