// Fixture: System.Security.Cryptography first-party PQC classes (.NET 10+,
// no NuGet dependency), quipuu scanner tests.
using System.Security.Cryptography;

public class PqcNativeFixture
{
    // Classical control — still detected via the pre-existing RSA.Create rule.
    public static void RsaControl()
    {
        using var rsa = RSA.Create();
    }

    // CSH-052 / CRYPTO-671 — ML-KEM-768 key generation
    public static void MlKem()
    {
        using var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
    }

    // CSH-053 / CRYPTO-674 — ML-DSA-65 key generation
    public static void MlDsa()
    {
        using var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    }

    // CSH-054 / CRYPTO-676 — SLH-DSA-SHA2-128s key generation
    public static void SlhDsa()
    {
        using var slh = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
    }

    // CSH-052 / CRYPTO-688 — parameter set read from a variable, not a literal
    public static void MlKemUnattributed(MLKemAlgorithm chosen)
    {
        using var kem = MLKem.GenerateKey(chosen);
    }
}
