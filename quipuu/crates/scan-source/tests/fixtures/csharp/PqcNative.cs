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

    // #Y51 — MLKem.Import* key-loading paths, not just GenerateKey
    public static void MlKemImportEncapsulationKey(byte[] source)
    {
        using var kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, source);
    }

    public static void MlKemImportDecapsulationKey(byte[] source)
    {
        using var kem = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem1024, source);
    }

    public static void MlKemImportPrivateSeed(byte[] source)
    {
        using var kem = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem512, source);
    }

    public static void MlKemImportPkcs8PrivateKey(byte[] source)
    {
        using var kem = MLKem.ImportPkcs8PrivateKey(source);
    }

    public static void MlKemImportSubjectPublicKeyInfo(byte[] source)
    {
        using var kem = MLKem.ImportSubjectPublicKeyInfo(source);
    }

    public static void MlKemImportFromPem(string source)
    {
        using var kem = MLKem.ImportFromPem(source);
    }

    // #Y55 — MLDsa/SlhDsa Import* key-loading paths, the exact remainder
    // #Y51 named and left open.
    public static void MlDsaImportMLDsaPrivateKey(byte[] source)
    {
        using var dsa = MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, source);
    }

    public static void MlDsaImportMLDsaPrivateSeed(byte[] source)
    {
        using var dsa = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa44, source);
    }

    public static void MlDsaImportMLDsaPublicKey(byte[] source)
    {
        using var dsa = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa87, source);
    }

    public static void MlDsaImportPkcs8PrivateKey(byte[] source)
    {
        using var dsa = MLDsa.ImportPkcs8PrivateKey(source);
    }

    public static void MlDsaImportSubjectPublicKeyInfo(byte[] source)
    {
        using var dsa = MLDsa.ImportSubjectPublicKeyInfo(source);
    }

    public static void MlDsaImportFromPem(string source)
    {
        using var dsa = MLDsa.ImportFromPem(source);
    }

    public static void SlhDsaImportSlhDsaPrivateKey(byte[] source)
    {
        using var slh = SlhDsa.ImportSlhDsaPrivateKey(SlhDsaAlgorithm.SlhDsaShake192s, source);
    }

    public static void SlhDsaImportSlhDsaPublicKey(byte[] source)
    {
        using var slh = SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm.SlhDsaSha2_256f, source);
    }

    public static void SlhDsaImportPkcs8PrivateKey(byte[] source)
    {
        using var slh = SlhDsa.ImportPkcs8PrivateKey(source);
    }

    public static void SlhDsaImportSubjectPublicKeyInfo(byte[] source)
    {
        using var slh = SlhDsa.ImportSubjectPublicKeyInfo(source);
    }

    public static void SlhDsaImportFromPem(string source)
    {
        using var slh = SlhDsa.ImportFromPem(source);
    }
}
