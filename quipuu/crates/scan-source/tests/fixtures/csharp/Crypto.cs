// Fixture: C# crypto API calls for quipuu scanner tests.
using System.Security.Cryptography;

public class CryptoFixture
{
    // CSH-001 / CRYPTO-600 — RSA.Create()
    public static void RsaCreate()
    {
        using var rsa = RSA.Create();
        rsa.KeySize = 2048;
    }

    // CSH-002 / CRYPTO-610 — ECDsa.Create()
    public static void EcDsaCreate()
    {
        using var ecdsa = ECDsa.Create();
    }

    // CSH-010 / CRYPTO-620 — Aes.Create()
    public static void AesCreate()
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.GCM;
    }

    // CSH-011 / CRYPTO-621 — TripleDES.Create()
    public static void TripleDesCreate()
    {
        using var des = TripleDES.Create();
    }

    // CSH-020 / CRYPTO-630 — SHA1.Create()
    public static void Sha1Create()
    {
        using var sha1 = SHA1.Create();
    }

    // CSH-020 / CRYPTO-631 — SHA256.Create()
    public static void Sha256Create()
    {
        using var sha256 = SHA256.Create();
    }

    // CSH-020 / CRYPTO-633 — SHA384.Create()
    public static void Sha384Create()
    {
        using var sha384 = SHA384.Create();
    }

    // CSH-020 / CRYPTO-945/946/947 — SHA3_256/384/512.Create()
    public static void Sha3Create()
    {
        using var sha3_256 = SHA3_256.Create();
        using var sha3_384 = SHA3_384.Create();
        using var sha3_512 = SHA3_512.Create();
    }

    // CSH-021 / CRYPTO-640 — MD5.Create()
    public static void Md5Create()
    {
        using var md5 = MD5.Create();
    }

    // CSH-030 / CRYPTO-650 — RandomNumberGenerator.Create()
    public static void RngCreate()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
    }

    // CSH-040 / CRYPTO-660 — new RijndaelManaged()
    public static void RijndaelCreate()
    {
        var rijndael = new RijndaelManaged();
    }
}
