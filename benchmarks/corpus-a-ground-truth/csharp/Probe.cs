using System.Security.Cryptography;

public class Probe {
    public void Run() {
        RSA.Create(2048);                                           // EXPECT rsa
        ECDsa.Create(ECCurve.NamedCurves.nistP256);                 // EXPECT ecdsa
        ECDiffieHellman.Create();                                   // EXPECT ecdh
        DSA.Create(2048);                                           // EXPECT dsa
        MD5.Create();                                               // EXPECT md5
        SHA1.Create();                                              // EXPECT sha1
        SHA256.Create();                                            // EXPECT sha256
        SHA384.Create();                                            // EXPECT sha384
        new HMACSHA256();                                           // EXPECT hmac
        new Rfc2898DeriveBytes("pw", 16, 600000, HashAlgorithmName.SHA256); // EXPECT pbkdf2
        Aes.Create();                                               // EXPECT aes
        TripleDES.Create();                                         // EXPECT 3des
        new ChaCha20Poly1305(new byte[32]);                         // EXPECT chacha20
        MLKem.GenerateKey(MLKemAlgorithm.MLKem768);                 // EXPECT mlkem
        MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);                  // EXPECT mldsa
    }
}
