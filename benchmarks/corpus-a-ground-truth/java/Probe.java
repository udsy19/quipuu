import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.mindrot.jbcrypt.BCrypt;

public class Probe {
    void probe() throws Exception {
        KeyPairGenerator.getInstance("RSA").initialize(2048);              // EXPECT rsa
        KeyPairGenerator.getInstance("EC");                                // EXPECT ecdsa
        KeyAgreement.getInstance("ECDH");                                  // EXPECT ecdh
        KeyPairGenerator.getInstance("DSA");                               // EXPECT dsa
        MessageDigest.getInstance("MD5");                                  // EXPECT md5
        MessageDigest.getInstance("SHA-1");                                // EXPECT sha1
        MessageDigest.getInstance("SHA-256");                              // EXPECT sha256
        MessageDigest.getInstance("SHA-384");                              // EXPECT sha384
        Mac.getInstance("HmacSHA256");                                     // EXPECT hmac
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");              // EXPECT pbkdf2
        BCrypt.hashpw("pw", BCrypt.gensalt());                             // EXPECT bcrypt
        Cipher.getInstance("AES/GCM/NoPadding");                           // EXPECT aesgcm
        Cipher.getInstance("DESede/CBC/PKCS5Padding");                      // EXPECT 3des
        Cipher.getInstance("RC4");                                         // EXPECT rc4
        Cipher.getInstance("ChaCha20-Poly1305");                           // EXPECT chacha20
        KeyPairGenerator.getInstance("ML-KEM");                            // EXPECT mlkem
        KeyPairGenerator.getInstance("ML-DSA");                            // EXPECT mldsa
        KeyPairGenerator.getInstance("SLH-DSA");                           // EXPECT slhdsa
    }
}
