const crypto = require('crypto');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

async function probe() {
  crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });            // EXPECT rsa
  crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });             // EXPECT ecdsa
  crypto.createECDH('prime256v1');                                       // EXPECT ecdh
  crypto.generateKeyPairSync('dsa', { modulusLength: 2048 });            // EXPECT dsa
  crypto.createHash('md5');                                              // EXPECT md5
  crypto.createHash('sha1');                                             // EXPECT sha1
  crypto.createHash('sha256');                                           // EXPECT sha256
  crypto.createHash('sha384');                                           // EXPECT sha384
  crypto.createHmac('sha256', 'k');                                      // EXPECT hmac
  crypto.pbkdf2Sync('pw', 's', 600000, 32, 'sha256');                    // EXPECT pbkdf2
  crypto.scryptSync('pw', 's', 32);                                      // EXPECT scrypt
  await bcrypt.hash('pw', 10);                                           // EXPECT bcrypt
  await argon2.hash('pw');                                               // EXPECT argon2
  crypto.createCipheriv('aes-128-gcm', k, iv);                           // EXPECT aes128
  crypto.createCipheriv('des-ede3-cbc', k, iv);                          // EXPECT 3des
  crypto.createCipheriv('rc4', k, null);                                 // EXPECT rc4
  crypto.createCipheriv('chacha20-poly1305', k, iv);                     // EXPECT chacha20
  await crypto.subtle.generateKey({ name: 'ML-KEM-768' }, true, ['encrypt']);  // EXPECT mlkem
  await crypto.subtle.generateKey({ name: 'ML-DSA-65' }, true, ['sign']);      // EXPECT mldsa
}
