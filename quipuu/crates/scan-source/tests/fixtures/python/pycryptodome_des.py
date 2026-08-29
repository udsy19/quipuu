from Crypto.Cipher import DES, DES3

# CRYPTO-809 — Single DES, 56-bit key
cipher = DES.new(key, DES.MODE_ECB)

# CRYPTO-810 — Triple DES, Sweet32-exposed 64-bit block
cipher3 = DES3.new(key3, DES3.MODE_ECB)
