# 1) Make a keypair and extract the public key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.pem
openssl pkey -in priv.pem -pubout -out pub.pem

# 2) Build
cc -O2 -Wall -Wextra new-rsa.c -o seeded_rsa_pubenc -lcrypto -ldl

# 3) Run twice with same seed/msg/key (ciphertext should be identical)
./seeded_rsa_pubenc 00112233445566778899aabbccddeeff "hello world" pub.pem
./seeded_rsa_pubenc 00112233445566778899aabbccddeeff "hello world" pub.pem

