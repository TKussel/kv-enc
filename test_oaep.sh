# 1) Keypair & public key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.pem
openssl pkey -in priv.pem -pubout -out pub.pem

# 2) Build
cc -O2 -Wall -Wextra seeded_rsa_pubenc_oaep.c -o seeded_rsa_pubenc_oaep -lcrypto -ldl

# 3) Determinism check (same output twice)
./seeded_rsa_pubenc_oaep 00112233445566778899aabbccddeeff "hello world" pub.pem
./seeded_rsa_pubenc_oaep 00112233445566778899aabbccddeeff "hello world" pub.pem

