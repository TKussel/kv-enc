# 1) Keypair & pubkey
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.pem
openssl pkey -in priv.pem -pubout -out pub.pem

# 2) Build
cc -O2 -Wall -Wextra seeded_rsa_pubenc_oaep_2.c -o seeded_rsa_pubenc_oaep -lcrypto -ldl

./seeded_rsa_pubenc_oaep  00112233445566778899aabbccddeeff "hello" pub.pem
./seeded_rsa_pubenc_oaep  00112233445566778899aabbccddeeff "hello" pub.pem
# 3) Determinism: same seed/msg/key/label → same ciphertext
./seeded_rsa_pubenc_oaep --label "ctx-v1" 00112233445566778899aabbccddeeff "hello" pub.pem
./seeded_rsa_pubenc_oaep --label "ctx-v1" 00112233445566778899aabbccddeeff "hello" pub.pem

# 4) Change label → different ciphertext
./seeded_rsa_pubenc_oaep --label "ctx-v2" 00112233445566778899aabbccddeeff "hello" pub.pem

