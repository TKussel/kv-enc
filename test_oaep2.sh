# 1) Keypair & pubkey
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.pem
openssl pkey -in priv.pem -pubout -out pub.pem

# 2) Build
make

./kv-encrypt pub.pem
./kv-encrypt pub.pem
# 3) Determinism: same key/label → same ciphertext
./kv-encrypt --label "ctx-v1" pub.pem
./kv-encrypt --label "ctx-v1" pub.pem

# 4) Change label → different ciphertext
./kv-encrypt --label "ctx-v2" pub.pem

