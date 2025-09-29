# 1) Keypair & pubkey
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.pem
openssl pkey -in priv.pem -pubout -out pub.pem

# 2) Build
make

echo "The two outputs should be the same:"
./kv-encrypt pub.pem tests/test_kvs.txt
cat tests/test_kvs.txt.out
./kv-encrypt pub.pem tests/test_kvs.txt
cat tests/test_kvs.txt.out
# 3) Determinism: same key/label → same ciphertext
echo "The two outputs should be the same but different from the first two:"
./kv-encrypt --label "ctx-v1" pub.pem tests/test_kvs.txt
cat tests/test_kvs.txt.out
./kv-encrypt --label "ctx-v1" pub.pem tests/test_kvs.txt
cat tests/test_kvs.txt.out

# 4) Change label → different ciphertext
echo "The last output should be different:"
./kv-encrypt --label "ctx-v2" pub.pem tests/test_kvs.txt
cat tests/test_kvs.txt.out

