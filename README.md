# Encrypt KV numbers
Work in progress.
Requires openssl 3.x

Warning: By using a seeded RNG and deterministic RSA encryption, this is NOT SAFE! Don't use it except in the very specific use case it's made for.


Generating keys:
```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.pem
openssl pkey -in priv.pem -pubout -out pub.pem
```
