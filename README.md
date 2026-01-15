# Encrypt KV numbers
This is a tool for deterministically encrypting and fingerprinting German health insurance numbers for usage in record linkage. 
The tool encrypts using OpenSSL's RSA and OAEP padding with a deterministically seeded random number generator to achieve deterministic encryption. Please note that by performing **deterministic** encryption on a quite small message space, this is generally NOT SAFE. The project using this tool (OnkoFDZ) has additional safeguards in place to mitigate all vulnerabilities. More information is available in the project's data protection concept.

Requires openssl 3.x

## Usage

### Generating keys:
```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.pem
openssl pkey -in priv.pem -pubout -out pub.pem
```

Only the public key is used and should be distributed between the parties. The private key must be deleted.

### Encrypting data
```
./kv-encrypt --label "encryption-context" pub.pem tests/test_kvs.txt
```

The encryption label is optional and defaults to "default". However, effectively working as a context-specific salt, its usage (and differing labels for different linkage pairings) is highly encouraged.
The second parameter provides the public key used for encryption, and the last parameter provides the input filename.

In the input file, a valid German health insurance number is expected in every line. The encrypted, fingerprinted "pseudonyms" are saved in <inputfilename>.out; that is, for the example above, `tests/test_kvs.txt.out`.
