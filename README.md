# crypto-test

Intentional cryptography usage for testing **CBOM** (Cryptography Bill of Materials)
generation. `crypto_examples.py` exercises a spread of primitives so a CBOM scan
produces varied `cryptographic-asset` findings:

- **Quantum-vulnerable:** RSA-2048, ECDSA P-256
- **Weak/deprecated:** MD5, SHA-1, 3DES
- **Modern:** SHA-256, AES-GCM, HMAC-SHA256, Fernet
- **Protocol:** TLS 1.2

Not for production use.
