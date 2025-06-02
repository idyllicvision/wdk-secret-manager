# WdkSecretManager

## Description

WdkSecretManager is a JavaScript library designed for securely managing secrets, specifically BIP39 mnemonic phrases. It uses a user-provided passkey and a salt to derive a strong cryptographic key using Argon2id. This key is then used to encrypt and decrypt mnemonic phrases using `sodium-universal` (libsodium).

The library provides functionalities to:
- Derive a cryptographic key from a passkey and salt.
- Encrypt BIP39 mnemonic phrases.
- Decrypt the encrypted payload back to the original mnemonic phrase.
- Generate random BIP39 mnemonic phrases.
- Generate a cryptographically secure salt.

## Dependencies

This library relies on the following external modules:
- `crypto`: For generating random bytes (e.g., for salt).
- `b4a`: Buffer-to-array and array-to-buffer conversions.
- `argon2`: For key derivation using the Argon2id algorithm.
- `bip39`: For mnemonic phrase generation and entropy conversion.
- `sodium-universal`: For cryptographic operations (encryption/decryption).

## Security Notes
- Passkey Strength: The security of the encrypted data heavily depends on the strength of the passKey. Encourage users to choose strong, unique passkeys.

- Salt Management: The salt is not secret but must be unique per passkey. It should be stored alongside the encrypted data. Reusing salts across different passkeys or for different users is insecure.

- Key Derivation Parameters: The Argon2id parameters (memoryCost, timeCost, parallelism) are set to reasonable defaults.