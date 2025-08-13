# WdkSecretManager

## Description

WdkSecretManager is a JavaScript library designed for securely managing secrets, specifically BIP39 mnemonic phrases. It uses a user-provided passkey and a salt to derive a strong cryptographic key using libsodium pbkdf2. This key is then used to encrypt and decrypt mnemonic phrases using `sodium-native` (libsodium).

The library provides functionalities to:
- Derive a cryptographic key from a passkey and salt.
- Encrypt BIP39 seed phrase.
- Decrypt the encrypted payload back to the original seed phrase.
- Generate random BIP39 mnemonic phrases.
- Generate a cryptographically secure salt.

## Dependencies

This library relies on the following external modules:
- `b4a`: Buffer-to-array and array-to-buffer conversions.
- `bip39`: For mnemonic phrase generation and entropy conversion.
- `sodium-native`: For cryptographic operations (memory allocation/random data generation/encryption/decryption).

## Security Notes
- Passkey Strength: The security of the encrypted data heavily depends on the strength of the passKey. Encourage users to choose strong, unique passkeys.

- Salt Management: The salt is not secret but must be unique per passkey. It should be stored alongside the encrypted data. Reusing salts across different passkeys or for different users is insecure.

- KDF rotation: You can raise iterations over time; old payloads remain decryptable (they carry their own params).

- Key Derivation Parameters: The pbkdf2 parameters (256-bit key, passkey, salt) are set to reasonable defaults.

## Example

```js
import WdkSecretManager from '@wdk/wdk-secret-manager'

// 1) Create a manager with a strong passkey (≥ 12 chars) and a 16-byte salt
const passkey = 'correct horse battery staple'
const salt = WdkSecretManager.generateSalt()
const sm = new WdkSecretManager(passkey, salt, { iterations: 100_000 })

// 2) Generate entropy + seed and encrypt both
const { encryptedSeed, encryptedEntropy } = await sm.generateAndEncrypt()

// 3) Decrypt later using the same passkey+salt
const entropy = sm.decrypt(encryptedEntropy)    
const seed    = sm.decrypt(encryptedSeed)

// 4) Convert entropy ↔ mnemonic (12 words for 16-byte entropy)
const mnemonic = sm.entropyToMnemonic(entropy)
const backToEntropy = sm.mnemonicToEntropy(mnemonic)

// Optional: encrypt/decrypt any 16–64 byte payload
const enc = sm.encrypt(Buffer.from('0123456789abcdef0123456789abcdef'))
const dec = sm.decrypt(enc)

// Cleanup sensitive fields (passkey/salt) from memory
sm.dispose()
```