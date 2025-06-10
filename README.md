# WdkSecretManager

## Description

WdkSecretManager is a JavaScript library designed for securely managing secrets, specifically BIP39 mnemonic phrases. It uses a user-provided passkey and a salt to derive a strong cryptographic key using libsodium pwhash. This key is then used to encrypt and decrypt mnemonic phrases using `sodium-universal` (libsodium).

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
- `sodium-universal`: For cryptographic operations (memory allocation/random data generation/encryption/decryption).

## Security Notes
- Passkey Strength: The security of the encrypted data heavily depends on the strength of the passKey. Encourage users to choose strong, unique passkeys.

- Salt Management: The salt is not secret but must be unique per passkey. It should be stored alongside the encrypted data. Reusing salts across different passkeys or for different users is insecure.

- Key Derivation Parameters: The pwhash parameters (256-bit key, passkey, salt, ) are set to reasonable defaults.

## Example

```flow js
const salt = wdkSaltGenerator.generate()
const passkey = '1234'
const wdkManager = new WdkSecretManager(passkey, salt);

const encrypted = wdkManager.generateAndEncrypt();

const decryptedSeed = wdkManager.decrypt(encrypted.encryptedSeed);

const decryptedEntropy = wdkManager.decrypt(encrypted.encryptedEntropy);

const mnemonicPhrase = wdkManager.entropyToMnemonic(decryptedEntropy);
```

## Installation
- After module installation.
- If you are using `expo` to run react native app, go to your React native application `ios` directory, open `Podfile` and after this line `config = use_native_modules!(config_command)` add this.
```flow js
pod 'sodium-react-native-direct', :path => '../node_modules/sodium-react-native-direct'
```
- run `pod install` command
- If you are not using `expo`, just run `pod install` from your RN application `ios` directory.