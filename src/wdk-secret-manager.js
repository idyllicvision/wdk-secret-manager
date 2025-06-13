import b4a from 'b4a';
import * as bip39 from 'bip39';
import sodium from 'sodium-universal';
import { Buffer } from 'buffer';
import CryptoJS from 'crypto-js';

/**
 *
 * @type {{generate: (function(): Buffer)}}
 */
export const wdkSaltGenerator = {
  generate: () => {
    const resultBuffer = b4a.alloc(16);
    sodium.randombytes_buf(resultBuffer);
    return resultBuffer;
  },
};

export default class WdkSecretManager {
  /**
   *
   * @param {string} passKey - The user's password (e.g., "password123").
   */
  #passkey = null;
  /**
   * @param {Buffer} salt - A unique, random 16-byte salt. This should be
   * generated once per user and stored alongside the
   * encrypted data. It is not a secret.
   */
  #salt = null;

  /**
   *
   * @param {string} passKey - The user's password (e.g., "password123").
   * @param {Buffer} salt - A unique, random 16-byte salt. This should be
   * generated once per user and stored alongside the
   * encrypted data. It is not a secret.
   */
  constructor(passKey, salt = null) {
    this.#passKeyValidator(passKey);
    this.#saltValidator(salt);
    this.#passkey = passKey;
    this.#salt = salt;
  }

  /**
   * Derives a strong, 32-byte (256-bit) cryptographic key from a user's password
   * Salt for preventing rainbow table attacks.
   * using the pwhash algorithm.
   * @return {Buffer}
   */
  #deriveKeyFromPassKey() {
    this.#passKeyValidator(this.#passkey);
    this.#saltValidator(this.#salt); // 16-byte Buffer

    const key = CryptoJS.PBKDF2(this.#passkey, CryptoJS.enc.Hex.parse(this.#salt.toString('hex')), {
      keySize: 256 / 32, // 256-bit = 32 bytes
      iterations: 5000,
      hasher: CryptoJS.algo.SHA256,
    });

    return Buffer.from(key.toString(CryptoJS.enc.Hex), 'hex');
  }

  /**
   * Generate randomBytes(16) Entropy
   * Convert Entropy to BIP39 mnemonic phrase
   * Convert BIP39 mnemonic phrase to seed buffer
   * Encrypt a seed buffer
   * Encrypt a randomBytes(16) Entropy
   * @param {Buffer} [payload=null] - Optional randomBytes(16) entropy. If not provided, it will be generated.
   * @returns {{encryptedSeed: Buffer, encryptedEntropy: Buffer}} A Object containing the encrypted seed and entropy.
   */
  generateAndEncrypt(payload = null) {
    if (payload) if (!b4a.isBuffer(payload)) throw new Error('Payload is not a buffer!');
    const entropy = payload ? payload : this.generateRandomBuffer();
    const seedBuffer = bip39.mnemonicToSeedSync(bip39.entropyToMnemonic(entropy));

    const encryptedSeed = this.#encrypt(seedBuffer, seedBuffer.byteLength);
    const encryptedEntropy = this.#encrypt(entropy, entropy.byteLength);

    return { encryptedSeed, encryptedEntropy };
  }

  /**
   * Encrypt entropy or seed buffer
   * @param {Buffer} buffer.
   * @param {number} buffLength.
   * @return {Buffer} A Buffer containing the encrypted payload.
   */
  #encrypt(buffer, buffLength) {
    if (!b4a.isBuffer(buffer)) throw new Error('Payload is not a buffer!');
    if (!buffLength) throw new Error('Incorrect buffer length');
    const key = this.#deriveKeyFromPassKey();
    if (buffer.byteLength > 64 || buffer.byteLength < 16)
      throw new Error('Buffer size must be between 16 and 64');

    const payload = b4a.alloc(
      1 + sodium.crypto_secretbox_NONCEBYTES + 1 + buffLength + sodium.crypto_secretbox_MACBYTES,
    );
    payload[0] = 0; // version

    const nonce = payload.subarray(1, 1 + sodium.crypto_secretbox_NONCEBYTES);
    const cipher = payload.subarray(1 + nonce.byteLength);
    const plain = cipher.subarray(0, cipher.byteLength - sodium.crypto_secretbox_MACBYTES);
    plain[0] = buffer.byteLength;
    plain.set(buffer, 1);

    sodium.sodium_memzero(buffer);
    sodium.randombytes_buf(nonce);
    // encrypt in-place
    sodium.crypto_secretbox_easy(cipher, plain, nonce, key);

    return payload;
  }

  /**
   * Decrypts a payload to retrieve a BIP39 mnemonic phrase.
   * @param {Buffer} payload - The encrypted payload.
   * @return {Buffer} The decrypted mnemonic phrase.
   */
  decrypt(payload) {
    if (!b4a.isBuffer(payload)) {
      throw new Error('Payload is not a buffer!');
    }
    const minLength = 1 + sodium.crypto_secretbox_NONCEBYTES + 1 + sodium.crypto_secretbox_MACBYTES;
    if (payload.byteLength < minLength) {
      throw new Error('Invalid payload: too short');
    }

    if (payload[0] !== 0) {
      throw new Error('Invalid version');
    }
    const key = this.#deriveKeyFromPassKey();
    const nonce = payload.subarray(1, 1 + sodium.crypto_secretbox_NONCEBYTES);
    const cipher = payload.subarray(1 + nonce.byteLength);

    const plain = b4a.alloc(cipher.byteLength - sodium.crypto_secretbox_MACBYTES);
    if (!sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key)) {
      throw new Error('Decryption failed');
    }
    const bytes = plain[0];
    if (bytes > 64) {
      throw new Error('Invalid decrypted payload');
    }

    if (plain.byteLength < 1 + bytes) {
      throw new Error('Invalid decrypted payload: inconsistent length');
    }
    const resultBuffer = b4a.alloc(bytes);
    resultBuffer.set(plain.subarray(1, 1 + bytes));
    sodium.sodium_memzero(plain);
    return resultBuffer;
  }

  /**
   * Generates a random 128 bits buffer
   * @return {Buffer} Which can be converted BIP39 mnemonic phrase (12 words).
   */
  generateRandomBuffer() {
    const resultBuffer = b4a.alloc(16);
    sodium.randombytes_buf(resultBuffer);
    return resultBuffer;
  }

  /**
   *
   * @param {Buffer} entropy - 128 bits entropy buffer.
   * @return {string} - BIP39 mnemonic phrase (12 words by default for 128 bits).
   */
  entropyToMnemonic(entropy) {
    if (!b4a.isBuffer(entropy)) throw new Error('Payload is not a buffer!');
    return bip39.entropyToMnemonic(entropy);
  }

  #passKeyValidator(passKey) {
    if (!passKey) {
      throw new Error('Pass key must not be empty!');
    }
    if (typeof passKey !== 'string') {
      throw new Error('Pass key must be a string!');
    }
  }

  #saltValidator(salt) {
    if (!salt) {
      throw new Error('Salt must not be empty!');
    }
    if (!b4a.isBuffer(salt)) {
      throw new Error('Salt must be a buffer!');
    }
    if (salt.byteLength < 16) {
      throw new Error('Salt must be at least 16 bytes!');
    }
  }

  /**
   *
   * @param decryptedSeedBuffer
   * @param decryptedEntropy
   */
  destructor(decryptedSeedBuffer, decryptedEntropy) {
    sodium.sodium_memzero(decryptedSeedBuffer);
    sodium.sodium_memzero(decryptedEntropy);
    sodium.sodium_memzero(this.#salt);
    decryptedSeedBuffer = null;
    decryptedEntropy = null;
    this.#passkey = null;
    this.#salt = null;
  }
}
