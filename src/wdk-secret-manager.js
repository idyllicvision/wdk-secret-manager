import crypto from 'crypto';
import b4a from 'b4a';
import * as argon2 from 'argon2';
import bip39 from 'bip39';
import sodium from 'sodium-universal'

/**
 *
 * @type {{generate: (function(): string)}}
 */
export const wdkSaltGenerator = {
    generate: () => crypto.randomBytes(16).toString('hex')
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
     * using the Argon2id algorithm.
     * @return {Promise<Buffer>}
     */
    async deriveKeyFromPassKey() {
        try {
            this.#passKeyValidator(this.#passkey);
            this.#saltValidator(this.#salt);
            const options = {
                salt: this.#salt,
                type: argon2.argon2id,
                memoryCost: 19456, // 19 MiB
                timeCost: 2,
                parallelism: 1,
                hashLength: 32, // 32 bytes for a 256-bit AES key
                raw: true, // IMPORTANT: This gives us the raw key
            }
            return await argon2.hash(this.#passkey, options);
        } catch (error) {
            throw new Error(error);
        }

    }

    /**
     * Encrypts a BIP39 mnemonic phrase.
     * @param {string} phrase - The mnemonic phrase to encrypt.
     * @return {Promise<Buffer>} A Buffer containing the encrypted payload.
     */
    async encrypt(phrase) {
        try {
            const key = await this.deriveKeyFromPassKey();

            const entropy = b4a.from(bip39.mnemonicToEntropy(phrase), 'hex')
            if (entropy.byteLength > 32) throw new Error('Phrase is too long')

            const payload = b4a.alloc(1 + sodium.crypto_secretbox_NONCEBYTES + 1 + 32 + sodium.crypto_secretbox_MACBYTES)
            payload[0] = 0 // version

            const nonce = payload.subarray(1, 1 + sodium.crypto_secretbox_NONCEBYTES)
            const cipher = payload.subarray(1 + nonce.byteLength)
            const plain = cipher.subarray(0, cipher.byteLength - sodium.crypto_secretbox_MACBYTES)
            plain[0] = entropy.byteLength
            plain.set(entropy, 1)

            sodium.sodium_memzero(entropy)
            sodium.randombytes_buf(nonce)
            // encrypt in-place
            sodium.crypto_secretbox_easy(cipher, plain, nonce, key)

            return payload
        } catch (error) {
            throw new Error(error);
        }

    }

    /**
     * Decrypts a payload to retrieve a BIP39 mnemonic phrase.
     * @param {Buffer} payload - The encrypted payload.
     * @return {Promise<string>} The decrypted mnemonic phrase.
     */
    async decrypt(payload) {
        if (payload.byteLength < 1 + sodium.crypto_secretbox_NONCEBYTES + 1 + 32 + sodium.crypto_secretbox_MACBYTES) {
            throw new Error('Invalid payload')
        }


        if (payload[0] !== 0) {
            throw new Error('Invalid version')
        }

        try {
            const key = await this.deriveKeyFromPassKey();

            const nonce = payload.subarray(1, 1 + sodium.crypto_secretbox_NONCEBYTES)
            const cipher = payload.subarray(1 + nonce.byteLength)
            const plain = cipher.subarray(0, cipher.byteLength - sodium.crypto_secretbox_MACBYTES)

            if (!sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key)) {
                throw new Error('Decryption failed')
            }

            const bytes = plain[0]
            if (bytes > 32) {
                throw new Error('Invalid decrypted payload')
            }

            const entropy = plain.subarray(1, 1 + bytes)
            return bip39.entropyToMnemonic(b4a.toString(entropy, 'hex'))
        } catch (error) {
            throw new Error(error);
        }


    }

    /**
     * Generates a random BIP39 mnemonic phrase (12 words by default for 128 bits).
     * @param {number} [strength=128] - The desired bit strength for the mnemonic.
     * @return {string} A string containing the random words.
     */
    generateRandomSeed(strength = 128) {
        return bip39.generateMnemonic(strength);
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
        if (!Buffer.isBuffer(salt)) {
            throw new Error('Salt must be a buffer!');
        }
        if (salt.byteLength < 16) { // Argon2 typically recommends at least 8 bytes, 16 is common.
            console.warn('Salt is less than 16 bytes. This is permissible, but 16 bytes is a common recommendation.');
        }
    }


}