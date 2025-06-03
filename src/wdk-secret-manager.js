import crypto from 'crypto';
import b4a from 'b4a';
import * as argon2 from 'argon2';
import bip39 from 'bip39';
import sodium from 'sodium-universal'

/**
 *
 * @type {{generate: (function(): Buffer)}}
 */
export const wdkSaltGenerator = {
    generate: () => crypto.randomBytes(16)
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
     * @param {Buffer} entropy.
     * @return {Promise<{encryptedSeed, encryptedEntropy, seedBuffer}>} A Object containing the encrypted seed/entropy and seed Buffer.
     */
    async encrypt(entropy) {
        if (!b4a.isBuffer(entropy)) throw new Error('Payload is not a buffer')
        const seedBuffer = bip39.mnemonicToSeedSync(bip39.entropyToMnemonic(entropy))
        const cpSeedBuffer = Buffer.from(seedBuffer);
        const encryptedSeed = await this.#encryptor(seedBuffer, seedBuffer.length);

        const encryptedEntropy = await this.#encryptor(entropy, entropy.length);

        return {encryptedSeed, encryptedEntropy, ...{seedBuffer: cpSeedBuffer}};
    }

    /**
     * Encrypts a BIP39 mnemonic phrase.
     * @param {Buffer} buffer.
     * @param {number} buffLength.
     * @return {Promise<Buffer>} A Buffer containing the encrypted payload.
     */
    async #encryptor(buffer, buffLength) {
        if (!b4a.isBuffer(buffer)) throw new Error('Payload is not a buffer')
        if (!buffLength) throw new Error('Incorrect buffer length');
        const key = await this.deriveKeyFromPassKey();

        if (buffer.byteLength > 64 || buffer.byteLength < 16) throw new Error('Phrase is too long')

        const payload = b4a.alloc(1 + sodium.crypto_secretbox_NONCEBYTES + 1 + buffLength + sodium.crypto_secretbox_MACBYTES)
        payload[0] = 0 // version

        const nonce = payload.subarray(1, 1 + sodium.crypto_secretbox_NONCEBYTES)
        const cipher = payload.subarray(1 + nonce.byteLength)
        const plain = cipher.subarray(0, cipher.byteLength - sodium.crypto_secretbox_MACBYTES)
        plain[0] = buffer.byteLength
        plain.set(buffer, 1)

        sodium.sodium_memzero(buffer)
        sodium.randombytes_buf(nonce)
        // encrypt in-place
        sodium.crypto_secretbox_easy(cipher, plain, nonce, key)

        return payload
    }

    /**
     * Decrypts a payload to retrieve a BIP39 mnemonic phrase.
     * @param {Buffer} payload - The encrypted payload.
     * @return {Promise<Buffer>} The decrypted mnemonic phrase.
     */
    async decrypt(payload) {
        if (!b4a.isBuffer(payload)) {
            throw new Error('Payload is not a buffer')
        }
        const minLength = 1 + sodium.crypto_secretbox_NONCEBYTES + 1 + sodium.crypto_secretbox_MACBYTES;
        if (payload.byteLength < minLength) {
            throw new Error('Invalid payload: too short');
        }


        if (payload[0] !== 0) {
            throw new Error('Invalid version')
        }
        const key = await this.deriveKeyFromPassKey();

        const nonce = payload.subarray(1, 1 + sodium.crypto_secretbox_NONCEBYTES)
        const cipher = payload.subarray(1 + nonce.byteLength)
        const plain = cipher.subarray(0, cipher.byteLength - sodium.crypto_secretbox_MACBYTES)

        if (!sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key)) {
            throw new Error('Decryption failed')
        }

        const bytes = plain[0]
        if (bytes > 64) {
            throw new Error('Invalid decrypted payload')
        }

        if (plain.byteLength < 1 + bytes) {
            throw new Error('Invalid decrypted payload: inconsistent length');
        }

        return plain.subarray(1, 1 + bytes)
    }

    /**
     * Generates a random 128 bits buffer
     * @return {Buffer} Which can be converted BIP39 mnemonic phrase (12 words).
     */
    generateRandomBuffer() {
        return crypto.randomBytes(16);
    }

    /**
     *
     * @param {Buffer} entropy - 128 bits entropy buffer.
     * @return {string} - BIP39 mnemonic phrase (12 words by default for 128 bits).
     */
    entropyToMnemonic(entropy) {
        if (!b4a.isBuffer(entropy)) throw new Error('Payload is not a buffer')
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
        if (!Buffer.isBuffer(salt)) {
            throw new Error('Salt must be a buffer!');
        }
        if (salt.byteLength < 16) { // Argon2 typically recommends at least 8 bytes, 16 is common.
            console.warn('Salt is less than 16 bytes. This is permissible, but 16 bytes is a common recommendation.');
        }
    }

    /**
     *
     * Clean up variables.
     */
    destructor() {
        this.#passkey = null;
        this.#salt = null;
    }


}