/**
 *
 * @type {{generate: (function(): Buffer)}}
 */
export const wdkSaltGenerator: {
    generate: (() => Buffer);
};
export default class WdkSecretManager {
    /**
     *
     * @param {string} passKey - The user's password (e.g., "password123").
     * @param {Buffer} salt - A unique, random 16-byte salt. This should be
     * generated once per user and stored alongside the
     * encrypted data. It is not a secret.
     */
    constructor(passKey: string, salt?: Buffer);
    /**
     * Derives a strong, 32-byte (256-bit) cryptographic key from a user's password
     * Salt for preventing rainbow table attacks.
     * using the Argon2id algorithm.
     * @return {Promise<Buffer>}
     */
    deriveKeyFromPassKey(): Promise<Buffer>;
    /**
     * Encrypts a BIP39 mnemonic phrase.
     * @param {string} phrase - The mnemonic phrase to encrypt.
     * @return {Promise<Buffer>} A Buffer containing the encrypted payload.
     */
    encrypt(phrase: string): Promise<Buffer>;
    /**
     * Decrypts a payload to retrieve a BIP39 mnemonic phrase.
     * @param {Buffer} payload - The encrypted payload.
     * @return {Promise<string>} The decrypted mnemonic phrase.
     */
    decrypt(payload: Buffer): Promise<string>;
    /**
     * Generates a random BIP39 mnemonic phrase (12 words by default for 128 bits).
     * @param {number} [strength=128] - The desired bit strength for the mnemonic.
     * @return {string} A string containing the random words.
     */
    generateRandomSeed(strength?: number): string;
    #private;
}
