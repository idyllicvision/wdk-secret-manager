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
     * @param {Buffer} entropy.
     * @return {Promise<{encryptedSeed, encryptedEntropy, seedBuffer}>} A Object containing the encrypted seed/entropy and seed Buffer.
     */
    encrypt(entropy: any): Promise<{
        encryptedSeed: any;
        encryptedEntropy: any;
        seedBuffer: any;
    }>;
    /**
     * Decrypts a payload to retrieve a BIP39 mnemonic phrase.
     * @param {Buffer} payload - The encrypted payload.
     * @return {Promise<Buffer>} The decrypted mnemonic phrase.
     */
    decrypt(payload: Buffer): Promise<Buffer>;
    /**
     * Generates a random 128 bits buffer
     * @return {Buffer} Which can be converted BIP39 mnemonic phrase (12 words).
     */
    generateRandomBuffer(): Buffer;
    /**
     *
     * @param {Buffer} entropy - 128 bits entropy buffer.
     * @return {string} - BIP39 mnemonic phrase (12 words by default for 128 bits).
     */
    entropyToMnemonic(entropy: Buffer): string;
    /**
     *
     * Clean up variables.
     */
    destructor(): void;
    #private;
}
