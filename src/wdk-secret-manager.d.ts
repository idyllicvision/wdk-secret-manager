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
     * Generate randomBytes(16) Entropy
     * Convert Entropy to BIP39 mnemonic phrase
     * Convert BIP39 mnemonic phrase to seed buffer
     * Encrypt a seed buffer
     * Encrypt a randomBytes(16) Entropy
     * @param {Buffer = null} payload - The randomBytes(16) Entropy.
     * @return {encryptedSeed, encryptedEntropy} A Object containing the encrypted seed/entropy and seed Buffer.
     */
    generateAndEncrypt(payload?: any): Buffer;
    /**
     * Decrypts a payload to retrieve a BIP39 mnemonic phrase.
     * @param {Buffer} payload - The encrypted payload.
     * @return {Buffer} The decrypted mnemonic phrase.
     */
    decrypt(payload: Buffer): Buffer;
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
     * @param decryptedSeedBuffer
     * @param decryptedEntropy
     */
    destructor(decryptedSeedBuffer: any, decryptedEntropy: any): void;
    #private;
}
