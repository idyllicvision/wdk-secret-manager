/**
 *
 * @type {{generate: (function(): Buffer)}}
 */
export const wdkSaltGenerator: {
    generate: (() => Buffer);
};
export class WdkSecretManager {
    /**
     *
     * @param {Buffer | ArrayBuffer | Uint8Array | string} passKey - The user's password (e.g., "password123").
     * @param {Buffer} salt - A unique, random 16-byte salt. This should be
     * generated once per user and stored alongside the
     * encrypted data. It is not a secret.
     */
    constructor(passKey: Buffer | ArrayBuffer | Uint8Array | string, salt?: Buffer);
    /**
     * Generate randomBytes(16) Entropy
     * Convert Entropy to BIP39 mnemonic phrase
     * Convert BIP39 mnemonic phrase to seed buffer
     * Encrypt a seed buffer
     * Encrypt a randomBytes(16) Entropy
     * @param {Buffer} [payload=null] - Optional randomBytes(16) entropy. If not provided, it will be generated.
     * @param {Buffer} [derivedKey=null] - Optional ArrayBuffer(32) bytes cryptographic key.
     * @returns {{encryptedSeed: Buffer, encryptedEntropy: Buffer}} A Object containing the encrypted seed and entropy.
     */
    generateAndEncrypt(payload?: Buffer, derivedKey?: Buffer): {
        encryptedSeed: Buffer;
        encryptedEntropy: Buffer;
    };
    /**
     * Decrypts a payload to retrieve a BIP39 mnemonic phrase.
     * @param {Buffer} payload - The encrypted payload.
     * @param {Buffer} [derivedKey=null] - Optional ArrayBuffer(32) bytes cryptographic key.
     * @return {Buffer} The decrypted mnemonic phrase.
     */
    decrypt(payload: Buffer, derivedKey?: Buffer): Buffer;
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
     * @param {string} seedPhrase
     * @return {Buffer}
     */
    mnemonicToEntropy(seedPhrase: string): Buffer;
    /**
     * Erase the salt and passkey from memory.
     */
    dispose(): void;
    #private;
}
