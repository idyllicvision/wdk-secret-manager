export default class WdkSecretManager {
    /**
     * Generate a cryptographically secure random salt for key derivation.
     * The salt should be unique per passkey and stored alongside encrypted data.
     *
     * @returns {Buffer} A 16-byte random salt buffer
     */
    static generateSalt(): Buffer;
    /**
     * Manages encryption and decryption of secrets using a passkey and salt.
     * Uses PBKDF2 for key derivation and libsodium for cryptographic operations.
     *
     * @param {Buffer|Uint8Array|string} passKey - The passkey used for encryption (min 12 chars)
     * @param {Buffer} salt - A 16-byte salt for key derivation
     * @param {{iterations?: number}} [kdfParams] - Optional params for key derivation
     */
    constructor(passKey: Buffer | Uint8Array | string, salt: Buffer, kdfParams?: {
        iterations?: number;
    });
    /** @private */ private _passkey;
    /** @private */ private _salt;
    /** @private */ private _iterations;
    /**
     * Generate 16-byte entropy, derive mnemonic+seed, and encrypt both.
     *
     * @param {Buffer|null} entropyOpt - If provided, must be 16 bytes.
     * @param {Buffer|null} masterKeyOpt - If provided, 32-byte key (skips PBKDF2).
     * @returns {{encryptedSeed: Buffer, encryptedEntropy: Buffer}} Object containing encrypted seed and entropy buffers
     */
    generateAndEncrypt(entropyOpt?: Buffer | null, masterKeyOpt?: Buffer | null): {
        encryptedSeed: Buffer;
        encryptedEntropy: Buffer;
    };
    /**
     * Encrypt arbitrary data (16–64 bytes) using libsodium's secretbox with a header.
     *
     * The header contains:
     * - Version (1 byte)
     * - KDF algorithm ID (1 byte)
     * - PBKDF2 iterations (4 bytes)
     * - Reserved (4 bytes)
     * - Salt (16 bytes)
     * - Nonce (24 bytes)
     *
     * The encrypted payload contains:
     * - Length prefix (1 byte)
     * - Data (16-64 bytes)
     * - MAC (16 bytes)
     *
     * @param {Buffer} data - The data to encrypt (must be 16-64 bytes)
     * @param {Buffer|null} masterKeyOpt - Optional 32-byte key to skip PBKDF2 derivation
     * @returns {Buffer} Encrypted payload with header
     */
    encrypt(data: Buffer, masterKeyOpt?: Buffer | null): Buffer;
    /**
     * Decrypt a payload produced by this manager.
     *
     * @param {Buffer} payload - The encrypted payload to decrypt
     * @param {Buffer|null} masterKeyOpt - Optional 32-byte key to skip PBKDF2 derivation
     * @returns {Buffer} The decrypted plaintext data
     */
    decrypt(payload: Buffer, masterKeyOpt?: Buffer | null): Buffer;
    /**
     * Generates a cryptographically secure random buffer of 16 bytes
     *
     * @returns {Buffer} A 16-byte buffer filled with random bytes from sodium
     */
    generateRandomBuffer(): Buffer;
    /**
     * Converts 16 bytes of entropy into a 12-word BIP39 mnemonic phrase
     *
     * @param {Buffer} entropy - A 16-byte buffer containing entropy
     * @returns {string} A 12-word mnemonic phrase
     */
    entropyToMnemonic(entropy: Buffer): string;
    /**
     * Converts a 12-word BIP39 mnemonic phrase back into its original 16-byte entropy
     *
     * @param {string} mnemonic - A 12-word BIP39 mnemonic phrase
     * @returns {Buffer} The original 16-byte entropy buffer
     */
    mnemonicToEntropy(mnemonic: string): Buffer;
    /**
     * Securely disposes of sensitive internal state by zeroing out memory buffers
     * and nullifying references. After calling dispose(), the instance cannot be
     * used for further encryption/decryption operations.
     */
    dispose(): void;
    /** @private */
    private _deriveKeyPBKDF2;
    /** @private */
    private _validatePassKey;
    /** @private */
    private _validateSalt;
    /** @private */
    private _validateEntropy;
    /** @private */
    private _validateKey32;
    /** @private */
    private _safeZero;
}
