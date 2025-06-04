import WdkSecretManager, {wdkSaltGenerator} from "../index.js";
import crypto from 'crypto';
import bip39 from "bip39";
/**
 * @jest-environment node
 */

describe('wdkSaltGenerator', () => {
    it('should generate a 16-byte buffer', () => {
        const salt = wdkSaltGenerator.generate();
        expect(salt).toBeInstanceOf(Buffer);
        expect(salt.length).toBe(16);
    });
});

describe('WdkSecretManager', () => {
    const passKey = 'my-super-secret-password-123';
    const salt = wdkSaltGenerator.generate();
    const knownEntropy = Buffer.from('9f8c7e3d6a2b4c1e0f3a9d5c6b7e2a1f', 'hex');
    const knownMnemonic = 'panel glue monster stairs regular audit diagram father fragile fossil melody display';
    describe('Constructor', () => {
        it('should create an instance with a valid passKey and salt', () => {
            const manager = new WdkSecretManager(passKey, salt);
            expect(manager).toBeInstanceOf(WdkSecretManager);
        });
        it('should throw an error if passKey is missing', () => {
            expect(() => new WdkSecretManager(null, salt)).toThrow('Pass key must not be empty!');
        });

        it('should throw an error if passKey is not a string', () => {
            expect(() => new WdkSecretManager(12345, salt)).toThrow('Pass key must be a string!');
        });

        it('should throw an error if salt is missing', () => {
            expect(() => new WdkSecretManager(passKey, null)).toThrow('Salt must not be empty!');
        });

        it('should throw an error if salt is not a buffer', () => {
            expect(() => new WdkSecretManager(passKey, 'not-a-buffer')).toThrow('Salt must be a buffer!');
        });

        it('should create an instance with a salt smaller than 16 bytes and throw error', () => {
            const shortSalt = crypto.randomBytes(12);
            expect(() => new WdkSecretManager(passKey, shortSalt)).toThrow('Salt must be at least 16 bytes!');
        });
    })

    describe('Helper Methods', () => {
        it('should generate a random 16-byte buffer', () => {
            const manager = new WdkSecretManager(passKey, salt);
            const buffer = manager.generateRandomBuffer();
            expect(buffer).toBeInstanceOf(Buffer);
            expect(buffer.length).toBe(16);
        });

        it('should convert a known entropy to the correct mnemonic', () => {
            const manager = new WdkSecretManager(passKey, salt);
            const mnemonic = manager.entropyToMnemonic(knownEntropy);
            expect(mnemonic).toEqual(knownMnemonic);
        });

        it('should throw an error if entropyToMnemonic receives a non-buffer', () => {
            const manager = new WdkSecretManager(passKey, salt);
            expect(() => manager.entropyToMnemonic('not-a-buffer')).toThrow('Payload is not a buffer!');
        });
    });

    describe('Encryption and Decryption Cycle', () => {
        it('should correctly generate, encrypt, and then decrypt entropy', () => {
            const manager = new WdkSecretManager(passKey, salt);
            const entropy = manager.generateRandomBuffer();
            const cpEntropy = Buffer.from(entropy);
            const { encryptedEntropy } = manager.generateAndEncrypt(entropy);
            const decryptedEntropy = manager.decrypt(encryptedEntropy);
            expect(decryptedEntropy).toEqual(cpEntropy);
        });
        it('should correctly generate, encrypt, and then decrypt a seed buffer', () => {
            const manager = new WdkSecretManager(passKey, salt);
            const entropy = manager.generateRandomBuffer();
            const localSeed = bip39.mnemonicToSeedSync(manager.entropyToMnemonic(entropy));
            const { encryptedSeed } = manager.generateAndEncrypt(entropy);
            const decryptedSeed = manager.decrypt(encryptedSeed);

            // The decrypted seed should be 64 bytes long for a 128-bit entropy
            expect(decryptedSeed).toBeInstanceOf(Buffer);
            expect(decryptedSeed.length).toBe(64);
            expect(decryptedSeed).toEqual(localSeed);
        });

        it('should successfully encrypt/decrypt entropy when no payload is provided', () => {
            const manager = new WdkSecretManager(passKey, salt);
            const { encryptedEntropy } = manager.generateAndEncrypt(); // No payload
            const decryptedEntropy = manager.decrypt(encryptedEntropy);
            expect(decryptedEntropy.length).toBe(16);
        });
        it('should successfully encrypt/decrypt seed buffer when no payload is provided', () => {
            const manager = new WdkSecretManager(passKey, salt);
            const { encryptedSeed } = manager.generateAndEncrypt(); // No payload
            const decryptedSeed = manager.decrypt(encryptedSeed);
            expect(decryptedSeed.length).toBe(64);
        });
    })

    describe('Encryption failures', () => {
        let manager;
        let entropy;

        beforeEach(() => {
            manager = new WdkSecretManager(passKey, salt);
            entropy = manager.generateRandomBuffer();
        });

        it('should throw an error if encryption payload is not a buffer', () => {
            expect(() => manager.generateAndEncrypt("not a buffer")).toThrow('Payload is not a buffer!');
        });
    })

    describe('Decryption Failures', () => {
        let manager;
        let encryptedEntropy;
        let entropy;

        beforeEach(() => {
            manager = new WdkSecretManager(passKey, salt);
            entropy = manager.generateRandomBuffer();
            ({ encryptedEntropy } = manager.generateAndEncrypt(entropy));
        });

        it('should throw an error if trying to decrypt with the wrong passKey', () => {
            const wrongManager = new WdkSecretManager('this-is-the-wrong-password', salt);
            expect(() => wrongManager.decrypt(encryptedEntropy)).toThrow('Decryption failed');
        });

        it('should throw an error if trying to decrypt with the wrong salt', () => {
            const wrongSalt = crypto.randomBytes(16);
            const wrongManager = new WdkSecretManager(passKey, wrongSalt);
            expect(() => wrongManager.decrypt(encryptedEntropy)).toThrow('Decryption failed');
        });

        it('should throw an error if the encrypted payload is tampered with', () => {
            // Tamper with a byte in the cipher text part of the payload
            encryptedEntropy[encryptedEntropy.length - 5]++;
            expect(() => manager.decrypt(encryptedEntropy)).toThrow('Decryption failed');
        });

        it('should throw an error for a payload that is too short', () => {
            const shortPayload = Buffer.from([0, 1, 2, 3]);
            expect(() => manager.decrypt(shortPayload)).toThrow('Invalid payload: too short');
        });

        it('should throw an error for an invalid version byte', () => {
            encryptedEntropy[0] = 1; // Change version from 0 to 1
            expect(() => manager.decrypt(encryptedEntropy)).toThrow('Invalid version');
        });

        it('should throw an error if decrypt payload is not a buffer', () => {
            expect(() => manager.decrypt("not a buffer")).toThrow('Payload is not a buffer!');
        });
    });



})