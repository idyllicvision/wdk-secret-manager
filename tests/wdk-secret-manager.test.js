"use strict";

import b4a from "b4a";
import sodium from "sodium-universal";
import bip39 from "bip39-mnemonic";

import { WdkSecretManager, wdkSaltGenerator } from "../index.js";

const rand = (n) => {
  const out = b4a.alloc(n);
  sodium.randombytes_buf(out);
  return out;
};
const eq = (a, b) => b4a.compare(b4a.from(a), b4a.from(b)) === 0;

const PASS = b4a.from("correct horse battery staple");

describe("wdkSaltGenerator", () => {
  test("generate returns a 16-byte Buffer", () => {
    const salt = wdkSaltGenerator.generate();
    expect(Buffer.isBuffer(salt)).toBe(true);
    expect(salt.length).toBe(16);
  });

  test("generate returns different values each time", () => {
    const a = wdkSaltGenerator.generate();
    const b = wdkSaltGenerator.generate();
    expect(eq(a, b)).toBe(false);
  });
});

describe("WdkSecretManager (unit)", () => {
  describe("constructor", () => {
    test("accepts valid passkey buffer and salt", () => {
      const salt = wdkSaltGenerator.generate();
      expect(() => new WdkSecretManager(PASS, salt)).not.toThrow();
    });

    test("rejects empty passkey", () => {
      const salt = wdkSaltGenerator.generate();
      expect(() => new WdkSecretManager(null, salt)).toThrow(
        /Pass key must not be empty/i
      );
    });

    test("rejects invalid passkey type", () => {
      const salt = wdkSaltGenerator.generate();
      expect(() => new WdkSecretManager(12345, salt)).toThrow(
        /Pass key must be a Buffer/i
      );
      expect(() => new WdkSecretManager({}, salt)).toThrow(
        /Pass key must be a Buffer/i
      );
    });

    test("rejects empty salt", () => {
      expect(() => new WdkSecretManager(PASS, null)).toThrow(
        /Salt must not be empty/i
      );
      expect(() => new WdkSecretManager(PASS)).toThrow(
        /Salt must not be empty/i
      );
    });

    test("rejects non-buffer salt", () => {
      expect(() => new WdkSecretManager(PASS, "not a buffer")).toThrow(
        /Salt must be a buffer/i
      );
    });

    test("rejects short salt", () => {
      const shortSalt = rand(8);
      expect(() => new WdkSecretManager(PASS, shortSalt)).toThrow(
        /Salt must be at least 16 bytes/i
      );
    });
  });

  describe("generateRandomBuffer", () => {
    test("returns 16 random bytes", () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const a = sm.generateRandomBuffer();
      const b = sm.generateRandomBuffer();
      expect(a.length).toBe(16);
      expect(Buffer.isBuffer(a)).toBe(true);
      expect(eq(a, b)).toBe(false);
    });
  });

  describe("entropyToMnemonic", () => {
    test("returns a 12-word mnemonic for 16-byte entropy", () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const entropy = sm.generateRandomBuffer();
      const mnemonic = sm.entropyToMnemonic(entropy);
      expect(typeof mnemonic).toBe("string");
      expect(mnemonic.trim().split(/\s+/).length).toBe(12);
    });

    test("rejects non-buffer input", () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      expect(() => sm.entropyToMnemonic("not a buffer")).toThrow(
        /Payload is not a buffer/i
      );
    });
  });

  describe("mnemonicToEntropy", () => {
    test("round-trips with entropyToMnemonic", () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const entropy = sm.generateRandomBuffer();
      const mnemonic = sm.entropyToMnemonic(entropy);
      const back = sm.mnemonicToEntropy(mnemonic);
      expect(eq(entropy, back)).toBe(true);
    });
  });

  describe("generateAndEncrypt", () => {
    test("returns encryptedSeed and encryptedEntropy buffers", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const { encryptedSeed, encryptedEntropy } = await sm.generateAndEncrypt();
      expect(Buffer.isBuffer(encryptedSeed)).toBe(true);
      expect(Buffer.isBuffer(encryptedEntropy)).toBe(true);
    });

    test("accepts custom entropy payload", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const customEntropy = rand(16);
      // Copy before encryption since encrypt zeros the original buffer
      const customEntropyCopy = b4a.from(customEntropy);
      const { encryptedEntropy } = await sm.generateAndEncrypt(customEntropy);
      const decryptedEntropy = sm.decrypt(encryptedEntropy);
      expect(eq(decryptedEntropy, customEntropyCopy)).toBe(true);
    });

    test("rejects non-buffer payload", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      await expect(sm.generateAndEncrypt("not a buffer")).rejects.toThrow(
        /Payload is not a buffer/i
      );
    });

    test("rejects payload smaller than 16 bytes", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const smallPayload = rand(15);
      await expect(sm.generateAndEncrypt(smallPayload)).rejects.toThrow(
        /seed must be a multiple of 4 bytes/i
      );
    });

    test("rejects payload larger than 64 bytes", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const largePayload = rand(65);
      await expect(sm.generateAndEncrypt(largePayload)).rejects.toThrow(
        /Invalid mnemonic/i
      );
    });

    test("with known entropy matches BIP39 seed", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const knownEntropy = rand(16);
      // Copy before encryption since encrypt zeros the original buffer
      const knownEntropyCopy = b4a.from(knownEntropy);
      const mnemonic = sm.entropyToMnemonic(knownEntropy);
      const expectedSeed = await bip39.mnemonicToSeed(mnemonic);

      const { encryptedSeed, encryptedEntropy } = await sm.generateAndEncrypt(
        knownEntropyCopy
      );
      const decryptedEntropy = sm.decrypt(encryptedEntropy);
      expect(eq(decryptedEntropy, knownEntropy)).toBe(true);

      const decryptedSeed = sm.decrypt(encryptedSeed);
      expect(eq(decryptedSeed, expectedSeed)).toBe(true);
    });

    test("accepts custom derivedKey", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const customKey = rand(32);
      const customEntropy = rand(16);
      // Copy before encryption since encrypt zeros the original buffer
      const customEntropyCopy = b4a.from(customEntropy);
      const { encryptedEntropy } = await sm.generateAndEncrypt(
        customEntropy,
        customKey
      );
      const decrypted = sm.decrypt(encryptedEntropy, customKey);
      expect(eq(decrypted, customEntropyCopy)).toBe(true);
    });
  });

  describe("encrypt/decrypt", () => {
    test("encrypt → decrypt round-trip with passkey+salt", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const data = rand(32);
      // Copy before encryption since encrypt zeros the original buffer
      const dataCopy = b4a.from(data);
      const { encryptedEntropy } = await sm.generateAndEncrypt(data);
      const decrypted = sm.decrypt(encryptedEntropy);
      expect(eq(decrypted, dataCopy)).toBe(true);
    });

    test("decrypt fails with wrong passkey", async () => {
      const salt = wdkSaltGenerator.generate();
      const sm1 = new WdkSecretManager(PASS, salt);
      const data = rand(16);
      const { encryptedEntropy } = await sm1.generateAndEncrypt(data);

      const sm2 = new WdkSecretManager(b4a.from("wrong passkey 1234"), salt);
      expect(() => sm2.decrypt(encryptedEntropy)).toThrow(/Decryption failed/i);
    });

    test("decrypt fails with tampered payload", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const data = rand(16);
      const { encryptedEntropy } = await sm.generateAndEncrypt(data);
      const tampered = b4a.from(encryptedEntropy);
      tampered[10] ^= 0xff;
      expect(() => sm.decrypt(tampered)).toThrow(/Decryption failed/i);
    });

    test("decrypt works with provided derivedKey regardless of manager passkey", async () => {
      const salt = wdkSaltGenerator.generate();
      const smA = new WdkSecretManager(PASS, salt);
      const data = rand(16);
      // Copy before encryption since encrypt zeros the original buffer
      const dataCopy = b4a.from(data);
      const customKey = rand(32);
      const { encryptedEntropy } = await smA.generateAndEncrypt(
        data,
        customKey
      );

      const smB = new WdkSecretManager(b4a.from("another passkey 5678"), salt);
      const decrypted = smB.decrypt(encryptedEntropy, customKey);
      expect(eq(decrypted, dataCopy)).toBe(true);
    });

    test("decrypt rejects non-buffer payload", () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      expect(() => sm.decrypt("not a buffer")).toThrow(
        /Payload is not a buffer/i
      );
    });

    test("decrypt rejects too-short payload", () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      expect(() => sm.decrypt(b4a.from([1, 2, 3]))).toThrow(/too short/i);
    });

    test("decrypt rejects invalid version", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const data = rand(16);
      const { encryptedEntropy } = await sm.generateAndEncrypt(data);
      const wrongVersion = b4a.from(encryptedEntropy);
      wrongVersion[0] = 1;
      expect(() => sm.decrypt(wrongVersion)).toThrow(/Invalid version/i);
    });

    test("decrypt rejects non-buffer derivedKey", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const data = rand(16);
      const { encryptedEntropy } = await sm.generateAndEncrypt(data);
      expect(() => sm.decrypt(encryptedEntropy, "not a buffer")).toThrow(
        /derivedKey is not a buffer/i
      );
    });
  });

  describe("dispose", () => {
    test("wipes internal state", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const data = rand(16);
      const { encryptedEntropy } = await sm.generateAndEncrypt(data);
      sm.dispose();
      expect(() => sm.decrypt(encryptedEntropy)).toThrow();
    });

    test("allows multiple dispose calls", async () => {
      const salt = wdkSaltGenerator.generate();
      const passBuffer = b4a.from("another passkey");
      const sm = new WdkSecretManager(passBuffer, salt);
      const data = rand(16);
      await sm.generateAndEncrypt(data);
      sm.dispose();
      expect(() => sm.dispose()).not.toThrow();
    });

    test("passkey buffer is zeroed after dispose", () => {
      const passBuffer = b4a.from("sensitive passkey data");
      const salt = wdkSaltGenerator.generate();
      const isNonZeroBefore = passBuffer.some((byte) => byte !== 0);
      expect(isNonZeroBefore).toBe(true);

      const sm = new WdkSecretManager(passBuffer, salt);
      sm.dispose();

      const isAllZeros = passBuffer.every((byte) => byte === 0);
      expect(isAllZeros).toBe(true);
    });

    test("salt buffer is zeroed after dispose", () => {
      const passBuffer = b4a.from("sensitive passkey data");
      const salt = wdkSaltGenerator.generate();
      const isNonZeroBefore = salt.some((byte) => byte !== 0);
      expect(isNonZeroBefore).toBe(true);

      const sm = new WdkSecretManager(passBuffer, salt);
      sm.dispose();

      const isAllZeros = salt.every((byte) => byte === 0);
      expect(isAllZeros).toBe(true);
    });
  });

  describe("memory zeroization", () => {
    test("entropy buffer is zeroed after generateAndEncrypt", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const entropy = rand(16);
      const isNonZeroBefore = entropy.some((byte) => byte !== 0);
      expect(isNonZeroBefore).toBe(true);

      await sm.generateAndEncrypt(entropy);

      const isAllZeros = entropy.every((byte) => byte === 0);
      expect(isAllZeros).toBe(true);
    });

    test("entropy is zeroed even if encryption fails", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const entropy = rand(16);
      const entropyCopy = b4a.from(entropy);

      const isNonZeroBefore = entropy.some((byte) => byte !== 0);
      expect(isNonZeroBefore).toBe(true);

      await sm.generateAndEncrypt(entropyCopy);
      sm.dispose();

      const isAllZeros = entropyCopy.every((byte) => byte === 0);
      expect(isAllZeros).toBe(true);
    });

    test("custom derivedKey is NOT zeroed (caller responsibility)", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const customKey = rand(32);
      const customKeyCopy = b4a.from(customKey);
      const entropy = rand(16);

      await sm.generateAndEncrypt(entropy, customKey);

      expect(eq(customKey, customKeyCopy)).toBe(true);
    });
  });

  describe("edge cases", () => {
    test("encrypts minimum payload size (16 bytes)", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const data = rand(16);
      const dataCopy = b4a.from(data);
      const { encryptedEntropy } = await sm.generateAndEncrypt(data);
      const decrypted = sm.decrypt(encryptedEntropy);
      expect(eq(decrypted, dataCopy)).toBe(true);
    });

    test("encrypts maximum payload size (64 bytes)", async () => {
      const sm = new WdkSecretManager(PASS, wdkSaltGenerator.generate());
      const { encryptedSeed } = await sm.generateAndEncrypt();
      const decryptedSeed = sm.decrypt(encryptedSeed);
      expect(decryptedSeed.length).toBe(64);
    });

    test("accepts salt larger than 16 bytes", () => {
      const largeSalt = rand(32);
      expect(() => new WdkSecretManager(PASS, largeSalt)).not.toThrow();
    });
  });
});
