"use strict";

import b4a from "b4a";
import sodium from "sodium-native";
import { pbkdf2Sync } from "crypto";
import bip39 from "bip39-mnemonic";

import WdkSecretManager from "../index.js";

const rand = (n) => {
  const out = b4a.alloc(n);
  sodium.randombytes_buf(out);
  return out;
};
const eq = (a, b) => b4a.compare(b4a.from(a), b4a.from(b)) === 0;

const PASS = b4a.from("correct horse battery staple", "utf-8");
const ITER = 100_000;
const NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES;
const MAC_BYTES = sodium.crypto_secretbox_MACBYTES;
const HEADER_BYTES = 1 + 1 + 4 + 4 + 16 + NONCE_BYTES;

describe("WdkSecretManager (unit)", () => {
  test("generateSalt returns a 16-byte Buffer and varies", () => {
    const a = WdkSecretManager.generateSalt();
    const b = WdkSecretManager.generateSalt();
    expect(Buffer.isBuffer(a)).toBe(true);
    expect(a.length).toBe(16);
    expect(eq(a, b)).toBe(false);
  });

  test("constructor accepts valid passkey and salt", () => {
    const salt = WdkSecretManager.generateSalt();
    expect(
      () => new WdkSecretManager(PASS, salt, { iterations: ITER })
    ).not.toThrow();
  });

  test("constructor rejects short passkey", () => {
    const salt = WdkSecretManager.generateSalt();
    expect(
      () => new WdkSecretManager(b4a.from("short", "utf-8"), salt)
    ).toThrow(/at least 12/i);
  });

  test("constructor rejects wrong salt size", () => {
    const bad = rand(12);
    expect(() => new WdkSecretManager(PASS, bad)).toThrow(
      /Salt must be 16 bytes/i
    );
  });

  test("generateRandomBuffer returns 16 random bytes", () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    const a = sm.generateRandomBuffer();
    const b = sm.generateRandomBuffer();
    expect(a.length).toBe(16);
    expect(eq(a, b)).toBe(false);
  });

  test("entropyToMnemonic returns a 12-word mnemonic", () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    const entropy = sm.generateRandomBuffer();
    const m = sm.entropyToMnemonic(entropy);
    expect(typeof m).toBe("string");
    expect(m.trim().split(/\s+/).length).toBe(12);
  });

  test("entropyToMnemonic validates input", () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    expect(() => sm.entropyToMnemonic("nope")).toThrow(/Buffer/i);
    expect(() => sm.entropyToMnemonic(rand(8))).toThrow(/exactly 16 bytes/i);
  });

  test("mnemonicToEntropy round-trips with entropyToMnemonic", () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    const entropy = sm.generateRandomBuffer();
    const mnemonic = sm.entropyToMnemonic(entropy);
    const back = sm.mnemonicToEntropy(mnemonic);
    expect(eq(entropy, back)).toBe(true);
  });

  test("mnemonicToEntropy rejects invalid input", () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    expect(() => sm.mnemonicToEntropy("")).toThrow(/non-empty/i);
    expect(() => sm.mnemonicToEntropy("foo bar baz")).toThrow();
  });

  test("encrypt adds v2 header and encrypts 16–64B payloads", () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    const data = rand(32);
    const payload = sm.encrypt(data);
    expect(Buffer.isBuffer(payload)).toBe(true);
    expect(payload[0]).toBe(2);
    expect(payload[1]).toBe(1);
    expect(payload.length).toBeGreaterThanOrEqual(HEADER_BYTES + 1 + MAC_BYTES);
  });

  test("encrypt enforces length bounds", () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    expect(() => sm.encrypt(rand(8))).toThrow(/between 16 and 64/i);
    expect(() => sm.encrypt(rand(80))).toThrow(/between 16 and 64/i);
  });

  test("encrypt/decrypt with masterKey (skip PBKDF2)", () => {
    const salt = WdkSecretManager.generateSalt();
    const sm = new WdkSecretManager(PASS, salt, { iterations: ITER });
    const data = rand(32);
    const masterKey = b4a.from(
      pbkdf2Sync(b4a.from(PASS), b4a.from(salt), ITER, 32, "sha256")
    );
    const payload = sm.encrypt(data, masterKey);
    const out = sm.decrypt(payload, masterKey);
    expect(eq(out, data)).toBe(true);
  });

  test("encrypt → decrypt round-trip with passkey+salt", () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    const data = rand(48);
    const payload = sm.encrypt(data);
    const out = sm.decrypt(payload);
    expect(eq(out, data)).toBe(true);
  });

  test("decrypt fails with wrong passkey", () => {
    const salt = WdkSecretManager.generateSalt();
    const sm1 = new WdkSecretManager(PASS, salt, { iterations: ITER });
    const data = rand(32);
    const payload = sm1.encrypt(data);
    const sm2 = new WdkSecretManager(
      b4a.from("wrong passkey 1234", "utf-8"),
      salt,
      {
        iterations: ITER,
      }
    );
    expect(() => sm2.decrypt(payload)).toThrow(/Decryption failed/i);
  });

  test("decrypt fails with tampered salt in header", () => {
    const salt = WdkSecretManager.generateSalt();
    const sm = new WdkSecretManager(PASS, salt, { iterations: ITER });
    const data = rand(32);
    const payload = sm.encrypt(data);
    const tampered = b4a.from(payload);
    tampered[10] ^= 0xff;
    expect(() => sm.decrypt(tampered)).toThrow(/Decryption failed/i);
  });

  test("decrypt works with provided masterKey regardless of manager passkey", () => {
    const salt = WdkSecretManager.generateSalt();
    const smA = new WdkSecretManager(PASS, salt, { iterations: ITER });
    const data = rand(32);
    const payload = smA.encrypt(data);
    const masterKey = b4a.from(
      pbkdf2Sync(b4a.from(PASS), b4a.from(salt), ITER, 32, "sha256")
    );
    const smB = new WdkSecretManager(
      b4a.from("another passkey 5678", "utf-8"),
      salt,
      {
        iterations: ITER,
      }
    );
    const out = smB.decrypt(payload, masterKey);
    expect(eq(out, data)).toBe(true);
  });

  test("generateAndEncrypt returns entropy(16)", async () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    const encryptedEntropy = await sm.generateAndEncrypt();
    const decryptedEntropy = sm.decrypt(encryptedEntropy);
    expect(decryptedEntropy.length).toBe(16);
    expect(Buffer.isBuffer(encryptedEntropy)).toBe(true);
    expect(encryptedEntropy.length).toBeGreaterThan(16);
  });

  test("generateAndEncrypt with known entropy matches BIP39 seed", async () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    const entropy = rand(16);
    const encryptedEntropy = await sm.generateAndEncrypt(entropy);
    const decEntropy = sm.decrypt(encryptedEntropy);
    expect(eq(decEntropy, entropy)).toBe(true);
    const m = sm.entropyToMnemonic(entropy);
    const expectedSeed = await bip39.mnemonicToSeed(m);
    const mDec = sm.entropyToMnemonic(decEntropy);
    const seedDec = await bip39.mnemonicToSeed(mDec);
    expect(eq(seedDec, expectedSeed)).toBe(true);
  });

  test("dispose wipes internal state; decrypt after dispose throws", () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
      iterations: ITER,
    });
    const data = rand(16);
    const payload = sm.encrypt(data);
    sm.dispose();
    expect(() => sm.decrypt(payload)).toThrow();
  });

  test("decrypt rejects too-short payloads and unsupported header fields", () => {
    const salt = WdkSecretManager.generateSalt();
    const sm = new WdkSecretManager(PASS, salt, { iterations: ITER });
    expect(() => sm.decrypt(b4a.from([1, 2, 3]))).toThrow(/too short/i);

    const data = rand(16);
    const payload = sm.encrypt(data);
    const wrongVersion = b4a.from(payload);
    wrongVersion[0] = 1;
    expect(() => sm.decrypt(wrongVersion)).toThrow(
      /Unsupported payload version/i
    );

    const wrongAlg = b4a.from(payload);
    wrongAlg[1] = 2;
    expect(() => sm.decrypt(wrongAlg)).toThrow(/Unsupported KDF algorithm/i);
  });

  describe("memory zeroization", () => {
    test("encrypt does not modify input data buffer", () => {
      const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
        iterations: ITER,
      });
      const originalData = rand(32);
      const dataCopy = b4a.from(originalData);
      sm.encrypt(dataCopy);
      // Input buffer should remain unchanged (internal copy is zeroed)
      expect(eq(dataCopy, originalData)).toBe(true);
    });

    test("decrypt returns a new buffer, original payload unchanged", () => {
      const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
        iterations: ITER,
      });
      const data = rand(32);
      const payload = sm.encrypt(data);
      const payloadCopy = b4a.from(payload);
      const decrypted = sm.decrypt(payload);
      // Payload should remain unchanged
      expect(eq(payload, payloadCopy)).toBe(true);
      // Decrypted should match original
      expect(eq(decrypted, data)).toBe(true);
    });

    test("generateAndEncrypt with provided entropy does not zero caller's buffer", async () => {
      const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
        iterations: ITER,
      });
      const entropy = rand(16);
      const entropyCopy = b4a.from(entropy);
      await sm.generateAndEncrypt(entropy);
      // Caller's entropy buffer should remain unchanged
      expect(eq(entropy, entropyCopy)).toBe(true);
    });

    test("generateAndEncrypt with masterKey does not modify masterKey", async () => {
      const salt = WdkSecretManager.generateSalt();
      const sm = new WdkSecretManager(PASS, salt, { iterations: ITER });
      const masterKey = b4a.from(
        pbkdf2Sync(b4a.from(PASS), b4a.from(salt), ITER, 32, "sha256")
      );
      const masterKeyCopy = b4a.from(masterKey);
      await sm.generateAndEncrypt(null, masterKey);
      // Master key should remain unchanged
      expect(eq(masterKey, masterKeyCopy)).toBe(true);
    });

    test("dispose prevents further operations", () => {
      const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
        iterations: ITER,
      });
      const data = rand(32);
      const payload = sm.encrypt(data);
      sm.dispose();
      // After dispose, operations that use internal state should fail
      expect(() => sm.encrypt(data)).toThrow();
      expect(() => sm.decrypt(payload)).toThrow();
      // generateRandomBuffer doesn't use internal state, so it still works
      expect(() => sm.generateRandomBuffer()).not.toThrow();
    });

    test("dispose can be called multiple times safely", () => {
      const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), {
        iterations: ITER,
      });
      sm.dispose();
      // Multiple dispose calls should not throw
      expect(() => sm.dispose()).not.toThrow();
      expect(() => sm.dispose()).not.toThrow();
    });
  });
});
