"use strict";

import b4a from "b4a";
import sodium from "sodium-native";
import { pbkdf2Sync } from "crypto";
import bip39 from "bip39-mnemonic";

import WdkSecretManager from "../../index.js";

const rand = (n) => {
  const out = b4a.alloc(n);
  sodium.randombytes_buf(out);
  return out;
};
const eq = (a, b) => b4a.compare(b4a.from(a), b4a.from(b)) === 0;

const PASS = b4a.from("correct horse battery staple", "utf-8");
const ITER = 100_000;

describe("WdkSecretManager (integration)", () => {
  test("end-to-end: entropy -> mnemonic -> seed -> encrypt/decrypt", async () => {
    const salt = WdkSecretManager.generateSalt();
    const sm = new WdkSecretManager(PASS, salt, { iterations: ITER });

    const entropy = sm.generateRandomBuffer();
    const mnemonic = sm.entropyToMnemonic(entropy);
    const seed = await bip39.mnemonicToSeed(mnemonic);

    const encEntropy = sm.encrypt(entropy);
    const encSeed = sm.encrypt(seed);

    const decEntropy = sm.decrypt(encEntropy);
    const decSeed = sm.decrypt(encSeed);

    expect(eq(decEntropy, entropy)).toBe(true);
    expect(eq(decSeed, seed)).toBe(true);
  });

  test("using masterKey derived externally works across instances", () => {
    const salt = WdkSecretManager.generateSalt();
    const smA = new WdkSecretManager(PASS, salt, { iterations: ITER });
    const data = rand(32);

    const masterKey = b4a.from(
      pbkdf2Sync(b4a.from(PASS), b4a.from(salt), ITER, 32, "sha256")
    );

    const payload = smA.encrypt(data, masterKey);
    const smB = new WdkSecretManager(
      b4a.from("different passkey here", "utf-8"),
      salt,
      { iterations: ITER }
    );
    const out = smB.decrypt(payload, masterKey);
    expect(eq(out, data)).toBe(true);
  });
});
