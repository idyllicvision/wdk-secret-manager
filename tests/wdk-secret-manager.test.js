'use strict'

import b4a from 'b4a'
import sodium from 'sodium-native'
import { pbkdf2Sync } from 'crypto'
import bip39 from 'bip39-mnemonic'

import WdkSecretManager from '../index.js'

const rand = (n) => { const out = b4a.alloc(n); sodium.randombytes_buf(out); return out }
const eq = (a, b) => b4a.compare(b4a.from(a), b4a.from(b)) === 0

const PASS = 'correct horse battery staple'
const ITER = 100_000
const NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES
const MAC_BYTES = sodium.crypto_secretbox_MACBYTES
const HEADER_BYTES = 1 + 1 + 4 + 4 + 16 + NONCE_BYTES

describe('WdkSecretManager (unit)', () => {
  test('generateSalt returns a 16-byte Buffer and varies', () => {
    const a = WdkSecretManager.generateSalt()
    const b = WdkSecretManager.generateSalt()
    expect(Buffer.isBuffer(a)).toBe(true)
    expect(a.length).toBe(16)
    expect(eq(a, b)).toBe(false)
  })

  test('constructor accepts valid passkey and salt', () => {
    const salt = WdkSecretManager.generateSalt()
    expect(() => new WdkSecretManager(PASS, salt, { iterations: ITER })).not.toThrow()
  })

  test('constructor rejects short passkey', () => {
    const salt = WdkSecretManager.generateSalt()
    expect(() => new WdkSecretManager('short', salt)).toThrow(/at least 12/i)
  })

  test('constructor rejects wrong salt size', () => {
    const bad = rand(12)
    expect(() => new WdkSecretManager(PASS, bad)).toThrow(/Salt must be 16 bytes/i)
  })

  test('generateRandomBuffer returns 16 random bytes', () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    const a = sm.generateRandomBuffer()
    const b = sm.generateRandomBuffer()
    expect(a.length).toBe(16)
    expect(eq(a, b)).toBe(false)
  })

  test('entropyToMnemonic returns a 12-word mnemonic', () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    const entropy = sm.generateRandomBuffer()
    const m = sm.entropyToMnemonic(entropy)
    expect(typeof m).toBe('string')
    expect(m.trim().split(/\s+/).length).toBe(12)
  })

  test('entropyToMnemonic validates input', () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    expect(() => sm.entropyToMnemonic('nope')).toThrow(/Buffer/i)
    expect(() => sm.entropyToMnemonic(rand(8))).toThrow(/exactly 16 bytes/i)
  })

  test('mnemonicToEntropy round-trips with entropyToMnemonic', () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    const entropy = sm.generateRandomBuffer()
    const mnemonic = sm.entropyToMnemonic(entropy)
    const back = sm.mnemonicToEntropy(mnemonic)
    expect(eq(entropy, back)).toBe(true)
  })

  test('mnemonicToEntropy rejects invalid input', () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    expect(() => sm.mnemonicToEntropy('')).toThrow(/non-empty/i)
    expect(() => sm.mnemonicToEntropy('foo bar baz')).toThrow()
  })

  test('encrypt adds v2 header and encrypts 16–64B payloads', () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    const data = rand(32)
    const payload = sm.encrypt(data)
    expect(Buffer.isBuffer(payload)).toBe(true)
    expect(payload[0]).toBe(2)
    expect(payload[1]).toBe(1)
    expect(payload.length).toBeGreaterThanOrEqual(HEADER_BYTES + 1 + MAC_BYTES)
  })

  test('encrypt enforces length bounds', () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    expect(() => sm.encrypt(rand(8))).toThrow(/between 16 and 64/i)
    expect(() => sm.encrypt(rand(80))).toThrow(/between 16 and 64/i)
  })

  test('encrypt/decrypt with masterKey (skip PBKDF2)', () => {
    const salt = WdkSecretManager.generateSalt()
    const sm = new WdkSecretManager(PASS, salt, { iterations: ITER })
    const data = rand(32)
    const masterKey = b4a.from(
      pbkdf2Sync(b4a.from(PASS), b4a.from(salt), ITER, 32, 'sha256')
    )
    const payload = sm.encrypt(data, masterKey)
    const out = sm.decrypt(payload, masterKey)
    expect(eq(out, data)).toBe(true)
  })

  test('encrypt → decrypt round-trip with passkey+salt', () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    const data = rand(48)
    const payload = sm.encrypt(data)
    const out = sm.decrypt(payload)
    expect(eq(out, data)).toBe(true)
  })

  test('decrypt fails with wrong passkey', () => {
    const salt = WdkSecretManager.generateSalt()
    const sm1 = new WdkSecretManager(PASS, salt, { iterations: ITER })
    const data = rand(32)
    const payload = sm1.encrypt(data)
    const sm2 = new WdkSecretManager('wrong passkey 1234', salt, { iterations: ITER })
    expect(() => sm2.decrypt(payload)).toThrow(/Decryption failed/i)
  })

  test('decrypt fails with tampered salt in header', () => {
    const salt = WdkSecretManager.generateSalt()
    const sm = new WdkSecretManager(PASS, salt, { iterations: ITER })
    const data = rand(32)
    const payload = sm.encrypt(data)
    const tampered = b4a.from(payload)
    tampered[10] ^= 0xff
    expect(() => sm.decrypt(tampered)).toThrow(/Decryption failed/i)
  })

  test('decrypt works with provided masterKey regardless of manager passkey', () => {
    const salt = WdkSecretManager.generateSalt()
    const smA = new WdkSecretManager(PASS, salt, { iterations: ITER })
    const data = rand(32)
    const payload = smA.encrypt(data)
    const masterKey = b4a.from(
      pbkdf2Sync(b4a.from(PASS), b4a.from(salt), ITER, 32, 'sha256')
    )
    const smB = new WdkSecretManager('another passkey 5678', salt, { iterations: ITER })
    const out = smB.decrypt(payload, masterKey)
    expect(eq(out, data)).toBe(true)
  })

  test('generateAndEncrypt returns decryptable seed(64) + entropy(16)', async () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    const { encryptedSeed, encryptedEntropy } = await sm.generateAndEncrypt()
    const entropy = sm.decrypt(encryptedEntropy)
    const seed = sm.decrypt(encryptedSeed)
    expect(entropy.length).toBe(16)
    expect(seed.length).toBe(64)
  })

  test('generateAndEncrypt with known entropy matches BIP39 seed', async () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    const known = rand(16)
    const { encryptedSeed, encryptedEntropy } = await sm.generateAndEncrypt(known)
    const decEntropy = sm.decrypt(encryptedEntropy)
    expect(eq(decEntropy, known)).toBe(true)
    const m = sm.entropyToMnemonic(known)
    const expectedSeed = await bip39.mnemonicToSeed(m)
    const decSeed = sm.decrypt(encryptedSeed)
    expect(eq(decSeed, expectedSeed)).toBe(true)
  })

  test('dispose wipes internal state; decrypt after dispose throws', () => {
    const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
    const data = rand(16)
    const payload = sm.encrypt(data)
    sm.dispose()
    expect(() => sm.decrypt(payload)).toThrow()
  })

  test('decrypt rejects too-short payloads and unsupported header fields', () => {
    const salt = WdkSecretManager.generateSalt()
    const sm = new WdkSecretManager(PASS, salt, { iterations: ITER })
    expect(() => sm.decrypt(b4a.from([1, 2, 3]))).toThrow(/too short/i)

    const data = rand(16)
    const payload = sm.encrypt(data)
    const wrongVersion = b4a.from(payload)
    wrongVersion[0] = 1
    expect(() => sm.decrypt(wrongVersion)).toThrow(/Unsupported payload version/i)

    const wrongAlg = b4a.from(payload)
    wrongAlg[1] = 2
    expect(() => sm.decrypt(wrongAlg)).toThrow(/Unsupported KDF algorithm/i)
  })
})


