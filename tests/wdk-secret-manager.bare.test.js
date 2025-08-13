'use strict'

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-native'
import bareCrypto from 'bare-crypto'
import bip39 from 'bip39-mnemonic'

import WdkSecretManager from '../index.js'

const rand = (n) => { const out = b4a.alloc(n); sodium.randombytes_buf(out); return out }
const eq = (a, b) => b4a.compare(b4a.from(a), b4a.from(b)) === 0

const PASS = 'correct horse battery staple'
const ITER = 100_000
const NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES
const MAC_BYTES = sodium.crypto_secretbox_MACBYTES
const HEADER_BYTES = 1 + 1 + 4 + 4 + 16 + NONCE_BYTES

test('generateSalt returns a 16-byte Buffer and varies', t => {
  const a = WdkSecretManager.generateSalt()
  const b = WdkSecretManager.generateSalt()
  t.is(Buffer.isBuffer(a), true)
  t.is(a.length, 16)
  t.is(eq(a, b), false)
})

test('constructor accepts valid passkey and salt', t => {
  const salt = WdkSecretManager.generateSalt()
  t.execution(() => new WdkSecretManager(PASS, salt, { iterations: ITER }))
})

test('constructor rejects short passkey', t => {
  const salt = WdkSecretManager.generateSalt()
  t.exception(() => new WdkSecretManager('short', salt), /at least 12/i)
})

test('constructor rejects wrong salt size', t => {
  const bad = rand(12)
  t.exception(() => new WdkSecretManager(PASS, bad), /Salt must be 16 bytes/i)
})

test('generateRandomBuffer returns 16 random bytes', t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  const a = sm.generateRandomBuffer()
  const b = sm.generateRandomBuffer()
  t.is(a.length, 16)
  t.is(eq(a, b), false)
})

test('entropyToMnemonic returns a 12-word mnemonic', t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  const entropy = sm.generateRandomBuffer()
  const m = sm.entropyToMnemonic(entropy)
  t.is(typeof m, 'string')
  t.is(m.trim().split(/\s+/).length, 12)
})

test('entropyToMnemonic validates input', t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  t.exception(() => sm.entropyToMnemonic('nope'), /Buffer/i)
  t.exception(() => sm.entropyToMnemonic(rand(8)), /exactly 16 bytes/i)
})

test('mnemonicToEntropy round-trips with entropyToMnemonic', t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  const entropy = sm.generateRandomBuffer()
  const mnemonic = sm.entropyToMnemonic(entropy)
  const back = sm.mnemonicToEntropy(mnemonic)
  t.is(eq(entropy, back), true)
})

test('mnemonicToEntropy rejects invalid input', t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  t.exception(() => sm.mnemonicToEntropy(''), /non-empty/i)
  t.exception(() => sm.mnemonicToEntropy('foo bar baz'))
})

test('encrypt adds v2 header and encrypts 16–64B payloads', t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  const data = rand(32)
  const payload = sm.encrypt(data)
  t.is(Buffer.isBuffer(payload), true)
  t.is(payload[0], 2)
  t.is(payload[1], 1)
  t.ok(payload.length >= HEADER_BYTES + 1 + MAC_BYTES)
})

test('encrypt enforces length bounds', t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  t.exception(() => sm.encrypt(rand(8)), /between 16 and 64/i)
  t.exception(() => sm.encrypt(rand(80)), /between 16 and 64/i)
})

test('encrypt/decrypt with masterKey (skip PBKDF2)', t => {
  const salt = WdkSecretManager.generateSalt()
  const sm = new WdkSecretManager(PASS, salt, { iterations: ITER })
  const data = rand(32)
  const masterKey = b4a.from(
    bareCrypto.pbkdf2Sync(b4a.from(PASS), b4a.from(salt), ITER, 32, 'sha256')
  )
  const payload = sm.encrypt(data, masterKey)
  const out = sm.decrypt(payload, masterKey)
  t.is(eq(out, data), true)
})

test('encrypt → decrypt round-trip with passkey+salt', t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  const data = rand(48)
  const payload = sm.encrypt(data)
  const out = sm.decrypt(payload)
  t.is(eq(out, data), true)
})

test('decrypt fails with wrong passkey', t => {
  const salt = WdkSecretManager.generateSalt()
  const sm1 = new WdkSecretManager(PASS, salt, { iterations: ITER })
  const data = rand(32)
  const payload = sm1.encrypt(data)
  const sm2 = new WdkSecretManager('wrong passkey 1234', salt, { iterations: ITER })
  t.exception(() => sm2.decrypt(payload), /Decryption failed/i)
})

test('decrypt fails with tampered salt in header', t => {
  const salt = WdkSecretManager.generateSalt()
  const sm = new WdkSecretManager(PASS, salt, { iterations: ITER })
  const data = rand(32)

  const payload = sm.encrypt(data)

  const tampered = b4a.from(payload)
  tampered[10] ^= 0xff

  t.exception(() => sm.decrypt(tampered), /Decryption failed/i)
})

test('decrypt works with provided masterKey regardless of manager passkey', t => {
  const salt = WdkSecretManager.generateSalt()
  const smA = new WdkSecretManager(PASS, salt, { iterations: ITER })
  const data = rand(32)
  const payload = smA.encrypt(data)
  const masterKey = b4a.from(
    bareCrypto.pbkdf2Sync(b4a.from(PASS), b4a.from(salt), ITER, 32, 'sha256')
  )
  const smB = new WdkSecretManager('another passkey 5678', salt, { iterations: ITER })
  const out = smB.decrypt(payload, masterKey)
  t.is(eq(out, data), true)
})

test('generateAndEncrypt returns decryptable seed(64) + entropy(16)', async t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  const { encryptedSeed, encryptedEntropy } = await sm.generateAndEncrypt()
  const entropy = sm.decrypt(encryptedEntropy)
  const seed = sm.decrypt(encryptedSeed)
  t.is(entropy.length, 16)
  t.is(seed.length, 64)
})

test('generateAndEncrypt with known entropy matches BIP39 seed', async t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  const known = rand(16)
  const { encryptedSeed, encryptedEntropy } = await sm.generateAndEncrypt(known)
  const decEntropy = sm.decrypt(encryptedEntropy)
  t.is(eq(decEntropy, known), true)
  const m = sm.entropyToMnemonic(known)
  const expectedSeed = await bip39.mnemonicToSeed(m)
  const decSeed = sm.decrypt(encryptedSeed)
  t.is(eq(decSeed, expectedSeed), true)
})

test('dispose wipes internal state; decrypt after dispose throws', t => {
  const sm = new WdkSecretManager(PASS, WdkSecretManager.generateSalt(), { iterations: ITER })
  const data = rand(16)
  const payload = sm.encrypt(data)
  sm.dispose()
  t.exception(() => sm.decrypt(payload))
})
