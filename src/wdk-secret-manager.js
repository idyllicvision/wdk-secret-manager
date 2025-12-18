'use strict'

import b4a from 'b4a'
import bip39 from 'bip39-mnemonic'
import sodium from 'sodium-native'
import { pbkdf2Sync } from 'crypto'

const VERSION = 2 // PBKDF2 payloads

const KDF_ALG = { PBKDF2_SHA256: 1 }

const SALT_BYTES = 16
const NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES
const MAC_BYTES = sodium.crypto_secretbox_MACBYTES
const KEY_BYTES = 32

const MIN_PLAINTEXT = 16
const MAX_PLAINTEXT = 64

const DEFAULT_PBKDF2_ITERATIONS = 100_000

// Header: [version(1), kdf_alg(1), iterations(u32le), reserved(u32le=0), salt(16), nonce(24)]
const HEADER_BYTES = 1 + 1 + 4 + 4 + SALT_BYTES + NONCE_BYTES

function writeU32LE (buf, off, val) {
  buf[off] = val & 0xff
  buf[off + 1] = (val >>> 8) & 0xff
  buf[off + 2] = (val >>> 16) & 0xff
  buf[off + 3] = (val >>> 24) & 0xff
}

function readU32LE (buf, off) {
  return (
    (buf[off] |
      (buf[off + 1] << 8) |
      (buf[off + 2] << 16) |
      (buf[off + 3] << 24)) >>>
    0
  )
}

export default class WdkSecretManager {
  #passkey
  #salt
  #iterations
  /**
   * Manages encryption and decryption of secrets using a passkey and salt.
   * Uses PBKDF2 for key derivation and libsodium for cryptographic operations.
   *
   * @param {Buffer|Uint8Array} passKeyBuf - The passkey buffer used for encryption (min 12 chars)
   * @param {Buffer} saltBuf - A 16-byte salt for key derivation
   * @param {{iterations?: number}} [kdfParams] - Optional params for key derivation
   */
  constructor (passKeyBuf, saltBuf, kdfParams = {}) {
    this._validatePassKey(passKeyBuf)
    this._validateSalt(saltBuf)

    this.#passkey = b4a.from(passKeyBuf)
    this.#salt = b4a.from(saltBuf)
    this.#iterations = kdfParams.iterations ?? DEFAULT_PBKDF2_ITERATIONS
  }

  /**
   * Generate a cryptographically secure random salt for key derivation.
   * The salt should be unique per passkey and stored alongside encrypted data.
   *
   * @returns {Buffer} A 16-byte random salt buffer
   */
  static generateSalt () {
    const out = b4a.alloc(SALT_BYTES)
    sodium.randombytes_buf(out)
    return out
  }

  /**
   * Generate 16-byte entropy, derive mnemonic+seed, and encrypt both.
   *
   * @param {Buffer|null} entropyBuf - If provided, must be 16 bytes.
   * @param {Buffer|null} masterKeyBuf - If provided, 32-byte key (skips PBKDF2).
   * @returns {Buffer} Encrypted entropy buffer
   */
  async generateAndEncrypt (entropyBuf = null, masterKeyBuf = null) {
    const entropy = entropyBuf
      ? this._validateEntropy(entropyBuf)
      : this.generateRandomBuffer()
    const encryptedEntropy = this.encrypt(entropy, masterKeyBuf)

    // Only zero entropy if we generated it internally
    if (!entropyBuf) {
      this._safeZero(entropy)
    }
    return encryptedEntropy
  }

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
  encrypt (data, masterKeyOpt = null) {
    this._validatePassKey(this.#passkey)
    this._validateSalt(this.#salt)
    if (!b4a.isBuffer(data)) throw new Error('Data must be a Buffer')
    const len = data.byteLength
    if (len < MIN_PLAINTEXT || len > MAX_PLAINTEXT) {
      throw new Error(
        `Data length must be between ${MIN_PLAINTEXT} and ${MAX_PLAINTEXT} bytes`
      )
    }

    const header = b4a.alloc(HEADER_BYTES)
    header[0] = VERSION
    header[1] = KDF_ALG.PBKDF2_SHA256

    writeU32LE(header, 2, this.#iterations >>> 0)
    writeU32LE(header, 6, 0)
    header.set(this.#salt, 10)

    const nonce = header.subarray(26, 26 + NONCE_BYTES)
    sodium.randombytes_buf(nonce)

    const key = masterKeyOpt
      ? this._validateKey32(masterKeyOpt)
      : this._deriveKeyPBKDF2(this.#passkey, this.#salt, this.#iterations)

    const plain = b4a.alloc(1 + len)
    plain[0] = len
    plain.set(data, 1)

    const cipher = b4a.alloc(plain.byteLength + MAC_BYTES)
    sodium.crypto_secretbox_easy(cipher, plain, nonce, key)

    const payload = b4a.concat([header, cipher])

    this._safeZero(plain)
    if (!masterKeyOpt) this._safeZero(key)

    return payload
  }

  /**
   * Decrypt a payload produced by this manager.
   *
   * @param {Buffer} payload - The encrypted payload to decrypt
   * @param {Buffer|null} masterKeyOpt - Optional 32-byte key to skip PBKDF2 derivation
   * @returns {Buffer} The decrypted plaintext data
   */
  decrypt (payload, masterKeyOpt = null) {
    this._validatePassKey(this.#passkey)
    this._validateSalt(this.#salt)
    if (!b4a.isBuffer(payload)) throw new Error('Payload must be a Buffer')
    if (payload.byteLength < HEADER_BYTES + 1 + MAC_BYTES) {
      throw new Error('Invalid payload: too short')
    }

    const header = payload.subarray(0, HEADER_BYTES)
    const version = header[0]
    if (version !== VERSION) throw new Error('Unsupported payload version')

    const alg = header[1]
    if (alg !== KDF_ALG.PBKDF2_SHA256) { throw new Error('Unsupported KDF algorithm') }

    const iterations = readU32LE(header, 2)
    const salt = header.subarray(10, 10 + SALT_BYTES)
    const nonce = header.subarray(26, 26 + NONCE_BYTES)

    const cipher = payload.subarray(HEADER_BYTES)
    const plain = b4a.alloc(cipher.byteLength - MAC_BYTES)

    const key = masterKeyOpt
      ? this._validateKey32(masterKeyOpt)
      : this._deriveKeyPBKDF2(this.#passkey, salt, iterations)

    const ok = sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key)
    if (!masterKeyOpt) this._safeZero(key)
    if (!ok) {
      this._safeZero(plain)
      throw new Error('Decryption failed')
    }

    const len = plain[0]
    if (len < MIN_PLAINTEXT || len > MAX_PLAINTEXT) {
      this._safeZero(plain)
      throw new Error('Invalid decrypted length')
    }
    if (plain.byteLength < 1 + len) {
      this._safeZero(plain)
      throw new Error('Invalid decrypted payload: inconsistent length')
    }

    const out = b4a.alloc(len)
    out.set(plain.subarray(1, 1 + len))
    this._safeZero(plain)
    return out
  }

  /**
   * Generates a cryptographically secure random buffer of 16 bytes
   *
   * @returns {Buffer} A 16-byte buffer filled with random bytes from sodium
   */
  generateRandomBuffer () {
    const out = b4a.alloc(16)
    sodium.randombytes_buf(out)
    return out
  }

  /**
   * Converts 16 bytes of entropy into a 12-word BIP39 mnemonic phrase
   *
   * @param {Buffer} entropy - A 16-byte buffer containing entropy
   * @returns {string} A 12-word mnemonic phrase
   */
  entropyToMnemonic (entropy) {
    this._validateEntropy(entropy)
    return bip39.entropyToMnemonic(entropy)
  }

  /**
   * Converts a 12-word BIP39 mnemonic phrase back into its original 16-byte entropy
   *
   * @param {string} mnemonic - A 12-word BIP39 mnemonic phrase
   * @returns {Buffer} The original 16-byte entropy buffer
   */
  mnemonicToEntropy (mnemonic) {
    if (typeof mnemonic !== 'string' || !mnemonic.trim()) {
      throw new Error('Mnemonic must be a non-empty string')
    }
    const hex = bip39.mnemonicToEntropy(mnemonic)
    const buf = b4a.from(hex, 'hex')
    if (buf.byteLength !== 16) {
      throw new Error(
        'This manager expects 12-word mnemonics (16-byte entropy)'
      )
    }
    return buf
  }

  /**
   * Securely disposes of sensitive internal state by zeroing out memory buffers
   * and nullifying references. After calling dispose(), the instance cannot be
   * used for further encryption/decryption operations.
   */
  dispose () {
    if (this.#salt) this._safeZero(this.#salt)
    if (this.#passkey) this._safeZero(this.#passkey)
    this.#salt = null
    this.#passkey = null
    this.#iterations = null
  }

  [Symbol.dispose] () {
    this.dispose()
  }

  /** @private */
  _deriveKeyPBKDF2 (passKeyBuf, saltBuf, iterations) {
    const key = pbkdf2Sync(
      b4a.from(passKeyBuf),
      b4a.from(saltBuf),
      iterations >>> 0,
      KEY_BYTES,
      'sha256'
    )
    return b4a.from(key)
  }

  /** @private */
  _validatePassKey (passKeyBuf) {
    if (!b4a.isBuffer(passKeyBuf) && !(passKeyBuf instanceof Uint8Array)) {
      throw new Error('Pass key must be a string or Buffer/Uint8Array')
    }
    if (passKeyBuf.byteLength < 12) { throw new Error('Binary pass key must be at least 12 bytes') }
  }

  /** @private */
  _validateSalt (saltBuf) {
    if (!b4a.isBuffer(saltBuf) && !(saltBuf instanceof Uint8Array)) {
      throw new Error('Salt must be a Buffer or Uint8Array')
    }
    if (saltBuf.byteLength !== SALT_BYTES) { throw new Error(`Salt must be ${SALT_BYTES} bytes`) }
  }

  /** @private */
  _validateEntropy (buf) {
    if (!b4a.isBuffer(buf)) throw new Error('Entropy must be a Buffer')
    if (buf.byteLength !== 16) { throw new Error('Entropy must be exactly 16 bytes for 12-word mnemonics') }
    return buf
  }

  /** @private */
  _validateKey32 (buf) {
    if (!b4a.isBuffer(buf) || buf.byteLength !== KEY_BYTES) {
      throw new Error('masterKey must be a 32-byte Buffer')
    }
    return buf
  }

  /** @private */
  _safeZero (buf) {
    if (buf && b4a.isBuffer(buf)) sodium.sodium_memzero(buf)
  }
}
