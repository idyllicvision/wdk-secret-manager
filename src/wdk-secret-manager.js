import b4a from 'b4a'
import bip39 from 'bip39-mnemonic'
import crypto from 'crypto'
import sodium from 'sodium-universal'

/**
 *
 * @type {{generate: (function(): Buffer)}}
 */
export const wdkSaltGenerator = {
  generate: () => {
    const resultBuffer = b4a.alloc(16)
    sodium.randombytes_buf(resultBuffer)
    return resultBuffer
  }
}

export class WdkSecretManager {
  /**
   *
   * @param {Buffer | ArrayBuffer} passKey - The user's password as a Buffer.
   */
  #passkey = null
  /**
   * @param {Buffer} salt - A unique, random 16-byte salt. This should be
   * generated once per user and stored alongside the
   * encrypted data. It is not a secret.
   */
  #salt = null

  /**
   *
   * @param {Buffer | ArrayBuffer | Uint8Array} passKey - The user's password as a Buffer.
   * @param {Buffer} salt - A unique, random 16-byte salt. This should be
   * generated once per user and stored alongside the
   * encrypted data. It is not a secret.
   */
  constructor (passKey, salt = null) {
    this.#passKeyValidator(passKey)
    this.#saltValidator(salt)
    this.#passkey = passKey
    this.#salt = salt
  }

  /**
   * Derives a strong, 32-byte (256-bit) cryptographic key from a user's password
   * Salt for preventing rainbow table attacks.
   * using the PBKDF2 algorithm.
   * @return {Buffer}
   */
  #deriveKeyFromPassKey () {
    this.#passKeyValidator(this.#passkey)
    this.#saltValidator(this.#salt) // Ensure this.#salt is a 16-byte Buffer

    // Key size in bytes (256-bit = 32 bytes)
    const keySizeInBytes = 32

    // The number of iterations
    const iterations = 100000

    // The digest algorithm
    const digest = 'sha256'

    const key = crypto.pbkdf2Sync(
      this.#passkey,
      this.#salt,
      iterations,
      keySizeInBytes,
      digest
    )

    return key
  }

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
  async generateAndEncrypt (payload = null, derivedKey = null) {
    if (payload && !b4a.isBuffer(payload)) {
      throw new Error('Payload is not a buffer!')
    }
    const entropy = payload || this.generateRandomBuffer()

    let entropyZeroed = false
    let seedZeroed = false
    let seedBuffer = null

    const key = derivedKey || this.#deriveKeyFromPassKey()

    try {
      seedBuffer = await bip39.mnemonicToSeed(bip39.entropyToMnemonic(entropy))

      const encryptedSeed = this.#encrypt(
        seedBuffer,
        seedBuffer.byteLength,
        key
      )
      seedZeroed = true

      const encryptedEntropy = this.#encrypt(entropy, entropy.byteLength, key)
      entropyZeroed = true

      return { encryptedSeed, encryptedEntropy }
    } finally {
      if (!derivedKey && b4a.isBuffer(key)) {
        sodium.sodium_memzero(key)
      }

      if (!entropyZeroed && b4a.isBuffer(entropy)) {
        sodium.sodium_memzero(entropy)
      }

      if (!seedZeroed && b4a.isBuffer(seedBuffer)) {
        sodium.sodium_memzero(seedBuffer)
      }
    }
  }

  /**
   * Encrypt entropy or seed buffer
   * @param {Buffer} buffer - The buffer to encrypt (will be zeroed after encryption).
   * @param {number} buffLength - The length of the buffer.
   * @param {Buffer} [derivedKey=null] - Optional ArrayBuffer(32) bytes cryptographic key.
   * @return {Buffer} A Buffer containing the encrypted payload.
   */
  #encrypt (buffer, buffLength, derivedKey = null) {
    if (!b4a.isBuffer(buffer)) throw new Error('Payload is not a buffer!')
    if (!buffLength) throw new Error('Incorrect buffer length')
    if (derivedKey && !b4a.isBuffer(derivedKey)) {
      throw new Error('derivedKey is not a buffer!')
    }

    if (buffer.byteLength > 64 || buffer.byteLength < 16) {
      throw new Error('Buffer size must be between 16 and 64')
    }

    const nonce = b4a.alloc(sodium.crypto_secretbox_NONCEBYTES)
    sodium.randombytes_buf(nonce)

    try {
      const payload = b4a.alloc(
        1 +
          sodium.crypto_secretbox_NONCEBYTES +
          1 +
          buffLength +
          sodium.crypto_secretbox_MACBYTES
      )
      payload[0] = 0 // version
      payload.set(nonce, 1)

      const cipher = payload.subarray(1 + nonce.byteLength)
      const plain = cipher.subarray(
        0,
        cipher.byteLength - sodium.crypto_secretbox_MACBYTES
      )
      plain[0] = buffer.byteLength
      plain.set(buffer, 1)

      // encrypt in-place
      sodium.crypto_secretbox_easy(cipher, plain, nonce, derivedKey)

      return payload
    } finally {
      sodium.sodium_memzero(buffer)
      sodium.sodium_memzero(nonce)
    }
  }

  /**
   * Decrypts a payload to retrieve a BIP39 mnemonic phrase.
   * @param {Buffer} payload - The encrypted payload.
   * @param {Buffer} [derivedKey=null] - Optional ArrayBuffer(32) bytes cryptographic key.
   * @return {Buffer} The decrypted mnemonic phrase.
   */
  decrypt (payload, derivedKey = null) {
    if (!b4a.isBuffer(payload)) {
      throw new Error('Payload is not a buffer!')
    }
    if (derivedKey && !b4a.isBuffer(derivedKey)) {
      throw new Error('derivedKey is not a buffer!')
    }
    const minLength =
      1 +
      sodium.crypto_secretbox_NONCEBYTES +
      1 +
      sodium.crypto_secretbox_MACBYTES
    if (payload.byteLength < minLength) {
      throw new Error('Invalid payload: too short')
    }

    if (payload[0] !== 0) {
      throw new Error('Invalid version')
    }

    // Derive key if not provided
    const key = derivedKey || this.#deriveKeyFromPassKey()
    const shouldZeroKey = !derivedKey

    const nonce = payload.subarray(1, 1 + sodium.crypto_secretbox_NONCEBYTES)
    const cipher = payload.subarray(1 + nonce.byteLength)

    const plain = b4a.alloc(
      cipher.byteLength - sodium.crypto_secretbox_MACBYTES
    )

    try {
      if (!sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key)) {
        throw new Error('Decryption failed')
      }
      const bytes = plain[0]
      if (bytes > 64) {
        throw new Error('Invalid decrypted payload')
      }

      if (plain.byteLength < 1 + bytes) {
        throw new Error('Invalid decrypted payload: inconsistent length')
      }
      const resultBuffer = b4a.alloc(bytes)
      resultBuffer.set(plain.subarray(1, 1 + bytes))
      return resultBuffer
    } finally {
      // Always zero the plaintext buffer
      sodium.sodium_memzero(plain)
      // Zero the derived key if we created it
      if (shouldZeroKey && b4a.isBuffer(key)) {
        sodium.sodium_memzero(key)
      }
    }
  }

  /**
   * Generates a random 128 bits buffer
   * @return {Buffer} Which can be converted BIP39 mnemonic phrase (12 words).
   */
  generateRandomBuffer () {
    const resultBuffer = b4a.alloc(16)
    sodium.randombytes_buf(resultBuffer)
    return resultBuffer
  }

  /**
   *
   * @param {Buffer} entropy - 128 bits entropy buffer.
   * @return {string} - BIP39 mnemonic phrase (12 words by default for 128 bits).
   */
  entropyToMnemonic (entropy) {
    if (!b4a.isBuffer(entropy)) throw new Error('Payload is not a buffer!')
    return bip39.entropyToMnemonic(entropy)
  }

  /**
   *
   * @param {string} seedPhrase
   * @return {Buffer}
   */
  mnemonicToEntropy (seedPhrase) {
    const entropy = bip39.mnemonicToEntropy(seedPhrase)
    return b4a.from(entropy, 'hex')
  }

  #passKeyValidator (passKey) {
    if (!passKey) {
      throw new Error('Pass key must not be empty!')
    }
    if (!b4a.isBuffer(passKey)) {
      throw new Error('Pass key must be a Buffer!')
    }
  }

  #saltValidator (salt) {
    if (!salt) {
      throw new Error('Salt must not be empty!')
    }
    if (!b4a.isBuffer(salt)) {
      throw new Error('Salt must be a buffer!')
    }
    if (salt.byteLength < 16) {
      throw new Error('Salt must be at least 16 bytes!')
    }
  }

  /**
   * Erase the salt and passkey from memory.
   */
  dispose () {
    if (this.#salt) sodium.sodium_memzero(this.#salt)
    if (this.#passkey) sodium.sodium_memzero(this.#passkey)
    this.#passkey = null
    this.#salt = null
  }

  /**
   * Clean up resources.
   */
  [Symbol.dispose] () {
    this.dispose()
  }
}
