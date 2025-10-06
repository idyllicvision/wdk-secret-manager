'use strict'

import test from 'brittle'
import b4a from 'b4a'
import bareCrypto from 'bare-crypto'
import bip39 from 'bip39-mnemonic'

import WdkSecretManager from '../bare.js'

const eq = (a, b) => b4a.compare(b4a.from(a), b4a.from(b)) === 0

const PASS = 'correct horse battery staple'
const ITER = 100_000

test('bare runtime: masterKey flow and round-trip', async t => {
  const salt = WdkSecretManager.generateSalt()
  const sm = new WdkSecretManager(PASS, salt, { iterations: ITER })
  const entropy = sm.generateRandomBuffer()
  const mnemonic = sm.entropyToMnemonic(entropy)
  const seed = await bip39.mnemonicToSeed(mnemonic)

  const masterKey = b4a.from(
    bareCrypto.pbkdf2Sync(b4a.from(PASS), b4a.from(salt), ITER, 32, 'sha256')
  )

  const encEntropy = sm.encrypt(entropy, masterKey)
  const encSeed = sm.encrypt(seed, masterKey)
  const decEntropy = sm.decrypt(encEntropy, masterKey)
  const decSeed = sm.decrypt(encSeed, masterKey)

  t.is(eq(decEntropy, entropy), true)
  t.is(eq(decSeed, seed), true)
})
