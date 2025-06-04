import WdkSecretManager, {wdkSaltGenerator} from "../index.js";
import bip39 from 'bip39';

try {
    const salt = wdkSaltGenerator.generate()
    console.log('[salt] ', salt)
    const wdkManager = new WdkSecretManager('1234', salt);
    const entropy = wdkManager.generateRandomBuffer();
    const entropyCopy = Buffer.from(entropy);
    const seedBuffer = bip39.mnemonicToSeedSync(bip39.entropyToMnemonic(entropy))
    console.log('[entropy] ', entropy);
    const phrase = bip39.entropyToMnemonic(entropy);
    console.log('[phrase] ', phrase);
    const encrypted = wdkManager.generateAndEncrypt(entropy)
    console.log('[encrypted] ', encrypted);


    const decryptedSeed = wdkManager.decrypt(encrypted.encryptedSeed);
    console.log('[decryptedSeed buffer] ', decryptedSeed);

    const decryptedEntropy = wdkManager.decrypt(encrypted.encryptedEntropy);
    console.log('[decryptedEntropy buffer] ', decryptedEntropy);
    const decryptedPhrase = wdkManager.entropyToMnemonic(decryptedEntropy)
    console.log('[decryptedMnemonicPhrase] ', decryptedPhrase);
    if (decryptedSeed.equals(seedBuffer)) {
        console.log('Seed Decryption works!!!!');
    } else {
        console.log('Decryption doesn\'t works');
    }

    if (entropyCopy.equals(decryptedEntropy)) {
        console.log('Entropy Decryption works!!!!');
    } else {
        console.log('Decryption doesn\'t works');
    }
} catch (e) {
    console.log(e)
}

