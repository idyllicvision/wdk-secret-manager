import WdkSecretManager, {wdkSaltGenerator} from "../index.js";
import crypto from "crypto";

try {
    const wdkManager = new WdkSecretManager('1234', crypto.randomBytes(16));
    wdkManager.deriveKeyFromPassKey().then(res => {
        console.log(res.toString('hex'));
    })
    const salt = wdkSaltGenerator.generate()
    console.log('salt => ', salt)
    const phrase = wdkManager.generateRandomSeed()
    console.log('phrase =>', phrase);
    const encrypted = await wdkManager.encrypt(phrase)
    console.log('encrypted phrase =>', encrypted);
    const decrypted = await wdkManager.decrypt(encrypted);
    console.log('decrypted phrase =>', decrypted);
    if (phrase === decrypted) {
        console.log('Decryption works!!!!');
    } else {
        console.log('Decryption doesn\'t works');
    }
} catch (e) {
    console.error('Error ', e.message);
}

