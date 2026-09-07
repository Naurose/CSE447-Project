const cryptoService = require("../services/cryptoService");


const keys = cryptoService.generateEccKeyPair();

console.log("Keys:", keys);


const encrypted = cryptoService.eccEncrypt(
    "Secret",
    keys.publicKey
);

console.log("Encrypted:", encrypted);


const decrypted = cryptoService.eccDecrypt(
    encrypted,
    keys.privateKey
);

console.log("Decrypted:", decrypted);