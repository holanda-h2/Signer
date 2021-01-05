const crypto = require('crypto');

const AESCripto = {
    ENCRYPTION_KEY: 'ABCDEFGHIJKLMNOP', // Must be 256 bits (32 characters)
    IV_LENGTH: 16, // For AES, this is always 16
    IV: "0000000000000000"
}

AESCripto.encrypt = function(text) {
    //  let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(AESCripto.ENCRYPTION_KEY), AESCripto.IV);
    let encrypted = cipher.update(text);

    encrypted = Buffer.concat([encrypted, cipher.final()]);
    let iv = Buffer.from(AESCripto.IV);

    return encrypted.toString('base64') + ':' + iv.toString('base64');
}

AESCripto.decrypt = function(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts[1], 'base64');
    let encryptedText = Buffer.from(textParts[0], 'base64'); //text
    let decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(AESCripto.ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
    //  decrypted = Buffer.concat([decrypted, decipher.final()]);
    decrypted += decipher.final('utf8');
    return decrypted.toString();
}

module.exports.AESCripto = AESCripto;