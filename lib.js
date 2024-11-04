const crypto = require('crypto');

// Generate a key using PBKDF2
function deriveKey(password, salt, keyLength = 32) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, 100000, keyLength, 'sha256', (err, derivedKey) => {
            if (err) reject(err);
            else resolve(derivedKey);
        });
    });
}

// Generate random salt
function getRandomSalt(length = 16) {
    return crypto.randomBytes(length);
}

module.exports = { deriveKey, getRandomSalt };
