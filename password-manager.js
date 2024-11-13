const { deriveKey, getRandomSalt } = require('./lib');
const { encrypt, decrypt } = require('./encrypt');
const crypto = require('crypto');
const fs = require('fs');

class PasswordManager {
    constructor() {
        this.kvs = {}; // Key-value store for passwords
        this.hmacKey = null;
        this.aesKey = null;
        this.salt = null; // Store salt as hex string
    }

    async init(masterPassword) {
        const saltBuffer = getRandomSalt(16); // Generate 128-bit salt as a Buffer
        this.salt = saltBuffer.toString('hex'); // Store salt as a hex string
        const masterKey = await deriveKey(masterPassword, saltBuffer);
        this.hmacKey = crypto.createHmac('sha256', masterKey).update('hmac').digest();
        this.aesKey = crypto.createHmac('sha256', masterKey).update('aes').digest();
        return this.salt;
    }

    async dump() {
        const serializedData = JSON.stringify({ salt: this.salt, kvs: this.kvs });
        const hash = crypto.createHash('sha256').update(serializedData).digest('hex');
        return { data: serializedData, checksum: hash };
    }

    async load(password, representation, trustedDataCheck) {
        const loadedData = JSON.parse(representation);

        // Compute hash for rollback protection
        const hash = crypto.createHash('sha256').update(representation).digest('hex');
        if (trustedDataCheck && hash !== trustedDataCheck) {
            throw new Error('Data integrity check failed! Possible rollback attack detected.');
        }

        // Convert salt from hex string to Buffer for key derivation
        const saltBuffer = Buffer.from(loadedData.salt, 'hex');
        const masterKey = await deriveKey(password, saltBuffer);
        this.hmacKey = crypto.createHmac('sha256', masterKey).update('hmac').digest();
        this.aesKey = crypto.createHmac('sha256', masterKey).update('aes').digest();

        // Load the key-value store (kvs)
        this.kvs = loadedData.kvs;
    }

    hashDomain(domain) {
        const hmac = crypto.createHmac('sha256', this.hmacKey);
        return hmac.update(domain).digest('hex');
    }

    async set(domain, password) {
        const domainKey = this.hashDomain(domain);
        const { iv, encrypted, tag } = await encrypt(password, this.aesKey);
        this.kvs[domainKey] = { iv, encrypted, tag };
    }

    async get(domain) {
        const domainKey = this.hashDomain(domain);
        const entry = this.kvs[domainKey];
        if (!entry) return null;
        const { iv, encrypted, tag } = entry;
        return await decrypt(encrypted, this.aesKey, iv, tag);
    }

    async remove(domain) {
        const domainKey = this.hashDomain(domain);
        if (this.kvs[domainKey]) {
            delete this.kvs[domainKey];
            return true;
        }
        return false;
    }
}

// Example usage with file storage and retrieval
(async () => {
    console.log("Initializing Password Manager...");
    const passwordManager = new PasswordManager();
    const salt = await passwordManager.init('strong_master_password');
    console.log('Salt:', salt);

    console.log("Storing password...");
    await passwordManager.set('example.com', 'example_password');
    
    console.log("Retrieving password...");
    const password = await passwordManager.get('example.com');
    console.log('Retrieved password:', password);

    const { data, checksum } = await passwordManager.dump();
    console.log('Serialized data:', data);
    console.log('Checksum:', checksum);

    fs.writeFileSync('passwords.json', JSON.stringify({ data, checksum }));
    console.log('Passwords saved to passwords.json');

    console.log("Loading data...");
    const fileData = fs.readFileSync('passwords.json');
    const parsedData = JSON.parse(fileData);
    await passwordManager.load('strong_master_password', parsedData.data, parsedData.checksum);
    
    console.log("Storing another password...");
    await passwordManager.set('anotherdomain.com', 'another_password');

    console.log("Retrieving another password...");
    const anotherPassword = await passwordManager.get('anotherdomain.com');
    console.log('Retrieved another password:', anotherPassword);
})();

module.exports = PasswordManager;
