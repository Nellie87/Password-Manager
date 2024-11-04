const { deriveKey, getRandomSalt } = require('./lib'); // Keep your imports consistent
const { encrypt, decrypt } = require('./encrypt'); // Make sure this is only once

const crypto = require('crypto');

class PasswordManager {
    constructor() {
        this.kvs = {}; // Key-value store for passwords
        this.hmacKey = null; // HMAC key for hashing domains
        this.aesKey = null; // AES key for encrypting passwords
    }

    async init(masterPassword) {
        const salt = getRandomSalt(); // Use your existing function
        const masterKey = await deriveKey(masterPassword, salt);
        this.hmacKey = crypto.createHmac('sha256', masterKey).update('hmac').digest();
        this.aesKey = crypto.createHmac('sha256', masterKey).update('aes').digest();
        return salt.toString('hex');
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

    serialize() {
        const json = JSON.stringify(this.kvs);
        const hash = crypto.createHash('sha256').update(json).digest('hex');
        return { data: json, checksum: hash };
    }

    load(data, checksum) {
        const hash = crypto.createHash('sha256').update(data).digest('hex');
        if (hash !== checksum) throw new Error('Data integrity check failed!');
        this.kvs = JSON.parse(data);
    }
}

const fs = require('fs'); // Import the fs module

(async () => {
    console.log("Initializing Password Manager..."); // Debugging statement
    const passwordManager = new PasswordManager();
    const salt = await passwordManager.init('strong_master_password');
    console.log('Salt:', salt);

    console.log("Storing password..."); // Debugging statement
    await passwordManager.set('example.com', 'example_password');
    
    console.log("Retrieving password..."); // Debugging statement
    const password = await passwordManager.get('example.com');
    console.log('Retrieved password:', password);

    const { data, checksum } = passwordManager.serialize();
    console.log('Serialized data:', data);
    console.log('Checksum:', checksum);

    // Save serialized data to a file
    fs.writeFileSync('passwords.json', JSON.stringify({ data, checksum }));
    console.log('Passwords saved to passwords.json');

    console.log("Loading data..."); // Debugging statement
    const fileData = fs.readFileSync('passwords.json');
    const parsedData = JSON.parse(fileData);
    passwordManager.load(parsedData.data, parsedData.checksum);
    
    console.log("Storing another password..."); // Debugging statement
    await passwordManager.set('anotherdomain.com', 'another_password');

    console.log("Retrieving another password..."); // Debugging statement
    const anotherPassword = await passwordManager.get('anotherdomain.com');
    console.log('Retrieved another password:', anotherPassword);
})();
