"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;
const HASH_ALGO = "SHA-256";
const KEY_LENGTH = 256; // 256-bit encryption

/********* Implementation ********/
class Keychain {
  constructor() {
    this.data = {};
    this.secrets = {};
  }

  /**
   * Creates an empty keychain with the given password.
   */
  static async init(password) {
    const keychain = new Keychain();
    keychain.secrets.masterKey = await keychain.#deriveKey(password);
    return keychain;
  }

  /**
   * Loads the keychain state from a serialized representation (repr).
   */
  static async load(password, repr, trustedDataCheck) {
    const keychain = new Keychain();
    keychain.secrets.masterKey = await keychain.#deriveKey(password);

    const parsedData = JSON.parse(repr);

    // Verify checksum if provided
    if (trustedDataCheck) {
      const calculatedCheck = await keychain.#calculateChecksum(repr);
      if (trustedDataCheck !== calculatedCheck) {
        throw new Error("Checksum mismatch: data integrity verification failed.");
      }
    }

    keychain.data = parsedData;
    return keychain;
  }

  /**
   * Returns a JSON serialization of the keychain with a checksum.
   */
  async dump() {
    const jsonData = JSON.stringify(this.data);
    const checksum = await this.#calculateChecksum(jsonData);
    return [jsonData, checksum];
  }

  /**
   * Fetches the data (as a string) corresponding to the given domain.
   */
  async get(name) {
    const encryptedData = this.data[name];
    if (!encryptedData) return null;

    const iv = decodeBuffer(encryptedData.iv);
    const ciphertext = decodeBuffer(encryptedData.ciphertext);

    const decryptedBuffer = await subtle.decrypt(
      { name: "AES-GCM", iv },
      this.secrets.masterKey,
      ciphertext
    );

    return bufferToString(decryptedBuffer);
  }

  /**
   * Inserts or updates the domain and associated data.
   */
  async set(name, value) {
    const iv = getRandomBytes(12); // 12-byte IV for AES-GCM
    const encryptedBuffer = await subtle.encrypt(
      { name: "AES-GCM", iv },
      this.secrets.masterKey,
      stringToBuffer(value)
    );

    this.data[name] = {
      iv: encodeBuffer(iv),
      ciphertext: encodeBuffer(new Uint8Array(encryptedBuffer))
    };
  }

  /**
   * Removes the record with the specified name from the keychain.
   */
  async remove(name) {
    if (this.data[name]) {
      delete this.data[name];
      return true;
    }
    return false;
  }

  /********* Helper Methods *********/

  /**
   * Derives a key from the password using PBKDF2 with a consistent salt.
   */
  async #deriveKey(password) {
    const passwordBuffer = stringToBuffer(password);
    const baseKey = await subtle.importKey("raw", passwordBuffer, { name: "PBKDF2" }, false, ["deriveKey"]);

    // Using a fixed salt derived from the password hash for consistency
    const salt = await subtle.digest(HASH_ALGO, passwordBuffer);
    return subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: new Uint8Array(salt),
        iterations: PBKDF2_ITERATIONS,
        hash: HASH_ALGO
      },
      baseKey,
      { name: "AES-GCM", length: KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Calculates SHA-256 checksum over the input data.
   */
  async #calculateChecksum(data) {
    const dataBuffer = stringToBuffer(data);
    const hashBuffer = await subtle.digest(HASH_ALGO, dataBuffer);
    return bufferToString(hashBuffer);
  }
}

module.exports = { Keychain };
