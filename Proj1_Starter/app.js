"use strict";

// Import the Keychain class from password-manager.js
const { Keychain } = require('./password-manager');

// Initialize the Keychain with a master password
async function initKeychain() {
  try {
    // Prompt the user for their master password (you can replace this with secure input in a real app)
    const password = prompt("Enter your master password:");  // You can replace this with actual UI input

    // Create a new Keychain instance based on the password
    const keychain = await Keychain.init(password);
    console.log("Keychain initialized successfully!");

    // Example: Add a password entry
    await keychain.set("exampleService", "examplePassword123");

    // Retrieve the password for the service
    const servicePassword = await keychain.get("exampleService");
    console.log("Password for 'exampleService':", servicePassword);

    // Example: Remove a password entry
    const removeResult = await keychain.remove("exampleService");
    console.log("Password entry for 'exampleService' removed:", removeResult);

    // Save the keychain to a file or print the serialized data with checksum
    const [jsonData, checksum] = await keychain.dump();
    console.log("Keychain data (obfuscated):", jsonData);
    console.log("Checksum of keychain data:", checksum);
    
  } catch (error) {
    console.error("Error initializing the keychain:", error);
  }
}

// Call the function to initialize the keychain and perform operations
initKeychain();
