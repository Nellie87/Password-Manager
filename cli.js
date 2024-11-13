const PasswordManager = require('./password-manager');
const inquirer = require('inquirer');

async function main() {
    const passwordManager = new PasswordManager();
    await passwordManager.init('your_master_password'); // Prompt for master password in a secure way.

    const actions = {
        setPassword: async () => {
            const { domain, password } = await inquirer.prompt([
                { type: 'input', name: 'domain', message: 'Enter domain name:' },
                { type: 'password', name: 'password', message: 'Enter password:' },
            ]);
            await passwordManager.set(domain, password);
            console.log('Password stored successfully!');
        },

        getPassword: async () => {
            const { domain } = await inquirer.prompt([
                { type: 'input', name: 'domain', message: 'Enter domain name:' }
            ]);
            const password = await passwordManager.get(domain);
            console.log(`Password for ${domain}: ${password ? password : 'Not found'}`);
        },

        removePassword: async () => {
            const { domain } = await inquirer.prompt([
                { type: 'input', name: 'domain', message: 'Enter domain name:' }
            ]);
            const removed = await passwordManager.remove(domain);
            console.log(removed ? 'Password removed successfully!' : 'Password not found.');
        },

        exit: () => process.exit(0),
    };

    while (true) {
        const { action } = await inquirer.prompt([
            { type: 'list', name: 'action', message: 'Select action:', choices: [
                { name: 'Set Password', value: 'setPassword' },
                { name: 'Get Password', value: 'getPassword' },
                { name: 'Remove Password', value: 'removePassword' },
                { name: 'Exit', value: 'exit' }
            ]}
        ]);
        await actions[action](); // Call the corresponding function
    }
}

main();
