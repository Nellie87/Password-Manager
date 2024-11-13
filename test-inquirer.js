const inquirer = require('inquirer');

(async () => {
    const { name } = await inquirer.prompt([
        { type: 'input', name: 'name', message: 'What is your name?' }
    ]);
    console.log(`Hello, ${name}!`);
})();
