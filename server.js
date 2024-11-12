const express = require('express');
const PasswordManager = require('./password-manager'); // Import PasswordManager class
const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static('public')); // Serve static files from the "public" directory

// Define API routes for password manager operations
const manager = new PasswordManager();

app.post('/init', async (req, res) => {
    const { masterPassword } = req.body;
    try {
        await manager.init(masterPassword);
        res.send({ message: 'Master password has been set.' });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

app.post('/load', async (req, res) => {
    const { masterPassword } = req.body;
    try {
        await manager.load(masterPassword);
        res.send({ message: 'Password manager loaded successfully.' });
    } catch (error) {
        res.status(401).send({ error: error.message });
    }
});

app.post('/add', (req, res) => {
    const { service, password } = req.body;
    try {
        manager.addPassword(service, password);
        res.send({ message: `Password added for ${service}.` });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

app.post('/get', (req, res) => {
    const { service } = req.body;
    try {
        const password = manager.getPassword(service);
        res.send({ service, password });
    } catch (error) {
        res.status(404).send({ error: error.message });
    }
});

app.post('/delete', (req, res) => {
    const { service } = req.body;
    try {
        manager.deletePassword(service);
        res.send({ message: `Password deleted for ${service}.` });
    } catch (error) {
        res.status(404).send({ error: error.message });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
