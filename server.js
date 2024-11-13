const express = require('express');
const bodyParser = require('body-parser');
const PasswordManager = require('./password-manager');

const app = express();
const PORT = 3004;

app.use(bodyParser.json());
const passwordManager = new PasswordManager();

// Initialize the password manager
passwordManager.init('your_master_password'); // Use a real prompt in production

app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Manager</title>
            <style>
                /* Global styling */
                body { font-family: Arial, sans-serif; background-color: #f0f2f5; color: #333; }
                h1 { text-align: center; color: #333; margin-bottom: 2rem; }
                
                /* Container styling */
                .container { max-width: 600px; margin: 2rem auto; padding: 2rem; background: #fff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); }
                .section { margin-bottom: 2rem; }
                
                /* Form and input styling */
                form { display: flex; flex-direction: column; }
                input[type="text"], input[type="password"], button { padding: 0.75rem; margin-top: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
                button { background-color: #28a745; color: white; font-weight: bold; cursor: pointer; transition: background-color 0.3s; }
                button:hover { background-color: #218838; }
                
                /* Message styling */
                p { margin-top: 0.5rem; font-size: 0.9rem; color: #555; }
                
                /* Headings */
                h2 { color: #555; font-size: 1.2rem; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Password Manager</h1>
                
                <!-- Form to set password -->
                <div class="section">
                    <h2>Store a Password</h2>
                    <form id="setPasswordForm">
                        <input type="text" id="setDomain" placeholder="Domain" required>
                        <input type="password" id="setPassword" placeholder="Password" required>
                        <button type="submit">Store Password</button>
                    </form>
                </div>
                
                <!-- Form to get password -->
                <div class="section">
                    <h2>Retrieve a Password</h2>
                    <form id="getPasswordForm">
                        <input type="text" id="getDomain" placeholder="Domain" required>
                        <button type="submit">Retrieve Password</button>
                        <p id="retrievedPassword"></p>
                    </form>
                </div>
                
                <!-- Form to delete password -->
                <div class="section">
                    <h2>Remove a Password</h2>
                    <form id="removePasswordForm">
                        <input type="text" id="removeDomain" placeholder="Domain" required>
                        <button type="submit">Remove Password</button>
                        <p id="removeStatus"></p>
                    </form>
                </div>
            </div>

            <script>
                // Store password
                document.getElementById('setPasswordForm').addEventListener('submit', async function(event) {
                    event.preventDefault();
                    const domain = document.getElementById('setDomain').value;
                    const password = document.getElementById('setPassword').value;
                    const response = await fetch('/setPassword', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain, password })
                    });
                    const result = await response.json();
                    alert(result.message);
                });

                // Retrieve password
                document.getElementById('getPasswordForm').addEventListener('submit', async function(event) {
                    event.preventDefault();
                    const domain = document.getElementById('getDomain').value;
                    const response = await fetch('/getPassword?domain=' + domain);
                    const result = await response.json();
                    document.getElementById('retrievedPassword').textContent = result.password 
                        ? "Password: " + result.password 
                        : "Password not found.";
                });

                // Remove password
                document.getElementById('removePasswordForm').addEventListener('submit', async function(event) {
                    event.preventDefault();
                    const domain = document.getElementById('removeDomain').value;
                    const response = await fetch('/removePassword?domain=' + domain, { method: 'DELETE' });
                    const result = await response.json();
                    document.getElementById('removeStatus').textContent = result.message;
                });
            </script>
        </body>
        </html>
    `);
});



app.post('/setPassword', async (req, res) => {
    const { domain, password } = req.body;
    await passwordManager.set(domain, password);
    res.json({ message: 'Password stored successfully!' });
});

app.get('/getPassword', async (req, res) => {
    const { domain } = req.query;
    const password = await passwordManager.get(domain);
    res.json({ password: password || null });
});

app.delete('/removePassword', async (req, res) => {
    const { domain } = req.query;
    const removed = await passwordManager.remove(domain);
    res.json({ message: removed ? 'Password removed successfully!' : 'Password not found.' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
