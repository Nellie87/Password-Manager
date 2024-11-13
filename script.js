async function showSetPasswordForm() {
    document.getElementById('form-container').innerHTML = `
        <h3>Set Password</h3>
        <input type="text" id="domain" placeholder="Enter Domain" required>
        <input type="password" id="password" placeholder="Enter Password" required>
        <button onclick="setPassword()">Submit</button>
    `;
}

async function showGetPasswordForm() {
    document.getElementById('form-container').innerHTML = `
        <h3>Get Password</h3>
        <input type="text" id="domain" placeholder="Enter Domain" required>
        <button onclick="getPassword()">Submit</button>
    `;
}

async function showRemovePasswordForm() {
    document.getElementById('form-container').innerHTML = `
        <h3>Remove Password</h3>
        <input type="text" id="domain" placeholder="Enter Domain" required>
        <button onclick="removePassword()">Submit</button>
    `;
}

async function setPassword() {
    const domain = document.getElementById('domain').value;
    const password = document.getElementById('password').value;

    const response = await fetch('/setPassword', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, password })
    });

    const result = await response.json();
    document.getElementById('output').innerText = result.message;
}

async function getPassword() {
    const domain = document.getElementById('domain').value;

    const response = await fetch(`/getPassword?domain=${domain}`, {
        method: 'GET'
    });

    const result = await response.json();
    document.getElementById('output').innerText = result.password ? `Password: ${result.password}` : 'Password not found';
}

async function removePassword() {
    const domain = document.getElementById('domain').value;

    const response = await fetch(`/removePassword?domain=${domain}`, {
        method: 'DELETE'
    });

    const result = await response.json();
    document.getElementById('output').innerText = result.message;
}
