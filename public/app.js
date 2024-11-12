// Function to load the password manager
async function loadManager() {
    const masterPassword = document.getElementById('masterPassword').value;
    const response = await fetch('/load', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ masterPassword })
    });
    const result = await response.json();

    if (result.message) {
        displayOutput(result.message);
        document.getElementById('masterPasswordSection').style.display = 'none';
        document.getElementById('actionSection').style.display = 'block'; // Show action selection
    } else {
        displayOutput(result.error);
    }
}

// Function to handle action selection from the dropdown
function selectAction() {
    const selectedAction = document.getElementById('actionDropdown').value;

    // Hide all action sections initially
    const actionSections = document.querySelectorAll('.action');
    actionSections.forEach(section => section.style.display = 'none');

    // Show the selected action's section
    if (selectedAction) {
        document.getElementById(`${selectedAction}Section`).style.display = 'block';
    }
}

// Function to add a new password
async function addPassword() {
    const service = document.getElementById('service').value;
    const password = document.getElementById('password').value;
    const response = await fetch('/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service, password })
    });
    const result = await response.json();
    displayOutput(result.message || result.error);
}

// Function to retrieve a password
async function getPassword() {
    const service = document.getElementById('getService').value;
    const response = await fetch('/get', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service })
    });
    const result = await response.json();
    displayOutput(result.password || result.error);
}

// Function to delete a password
async function deletePassword() {
    const service = document.getElementById('deleteService').value;
    const response = await fetch('/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service })
    });
    const result = await response.json();
    displayOutput(result.message || result.error);
}

// Function to display output messages
function displayOutput(message) {
    document.getElementById('output').innerText = message;
}
