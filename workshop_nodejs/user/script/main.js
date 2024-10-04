async function decodeToken() {
    // Get the token from local storage
    const token = localStorage.getItem('token');

    // Print the token in the console
    console.log("Token from local storage:", token);

    // Check if token exists
    if (!token) {
        console.error("No token found in local storage.");
        window.location.href = './login.html'; // Redirect to login if no token
        return;
    }

    try {
        // Send POST request to decode the token
        const response = await fetch('http://localhost:3000/api/decodeToken', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token }),
        });

        const result = await response.json();

        if (response.ok) {
            // If the role_id is 1, continue
            if (result.role_id === 2) {
                console.log("User Role: user");
                console.log("User Name:", result.name); // Print the name in the console
                // Continue with admin functionality
                const nameElement = document.getElementById('name');
                if (nameElement) {
                    nameElement.textContent = ` ${result.name}`;
                }
            } else {
                // If the role_id is not 1, redirect to login
                window.location.href = '../login.html';
            }
        } else {
            console.error(result.error);
            // Handle error if token decoding fails
            window.location.href = '../login.html';
        }
    } catch (error) {
        console.error('Error during token decoding:', error);

    }
}

// Call decodeToken when the window is loaded
window.onload = decodeToken;