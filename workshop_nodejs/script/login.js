async function handleLogin(event) {
    event.preventDefault(); // Prevent default form submission

    // Collect form data
    const rollNo = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Prepare data to send
    const loginData = {
        roll_no: rollNo,
        password: password
    };

    try {
        // Send POST request to the login endpoint
        const response = await fetch(' http://localhost:3000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(loginData),
        });

        const result = await response.json();

        if (response.ok) {
            // Store the token in local storage
            localStorage.setItem('token', result.token);
            console.log("Token stored:", result.token);

            // Redirect based on role_id
            if (result.role_id === 1) {
                window.location.href = './admin/admin.html'; // Admin dashboard
            } else if (result.role_id === 2) {
                window.location.href = './user/user.html'; // User dashboard
            }
        } else {
            // Handle errors
            alert(result.error);
        }
    } catch (error) {
        console.error('Error during login:', error);
        alert('An error occurred. Please try again later.');
    }
}