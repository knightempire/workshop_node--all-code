async function handleRegister(event) {
    event.preventDefault(); // Prevent the default form submission

    // Collect form data
    const fullname = document.getElementById('fullname').value;
    const rollNo = document.getElementById('roll_no').value;
    const dob = document.getElementById('dob').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const role = document.getElementById('role').value;

    // Basic validation
    if (password !== confirmPassword) {
        alert("Passwords do not match!");
        return;
    }

    // Prepare data to send
    const userData = {
        name: fullname,
        roll_no: rollNo,
        dob: dob,
        password: password,
        role_name: role
    };

    try {
        // Send POST request to the registration endpoint
        const response = await fetch('http://localhost:3000/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData),
        });

        const result = await response.json();

        if (response.ok) {
            // Successful registration
            alert(result.message);
            // Optionally redirect to another page
            window.location.href = './login.html';
        } else {
            // Handle errors
            alert(result.error);
        }
    } catch (error) {
        console.error('Error during registration:', error);
        alert('An error occurred. Please try again later.');
    }
}