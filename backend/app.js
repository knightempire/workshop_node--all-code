const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const session = require('express-session');
//const cookieParser = require('cookie-parser');
//const bodyParser = require('body-parser');



const app = express();



const port = 3000 || null;


app.use(cors());
app.use(express.json());



require('dotenv').config();
const {
    DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_DATABASE,
    //DB_WAIT_FOR_CONNECTIONS,
    //DB_CONNECTION_LIMIT,
    //DB_QUEUE_LIMIT,
    DB_PORT,
    SESSION_SECRET,
    JWT_SECRET,
    JWT_EXPIRY,
} = process.env;

const dbConfig = {
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE,
    //waitForConnections: DB_WAIT_FOR_CONNECTIONS === 'true', // Convert string to boolean
    //connectionLimit: parseInt(DB_CONNECTION_LIMIT, 10),
    //queueLimit: parseInt(DB_QUEUE_LIMIT, 10),
};



// Create a MySQL pool
const pool = mysql.createPool(dbConfig);




// Session middleware configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));


// the function you've written is an immediately invoked async function expression (IIFE). Here’s a breakdown of its components:
(async() => {
    try {
        // Attempt to get a connection from the pool
        const connection = await pool.getConnection();

        // If connection successful, log a success message
        console.log('Database connected successfully');

        // Release the connection back to the pool
        connection.release();
    } catch (error) {
        // Log an error message if connection fails
        console.error('Error connecting to the database:', error);
        process.exit(1); // Terminate the application process
    }
})();




//function to create token
const createtoken = (req, res, { roll_no, role_id }) => {
    // Sign the token with roll_no and role_id
    const token = jwt.sign({ roll_no, role_id }, JWT_SECRET, {
        expiresIn: JWT_EXPIRY,
    });

    // Store the token in the session if needed
    req.session.jwtToken = token;

    // Return the token
    return token;
};




const authenticateToken = (req, res, next) => {
    try {
        // Check if Authorization header exists
        if (!req.headers.authorization) {
            return res.redirect('#'); // Redirect to login page
        }

        // Retrieve token from request headers and split it
        const token = req.headers.authorization.split(' ')[1];
        // console.log("Token:", token); // Print token value

        // Verify token
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) {
                console.error('Authentication error:', err.message);
                // Token is invalid or expired, send 401 Unauthorized response to client
                return res.status(401).json({ error: 'Unauthorized' });
            } else {
                req.user = decoded; // Set decoded information in request object
                // console.log('Decoded user:', decoded);
                next(); // Proceed to next middleware
            }
        });
    } catch (err) {
        console.error('Error in authentication middleware:', err.message);
        res.status(500).send('Internal Server Error');
    }
};



app.post('/api/decodeToken', async(req, res) => {
    console.log('API decode requested');

    try {
        const { token } = req.body;

        // Verify and decode the token
        const decodedToken = jwt.verify(token, JWT_SECRET);
        const { roll_no, role_id } = decodedToken; // Extract roll_no and role_id

        // Check if roll_no is defined
        if (!roll_no) {
            return res.status(400).json({ error: 'roll_no not found in token' });
        }

        // Query to retrieve the user's name based on roll_no in a single line
        const [rows] = await pool.execute(`SELECT name FROM profile WHERE roll_no = ?`, [roll_no]);

        // Check if user exists and send response
        if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

        // Send user name back to the client, defaulting to 'User' if name is null
        res.status(200).json({ roll_no, name: rows[0].name || 'unkown User', role_id }); // Include role_id in the response
    } catch (error) {
        console.error('Error decoding token:', error.message);
        res.status(400).json({ error: 'Failed to decode token' });
    }
});



app.post('/api/login', async(req, res) => {
    const { roll_no, password } = req.body;

    try {
        console.log('API login requested');

        // Check if the roll number exists
        const [user] = await pool.execute('SELECT * FROM login WHERE LOWER(roll_no) = LOWER(?)', [roll_no]);

        if (user.length === 0) {
            console.log('User not found');
            return res.status(401).json({ error: 'Invalid roll number or password' });
        }

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user[0].password);

        if (!isMatch) {
            console.log('Password does not match');
            return res.status(401).json({ error: 'Invalid roll number or password' });
        }

        // Retrieve the role_id
        const role_id = user[0].role_id;



        // Create token with role_id
        const token = createtoken(req, res, { roll_no, role_id });
        console.log("Token:", token);

        // Send response with role message and token
        res.json({ success: true, role_id, token });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.post('/api/register', async(req, res) => {
    const { roll_no, password, role_name, name, dob } = req.body;

    try {
        console.log('API registration requested');

        // Check if the role_name exists and get the role_id
        const [role] = await pool.execute('SELECT role_id FROM roles WHERE role_name = ?', [role_name]);

        if (role.length === 0) {
            console.log('Role not found');
            return res.status(400).json({ error: 'Role not found' });
        }

        const role_id = role[0].role_id; // Corrected to use role_id

        // Check if the roll number already exists (case-insensitive check)
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE LOWER(roll_no) = LOWER(?)', [roll_no]);

        if (existingUser.length > 0) {
            console.log('User with the same roll number already exists');
            return res.status(400).json({ error: 'User with the same roll number already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user into the login table
        await pool.execute('INSERT INTO login (roll_no, password, role_id) VALUES (?, ?, ?)', [roll_no, hashedPassword, role_id]);

        // Insert user details into the profile table
        await pool.execute('INSERT INTO profile (name, roll_no, dob) VALUES (?, ?, ?)', [name, roll_no, dob]);

        // Send response
        res.json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/test', (req, res) => {
    res.status(200).json({ message: "Welcome Aagneya" });
});



//port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}).on('error', (err) => {
    console.error('Server start error:', err);
})