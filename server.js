const express = require('express');
const bodyParser = require('body-parser');
const sql = require("msnodesqlv8");
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing
const app = express();
const path = require('path');

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database configuration
const sqlConfig = {
    connectionString: 'Driver={ODBC Driver 17 for SQL Server};Server=MSI\\SQLEXPRESS;Database=MyDatabase;Trusted_Connection=yes;'
};

// Test the connection
sql.open(sqlConfig.connectionString, (err, db) => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Connected to MyDatabase.');

        // Signup Route
        app.post('/signup', async (req, res) => {
            const { name, email, password } = req.body;

            try {
                // Check if email already exists
                const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
                db.query(checkEmailQuery, [email], async (error, results) => {
                    if (error) {
                        console.error('Database query error:', error);
                        return res.status(500).json({ message: 'Error checking email', error });
                    }
                    if (results.length > 0) {
                        return res.status(400).json({ message: 'Email already exists' });
                    }

                    // Hash the password
                    const saltRounds = 10;
                    const hashedPassword = await bcrypt.hash(password, saltRounds);

                    // Insert new user
                    const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
                    db.query(query, [name, email, hashedPassword], (error, results) => {
                        if (error) {
                            console.error('Database query error:', error);
                            return res.status(500).json({ message: 'Error signing up', error });
                        }
                        // Successful signup
                        res.status(201).json({ message: 'User  registered successfully', userId: results.insertId });
                    });
                });
            } catch (error) {
                console.error('Error hashing password:', error);
                return res.status(500).json({ message: 'Error signing up', error });
            }
        });

        // Signin Route
        app.post('/signin', (req, res) => {
            const { email, password } = req.body;

            const query = 'SELECT * FROM users WHERE email = ?';

            db.query(query, [email], async (error, results) => {
                if (error || results.length === 0) {
                    return res.status(401).json({ message: 'Invalid email or password' });
                }

                // Compare the entered password with the hashed password
                const user = results[0];
                const match = await bcrypt.compare(password, user.password);
                if (!match) {
                    return res.status(401).json({ message: 'Invalid email or password' });
                }

                res.status(200).json({ message: 'Signed in successfully', user });
            });
        });

        // Routes
        app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'index.html'));
        });

        // Start server
        const PORT = 3000;
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    }
});