const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// SQLite Database Setup
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT
        )`, (err) => {
            if (err) {
                console.error('Error creating users table:', err.message);
            } else {
                console.log('Users table ready');
            }
        });
    }
});

// Configuration
const GEMINI_API_KEY = 'AIzaSyD-oW66to7ctLKcf71iNp9t2-8q9JiO7jM'; // Your Gemini API key hardcoded
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-secure-secret-key'; // Keep as env var or replace
const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent';

// Middleware to Verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Routes
app.get('/', (req, res) => {
    res.send('Investment Playbook Backend Running');
});

app.post('/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
            [username, email, hashedPassword],
            function (err) {
                if (err) {
                    console.error('Registration error:', err.message);
                    return res.status(400).json({ error: 'Registration failed. Email or username may already be in use.' });
                }
                res.status(201).json({ message: 'User registered successfully' });
            }
        );
    } catch (error) {
        console.error('Error during registration:', error.message);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) {
            console.error('Database error during login:', err.message);
            return res.status(500).json({ error: 'Server error during login' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        try {
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }
            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ token, message: 'Login successful' });
        } catch (error) {
            console.error('Error during login:', error.message);
            res.status(500).json({ error: 'Server error during login' });
        }
    });
});

app.post('/playbook/generate', authenticateToken, async (req, res) => {
    const {
        age, monthlyAmount, goal, riskTolerance, timeHorizon,
        focusAreas, investmentStyle, currentHoldings, additionalGoals
    } = req.body;

    const prompt = `
        Generate a detailed investment playbook for a user with the following profile:
        - Age: ${age}
        - Monthly Investment Amount: $${monthlyAmount}
        - Financial Goal: ${goal}
        - Risk Tolerance: ${riskTolerance}/10
        - Time Horizon: ${timeHorizon} years
        - Focus Areas: ${focusAreas.join(', ')}
        - Investment Style: ${investmentStyle.join(', ') || 'Not specified'}
        - Current Holdings: ${currentHoldings || 'None'}
        - Additional Goals: ${additionalGoals || 'None'}

        Include sections in markdown with headings (##) and bullet points for:
        - Portfolio Allocation
        - Investment Recommendations
        - Expected Annual Return
        - Future Trends to Watch
        - Risks to Monitor
        - Tax-Efficient Strategies
        - Grow with Time
        - Educational Tip
    `;

    try {
        const response = await axios.post(`${GEMINI_API_URL}?key=${GEMINI_API_KEY}`, {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { temperature: 0.7 }
        });

        const playbookText = response.data.candidates[0].content.parts[0].text;
        res.json({ playbook: playbookText });
    } catch (error) {
        console.error('Error generating playbook:', error.message);
        res.status(500).json({ error: 'Failed to generate playbook' });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
