const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const { encrypt, decrypt } = require('./encryption');

const app = express();
const PORT = 5000;
const SECRET_KEY = "my_jwt_secret_key"; // Use env var in production

app.use(express.json());
app.use(cors());

// --- Database Setup ---
const db = new sqlite3.Database(':memory:'); // Using in-memory DB for MVP
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, name TEXT, aadhaar_enc TEXT)");
});

// --- Middleware: Verify JWT ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).json({ error: "Access Denied" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        next();
    });
};

// --- Routes ---

// 1. Register
app.post('/register', async (req, res) => {
    const { email, password, name, aadhaar } = req.body;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Encrypt Aadhaar (AES-256)
    const encryptedAadhaar = encrypt(aadhaar);

    const stmt = db.prepare("INSERT INTO users (email, password, name, aadhaar_enc) VALUES (?, ?, ?, ?)");
    stmt.run(email, hashedPassword, name, encryptedAadhaar, function(err) {
        if (err) return res.status(400).json({ error: "User already exists" });
        res.json({ message: "User registered successfully" });
    });
    stmt.finalize();
});

// 2. Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "User not found" });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Invalid password" });

        // Generate Token
        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// 3. Get Profile (Protected & Decrypted)
app.get('/profile', verifyToken, (req, res) => {
    db.get("SELECT name, email, aadhaar_enc FROM users WHERE id = ?", [req.user.id], (err, row) => {
        if (err) return res.sendStatus(500);

        // Decrypt Aadhaar before sending to frontend
        const decryptedAadhaar = decrypt(row.aadhaar_enc);
        
        res.json({
            name: row.name,
            email: row.email,
            aadhaar: decryptedAadhaar // Sending plain text ONLY to authenticated user
        });
    });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));