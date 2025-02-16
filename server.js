const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "rinkucherry123",
    database: "mydatabase"
});

db.connect(err => {
    if (err) console.error("Database connection failed: " + err.message);
    else console.log("Connected to MySQL database.");
});

// Secret key for JWT
const SECRET_KEY = "mF8x!@#&9sLk3D2pQz%vTgB7^XaYwN";

// User Signup
app.post("/signup", (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
        [name, email, hashedPassword], 
        (err, result) => {
            if (err) return res.status(500).json({ error: "Signup failed!" });
            res.json({ message: "User registered successfully!" });
        }
    );
});

// User Login
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
        if (err || result.length === 0) return res.status(400).json({ error: "User not found!" });

        const user = result[0];
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(400).json({ error: "Invalid credentials!" });
        }

        // Generate JWT Token
        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ message: "Login successful!", token });
    });
});

// Protected Route Example (Middleware)
const authenticateToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) return res.status(403).json({ error: "Access denied!" });

    jwt.verify(token.split(" ")[1], SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token!" });
        req.user = user;
        next();
    });
};

app.get("/profile", authenticateToken, (req, res) => {
    res.json({ message: "Welcome to your profile!", user: req.user });
});

// Start Server
app.listen(5000, () => {
    console.log("Server running on port 5000.");
});