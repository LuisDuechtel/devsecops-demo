/**
 * Beispiel JavaScript-Code mit verschiedenen Sicherheitslücken
 * für DevSecOps Pipeline Testing
 */

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const child_process = require('child_process');

const app = express();
app.use(express.json());

// VULNERABILITY 1: Hardcoded Secrets
const API_SECRET = 'super-secret-key-12345';  // Hardcoded Secret
const DB_PASSWORD = 'root123';  // Database Password im Code
const JWT_SECRET = 'jwt-secret-key';  // JWT Secret

// VULNERABILITY 2: Insecure Database Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: DB_PASSWORD,  // Passwort im Klartext
    database: 'vulnerable_db',
    multipleStatements: true  // Ermöglicht SQL Injection!
});

// VULNERABILITY 3: SQL Injection
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    
    // Unsichere Query-Konstruktion
    const query = `SELECT * FROM users WHERE id = ${userId}`;  // SQL Injection!
    
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err.message);  // Information Disclosure
            return;
        }
        res.json(results);
    });
});

// VULNERABILITY 4: NoSQL Injection (MongoDB)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Unsichere MongoDB Query
    db.collection('users').findOne({
        username: username,
        password: password  // NoSQL Injection wenn Objekt übergeben wird!
    }, (err, user) => {
        if (user) {
            res.json({ success: true, user });
        } else {
            res.json({ success: false });
        }
    });
});

// VULNERABILITY 5: Command Injection
app.get('/ping', (req, res) => {
    const host = req.query.host;
    
    // Unsichere Kommando-Ausführung
    child_process.exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {  // Command Injection!
        res.send(stdout);
    });
});

// VULNERABILITY 6: Path Traversal
app.get('/file', (req, res) => {
    const fileName = req.query.name;
    
    // Unsicherer Dateizugriff
    const filePath = path.join(__dirname, 'uploads', fileName);  // Path Traversal möglich!
    
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send(err.message);
            return;
        }
        res.send(data);
    });
});

// VULNERABILITY 7: Eval Injection
app.post('/calculate', (req, res) => {
    const expression = req.body.expression;
    
    // Unsichere Verwendung von eval
    try {
        const result = eval(expression);  // Code Injection!
        res.json({ result });
    } catch (e) {
        res.status(400).send(e.message);
    }
});

// VULNERABILITY 8: Weak Cryptography
function hashPassword(password) {
    // MD5 ist unsicher für Passwörter
    return crypto.createHash('md5').update(password).digest('hex');  // Weak Hash!
}

// VULNERABILITY 9: Insecure Random Token
function generateToken() {
    // Math.random() ist nicht kryptographisch sicher
    return Math.random().toString(36).substring(7);  // Predictable Random!
}

// VULNERABILITY 10: XSS Vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    
    // Unsichere HTML-Generierung
    const html = `
        <html>
            <body>
                <h1>Search Results for: ${query}</h1>
            </body>
        </html>
    `;  // XSS Vulnerability!
    
    res.send(html);
});

// VULNERABILITY 11: Insecure Direct Object Reference
app.get('/profile/:userId', (req, res) => {
    const userId = req.params.userId;
    
    // Keine Autorisierungsprüfung
    const userProfile = getUserProfile(userId);  // IDOR Vulnerability!
    res.json(userProfile);
});

// VULNERABILITY 12: Server-Side Request Forgery (SSRF)
const axios = require('axios');

app.post('/fetch', async (req, res) => {
    const url = req.body.url;
    
    // Unsichere URL-Anfrage
    try {
        const response = await axios.get(url);  // SSRF möglich!
        res.send(response.data);
    } catch (e) {
        res.status(500).send(e.message);
    }
});

// VULNERABILITY 13: Regex DoS
app.post('/validate-email', (req, res) => {
    const email = req.body.email;
    
    // Unsichere Regex (ReDoS anfällig)
    const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    
    if (regex.test(email)) {
        res.json({ valid: true });
    } else {
        res.json({ valid: false });
    }
});

// VULNERABILITY 14: Missing Rate Limiting
app.post('/reset-password', (req, res) => {
    const email = req.body.email;
    
    // Keine Rate-Limiting - Brute Force möglich!
    sendPasswordResetEmail(email);
    res.json({ success: true });
});

// VULNERABILITY 15: Prototype Pollution
app.post('/merge', (req, res) => {
    const obj1 = {};
    const obj2 = req.body;
    
    // Unsichere Objekt-Zusammenführung
    for (let key in obj2) {
        obj1[key] = obj2[key];  // Prototype Pollution möglich!
    }
    
    res.json(obj1);
});

// VULNERABILITY 16: Unvalidated Redirects
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    
    // Unsichere Weiterleitung
    res.redirect(url);  // Open Redirect!
});

// VULNERABILITY 17: Insufficient Logging
app.post('/admin/delete-user/:id', (req, res) => {
    const userId = req.params.id;
    
    // Keine Logging von kritischen Aktionen
    deleteUser(userId);  // Keine Audit-Logs!
    res.json({ success: true });
});

// VULNERABILITY 18: Debug Mode in Production
app.listen(3000, () => {
    console.log('Server running on port 3000');
    console.log('Debug mode:', process.env.NODE_ENV !== 'production');  // Debug Info!
});

// VULNERABILITY 19: Insecure CORS Configuration
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');  // Zu permissiv!
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// VULNERABILITY 20: Missing Security Headers
// Keine Security Headers wie CSP, X-Frame-Options, etc.

module.exports = app;