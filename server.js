const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();

/* =========================
   🔐 ENV CONFIG
========================= */
const JWT_SECRET = process.env.JWT_SECRET || "jwt_secret_change_me";
const API_SECRET = process.env.API_SECRET || "api_secret_change_me";

const SECRET_KEY = crypto
  .createHash('sha256')
  .update(process.env.SECRET_KEY)
  .digest();

const IV = Buffer.from(process.env.IV).slice(0, 16);

/* =========================
   🧠 SIMPLE REPLAY CACHE
========================= */
const usedNonces = new Map();

/* =========================
   🔒 ENCRYPTION
========================= */
function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, IV);
    return cipher.update(text, 'utf8', 'base64') + cipher.final('base64');
}

/* =========================
   🔑 JWT GENERATOR (optional use)
========================= */
function generateToken() {
    return jwt.sign(
        { app: "client" },
        JWT_SECRET,
        { expiresIn: "1h" }
    );
}

/* =========================
   🧱 VERIFY JWT
========================= */
function verifyJWT(req, res, next) {
    const token = req.headers['authorization']?.split(" ")[1];

    if (!token) {
        return res.status(403).json({ error: "Missing token" });
    }

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) {
        return res.status(403).json({ error: "Invalid or expired token" });
    }
}

/* =========================
   🧬 HMAC SIGNATURE CHECK
========================= */
function verifySignature(req, res, next) {
    const nonce = req.headers['x-nonce'];
    const signature = req.headers['x-signature'];

    if (!nonce || !signature) {
        return res.status(403).json({ error: "Missing signature" });
    }

    // replay protection
    if (usedNonces.has(nonce)) {
        return res.status(403).json({ error: "Replay detected" });
    }

    const expected = crypto
        .createHmac('sha256', API_SECRET)
        .update(nonce)
        .digest('hex');

    if (expected !== signature) {
        return res.status(403).json({ error: "Invalid signature" });
    }

    usedNonces.set(nonce, Date.now());

    // cleanup old nonces
    for (const [key, time] of usedNonces.entries()) {
        if (Date.now() - time > 5 * 60 * 1000) {
            usedNonces.delete(key);
        }
    }

    next();
}

/* =========================
   📦 CONFIG SOURCE
========================= */
const CONFIG_URL =
  "https://raw.githubusercontent.com/sajadMod1/Raven1/main/config.json";

/* =========================
   🚀 SECURE ROUTE
========================= */
app.get('/signchk', verifyJWT, verifySignature, async (req, res) => {
    try {
        const response = await fetch(CONFIG_URL);

        if (!response.ok) {
            throw new Error("GitHub fetch failed");
        }

        const data = await response.text();

        const encrypted = encrypt(data);

        res.json({
            data: encrypted,
            exp: Date.now()
        });

    } catch (err) {
        res.status(500).json({
            error: "Failed",
            debug: err.message
        });
    }
});

/* =========================
   🔑 TOKEN GENERATOR (for testing)
========================= */
app.get('/token', (req, res) => {
    res.json({
        token: generateToken()
    });
});

module.exports = app;