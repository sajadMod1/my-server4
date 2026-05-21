const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();

/* =========================
   🔐 ENV VALIDATION
========================= */
const REQUIRED_ENVS = [
    'SECRET_KEY',
    'IV',
    'JWT_SECRET',
    'API_SECRET'
];

for (const envName of REQUIRED_ENVS) {
    if (!process.env[envName]) {
        throw new Error(`Missing ENV variable: ${envName}`);
    }
}

/* =========================
   🔐 CONFIG
========================= */
const JWT_SECRET = process.env.JWT_SECRET;
const API_SECRET = process.env.API_SECRET;

/* =========================
   🔒 AES KEYS
========================= */
const SECRET_KEY = crypto
    .createHash('sha256')
    .update(process.env.SECRET_KEY)
    .digest(); // 32 bytes

const IV = Buffer
    .from(process.env.IV)
    .subarray(0, 16);

/* =========================
   🧠 REPLAY CACHE
========================= */
const usedNonces = new Map();
const NONCE_EXPIRE_MS = 5 * 60 * 1000;

/* =========================
   🧹 CLEANUP TASK
========================= */
setInterval(() => {
    const now = Date.now();

    for (const [nonce, time] of usedNonces.entries()) {
        if (now - time > NONCE_EXPIRE_MS) {
            usedNonces.delete(nonce);
        }
    }
}, 60 * 1000);

/* =========================
   🔒 ENCRYPT
========================= */
function encrypt(text) {
    const cipher = crypto.createCipheriv(
        'aes-256-cbc',
        SECRET_KEY,
        IV
    );

    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    return encrypted;
}

/* =========================
   🔑 JWT GENERATOR
========================= */
function generateToken() {
    return jwt.sign(
        {
            app: "client",
            type: "access"
        },
        JWT_SECRET,
        {
            expiresIn: '1h'
        }
    );
}

/* =========================
   🧱 VERIFY JWT
========================= */
function verifyJWT(req, res, next) {
    try {
        const auth = req.headers['authorization'];

        if (!auth || !auth.startsWith('Bearer ')) {
            return res.status(403).json({
                error: "Missing bearer token"
            });
        }

        const token = auth.split(' ')[1];

        req.user = jwt.verify(token, JWT_SECRET);

        next();

    } catch (err) {
        return res.status(403).json({
            error: "Invalid or expired token"
        });
    }
}

/* =========================
   🧬 VERIFY SIGNATURE
========================= */
function verifySignature(req, res, next) {
    try {
        const nonce = req.headers['x-nonce'];
        const signature = req.headers['x-signature'];

        if (!nonce || !signature) {
            return res.status(403).json({
                error: "Missing signature headers"
            });
        }

        /* replay protection */
        if (usedNonces.has(nonce)) {
            return res.status(403).json({
                error: "Replay detected"
            });
        }

        const expected = crypto
            .createHmac('sha256', API_SECRET)
            .update(nonce)
            .digest('hex');

        const sigBuffer = Buffer.from(signature);
        const expBuffer = Buffer.from(expected);

        if (
            sigBuffer.length !== expBuffer.length ||
            !crypto.timingSafeEqual(sigBuffer, expBuffer)
        ) {
            return res.status(403).json({
                error: "Invalid signature"
            });
        }

        usedNonces.set(nonce, Date.now());

        next();

    } catch (err) {
        return res.status(500).json({
            error: "Signature verification failed"
        });
    }
}

/* =========================
   📦 CONFIG URL
========================= */
const CONFIG_URL =
    "https://raw.githubusercontent.com/sajadMod1/Raven1/main/config.json";

/* =========================
   ❤️ HEALTH CHECK
========================= */
app.get('/', (req, res) => {
    res.json({
        status: "online",
        uptime: process.uptime()
    });
});

/* =========================
   🔑 TOKEN ENDPOINT
========================= */
app.get('/token', (req, res) => {
    try {
        const token = generateToken();

        res.json({
            token,
            expires_in: "1h"
        });

    } catch (err) {
        res.status(500).json({
            error: "Failed to generate token"
        });
    }
});

/* =========================
   🚀 SECURE ROUTE
========================= */
app.get(
    '/signchk',
    verifyJWT,
    verifySignature,
    async (req, res) => {
        try {

            const response = await fetch(CONFIG_URL);

            if (!response.ok) {
                throw new Error(
                    `GitHub fetch failed: ${response.status}`
                );
            }

            const data = await response.text();

            const encrypted = encrypt(data);

            return res.json({
                success: true,
                timestamp: Date.now(),
                data: encrypted
            });

        } catch (err) {

            console.error("SIGNCHK ERROR:", err);

            return res.status(500).json({
                error: "Failed to fetch or encrypt",
                debug: err.message
            });
        }
    }
);

module.exports = app;