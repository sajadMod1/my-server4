const express = require('express');
const crypto = require('crypto');

const app = express();

/**
 * 🔐 FIXED KEYS (No more length errors)
 */
const SECRET_KEY = crypto
  .createHash('sha256')
  .update(process.env.SECRET_KEY)
  .digest();

const IV = Buffer.from(process.env.IV).slice(0, 16);

/**
 * 🔒 Encrypt
 */
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

const CONFIG_URL =
  "https://raw.githubusercontent.com/sajadMod1/Raven1/main/config.json";

app.get('/signchk', async (req, res) => {
    try {
        const response = await fetch(CONFIG_URL);

        if (!response.ok) {
            throw new Error("GitHub fetch failed");
        }

        const data = await response.text();

        const encrypted = encrypt(data);

        res.json({ data: encrypted });

    } catch (err) {
        res.status(500).json({
            error: "Failed to fetch or encrypt",
            debug: err.message
        });
    }
});

module.exports = app;