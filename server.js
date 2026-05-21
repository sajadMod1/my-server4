const express = require('express');
const crypto = require('crypto');

const app = express();

/**
 * ❌ لا تستخدم node-fetch على Vercel
 * ✔ استخدم fetch المدمج فقط
 */

/**
 * 🔐 Keys (UTF-8)
 */
const SECRET_KEY = Buffer.from(process.env.SECRET_KEY, 'utf8');
const IV = Buffer.from(process.env.IV, 'utf8');

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

/**
 * 📦 GitHub URL (مهم: بدون refs)
 */
const CONFIG_URL =
  "https://raw.githubusercontent.com/sajadMod1/Raven1/main/config.json";

/**
 * 🚀 Route
 */
app.get('/signchk', async (req, res) => {
    try {
        console.log("Fetching:", CONFIG_URL);

        const response = await fetch(CONFIG_URL);

        if (!response.ok) {
            throw new Error(`GitHub error: ${response.status}`);
        }

        const data = await response.text();

        const encrypted = encrypt(data);

        return res.status(200).json({
            data: encrypted
        });

    } catch (err) {
        console.error("ERROR:", err);

        return res.status(500).json({
            error: 'Failed to fetch or encrypt',
            debug: err.message
        });
    }
});

module.exports = app;