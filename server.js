const express = require('express');
const crypto = require('crypto');

const app = express();

/**
 * 🔥 FIX: ضمان fetch في Vercel / Node environments
 */
const fetch = (...args) =>
  import('node-fetch').then(({ default: fetch }) => fetch(...args));

/**
 * 🔐 Keys
 */
const SECRET_KEY = Buffer.from(process.env.SECRET_KEY, 'utf8');
const IV = Buffer.from(process.env.IV, 'utf8');

/**
 * 🔒 Encrypt function
 */
function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, IV);

    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    return encrypted;
}

/**
 * 📦 Config URL (GitHub)
 */
const CONFIG_URL =
  "https://raw.githubusercontent.com/sajadMod1/Raven1/main/config.json";

/**
 * 🚀 API Route
 */
app.get('/signchk', async (req, res) => {
    try {
        console.log("Fetching:", CONFIG_URL);

        const response = await fetch(CONFIG_URL);

        if (!response.ok) {
            throw new Error("GitHub fetch failed: " + response.status);
        }

        const data = await response.text();

        const encrypted = encrypt(data);

        return res.status(200).json({
            data: encrypted
        });

    } catch (err) {
        console.error("ERROR:", err.message);

        return res.status(500).json({
            error: 'Failed to fetch or encrypt',
            debug: err.message
        });
    }
});

module.exports = app;