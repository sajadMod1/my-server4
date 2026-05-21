const express = require('express');
const crypto = require('crypto');

const app = express();

// لازم يكونوا 32 بايت و 16 بايت
const SECRET_KEY = Buffer.from(process.env.SECRET_KEY, 'utf8'); // 32 bytes
const IV = Buffer.from(process.env.IV, 'utf8'); // 16 bytes

function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, IV);

    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    return encrypted;
}

// رابط الملف الحقيقي
const CONFIG_URL =
  "https://raw.githubusercontent.com/sajadMod1/Raven1/refs/heads/main/config.json";

app.get('/signchk', async (req, res) => {
    try {
        const response = await fetch(CONFIG_URL);
        if (!response.ok) throw new Error("Fetch failed");

        const data = await response.text();

        const encrypted = encrypt(data);

        res.json({
            data: encrypted
        });

    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch or encrypt' });
    }
});

app.listen(3000, () => {
    console.log("Proxy running on port 3000");
});