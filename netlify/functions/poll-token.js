const crypto = require('crypto');

// The browser on token.html polls this endpoint every few seconds after
// the user clicks the Ko-fi button. Once kofi-webhook has stored the token
// in Netlify Blobs, this endpoint finds it and returns it to the browser.

exports.handler = async function(event) {
    if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors() };
    if (event.httpMethod !== 'POST')    return { statusCode: 405, headers: cors(), body: 'Method not allowed' };

    let email;
    try {
        const body = JSON.parse(event.body || '{}');
        email = (body.email || '').trim().toLowerCase();
    } catch {
        return { statusCode: 400, headers: cors(), body: JSON.stringify({ ready: false }) };
    }

    if (!email) {
        return { statusCode: 400, headers: cors(), body: JSON.stringify({ ready: false }) };
    }

    try {
        const { getStore } = require('@netlify/blobs');
        const store   = getStore('pending-tokens');
        const keyHash = crypto.createHash('sha256').update(email).digest('hex').slice(0, 24);
        const raw     = await store.get(keyHash, { type: 'text' });

        if (!raw) {
            return {
                statusCode: 200,
                headers: cors(),
                body: JSON.stringify({ ready: false })
            };
        }

        const data = JSON.parse(raw);

        // Delete the blob so it can't be retrieved again (one-time use)
        await store.delete(keyHash);

        return {
            statusCode: 200,
            headers: cors(),
            body: JSON.stringify({
                ready:  true,
                token:  data.token,
                expiry: data.expiry
            })
        };
    } catch(e) {
        console.error('[poll-token] Blobs error:', e.message);
        // If blobs aren't configured, return not ready gracefully
        return {
            statusCode: 200,
            headers: cors(),
            body: JSON.stringify({ ready: false })
        };
    }
};

function cors() {
    return {
        'Content-Type':                 'application/json',
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    };
}
