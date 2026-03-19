const crypto = require('crypto');

// TOKEN_SECRET must be set as a Netlify environment variable.
// Site Settings → Environment Variables → TOKEN_SECRET = (your secret string)
// Must be the same value used in verify-token.js

exports.handler = async function(event) {
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 204, headers: corsHeaders() };
    }

    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, headers: corsHeaders(), body: 'Method not allowed' };
    }

    const secret = process.env.TOKEN_SECRET;
    if (!secret) {
        console.error('[generate-token] TOKEN_SECRET not set');
        return {
            statusCode: 500,
            headers: corsHeaders(),
            body: JSON.stringify({ error: 'Server misconfiguration' })
        };
    }

    let rand, expiry;
    try {
        const body = JSON.parse(event.body || '{}');
        rand   = (body.rand   || '').trim().toUpperCase();
        expiry = parseInt(body.expiry, 10);
    } catch {
        return {
            statusCode: 400,
            headers: corsHeaders(),
            body: JSON.stringify({ error: 'Invalid request body' })
        };
    }

    if (!rand || isNaN(expiry)) {
        return {
            statusCode: 400,
            headers: corsHeaders(),
            body: JSON.stringify({ error: 'Missing rand or expiry' })
        };
    }

    // Validate expiry: must be in the future and not more than 1 year ahead
    const now = Date.now();
    if (expiry <= now) {
        return {
            statusCode: 400,
            headers: corsHeaders(),
            body: JSON.stringify({ error: 'Expiry must be in the future' })
        };
    }
    if (expiry > now + 366 * 86400000) {
        return {
            statusCode: 400,
            headers: corsHeaders(),
            body: JSON.stringify({ error: 'Expiry too far in the future (max 1 year)' })
        };
    }

    // Generate signature: first 12 hex chars of sha256(secret + rand + expiry)
    const sig = crypto
        .createHash('sha256')
        .update(secret + rand + expiry.toString())
        .digest('hex')
        .slice(0, 12);

    // Token format: RAND-SIG-EXPIRY
    const token = `${rand}-${sig}-${expiry}`;

    return {
        statusCode: 200,
        headers: corsHeaders(),
        body: JSON.stringify({ token })
    };
};

function corsHeaders() {
    return {
        'Content-Type':                 'application/json',
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    };
}
