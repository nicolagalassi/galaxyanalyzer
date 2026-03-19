const crypto = require('crypto');

// Required env var: TOKEN_SECRET (same as generate-token.js)

exports.handler = async function(event) {
    if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors() };
    if (event.httpMethod !== 'POST')    return { statusCode: 405, headers: cors(), body: 'Method not allowed' };

    const secret = process.env.TOKEN_SECRET;
    if (!secret) {
        console.error('[verify-token] TOKEN_SECRET not set');
        return { statusCode: 500, headers: cors(), body: JSON.stringify({ valid: false, error: 'Server misconfiguration' }) };
    }

    let token;
    try {
        const body = JSON.parse(event.body || '{}');
        token = (body.token || '').trim();
    } catch {
        return { statusCode: 400, headers: cors(), body: JSON.stringify({ valid: false }) };
    }

    if (!token) return { statusCode: 400, headers: cors(), body: JSON.stringify({ valid: false }) };

    // Token format: RAND-SIG-EXPIRY
    const parts = token.split('-');
    if (parts.length !== 3) {
        return { statusCode: 200, headers: cors(), body: JSON.stringify({ valid: false, reason: 'invalid_format' }) };
    }

    const [rand, sig, expiryStr] = parts;
    const expiry = parseInt(expiryStr, 10);

    if (!rand || !sig || isNaN(expiry)) {
        return { statusCode: 200, headers: cors(), body: JSON.stringify({ valid: false, reason: 'invalid_format' }) };
    }

    if (Date.now() > expiry) {
        return { statusCode: 200, headers: cors(), body: JSON.stringify({ valid: false, reason: 'expired' }) };
    }

    const expectedSig = crypto
        .createHash('sha256')
        .update(secret + rand + expiry.toString())
        .digest('hex')
        .slice(0, 12);

    if (sig !== expectedSig) {
        return { statusCode: 200, headers: cors(), body: JSON.stringify({ valid: false, reason: 'invalid_signature' }) };
    }

    const expiryDate = new Date(expiry).toLocaleDateString('it-IT', {
        day:'2-digit', month:'2-digit', year:'numeric'
    });

    return {
        statusCode: 200,
        headers: cors(),
        body: JSON.stringify({ valid: true, expiry, expiryDate })
    };
};

function cors() {
    return {
        'Content-Type':                 'application/json',
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    };
}
