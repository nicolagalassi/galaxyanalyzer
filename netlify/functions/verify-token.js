const crypto = require('crypto');

// TOKEN_SECRET must be set as a Netlify environment variable.
// In Netlify dashboard: Site Settings → Environment Variables → Add variable
//   Key:   TOKEN_SECRET
//   Value: (any long random string you choose, e.g. "xK9#mQ2!vLp7nR4$wZ")

exports.handler = async function(event) {
    // Allow CORS preflight
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 204,
            headers: corsHeaders()
        };
    }

    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, headers: corsHeaders(), body: 'Method not allowed' };
    }

    const secret = process.env.TOKEN_SECRET;
    if (!secret) {
        console.error('[verify-token] TOKEN_SECRET environment variable not set');
        return {
            statusCode: 500,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, error: 'Server misconfiguration' })
        };
    }

    let token;
    try {
        const body = JSON.parse(event.body || '{}');
        token = (body.token || '').trim();
    } catch {
        return {
            statusCode: 400,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, error: 'Invalid request body' })
        };
    }

    if (!token) {
        return {
            statusCode: 400,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, error: 'Missing token' })
        };
    }

    // Token format: RAND-EXPIRY_TIMESTAMP
    // where RAND = random hex, EXPIRY_TIMESTAMP = ms since epoch
    // Signature = hmac-sha256(secret, token) or sha256(secret + token)
    // We use sha256(secret + token) to stay consistent with the client-side generation in token.html
    const lastDash = token.lastIndexOf('-');
    if (lastDash === -1) {
        return {
            statusCode: 200,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, reason: 'invalid_format' })
        };
    }

    const expiryStr = token.slice(lastDash + 1);
    const expiry    = parseInt(expiryStr, 10);

    if (isNaN(expiry)) {
        return {
            statusCode: 200,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, reason: 'invalid_format' })
        };
    }

    // Check expiry
    if (Date.now() > expiry) {
        return {
            statusCode: 200,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, reason: 'expired' })
        };
    }

    // Verify signature: sha256(secret + token)
    const expected = crypto
        .createHash('sha256')
        .update(secret + token)
        .digest('hex');

    // The client sends the token string; we recompute its expected hash server-side.
    // But we need the *generated* hash to compare against — stored nowhere.
    // CORRECT approach: token itself encodes a verifiable signature.
    //
    // Token format (revised): RAND-SIG-EXPIRY
    //   RAND = random hex (8 chars)
    //   SIG  = sha256(secret + RAND + EXPIRY)[0:12]  (first 12 hex chars)
    //   EXPIRY = ms timestamp
    //
    // Verification: recompute sha256(secret + RAND + EXPIRY), check first 12 chars match SIG.
    // No database needed, no stored hashes.

    const parts = token.split('-');
    if (parts.length !== 3) {
        return {
            statusCode: 200,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, reason: 'invalid_format' })
        };
    }

    const [rand, sig, expiryPart] = parts;
    const expiryTs = parseInt(expiryPart, 10);

    if (isNaN(expiryTs) || !rand || !sig) {
        return {
            statusCode: 200,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, reason: 'invalid_format' })
        };
    }

    if (Date.now() > expiryTs) {
        return {
            statusCode: 200,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, reason: 'expired' })
        };
    }

    const expectedSig = crypto
        .createHash('sha256')
        .update(secret + rand + expiryTs.toString())
        .digest('hex')
        .slice(0, 12);

    if (sig !== expectedSig) {
        return {
            statusCode: 200,
            headers: corsHeaders(),
            body: JSON.stringify({ valid: false, reason: 'invalid_signature' })
        };
    }

    const expiryDate = new Date(expiryTs).toLocaleDateString('it-IT', {
        day: '2-digit', month: '2-digit', year: 'numeric'
    });

    return {
        statusCode: 200,
        headers: corsHeaders(),
        body: JSON.stringify({ valid: true, expiry: expiryTs, expiryDate })
    };
};

function corsHeaders() {
    return {
        'Content-Type':                'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    };
}
