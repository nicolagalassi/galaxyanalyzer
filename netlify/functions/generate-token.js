const crypto = require('crypto');

// Required Netlify environment variables:
//   TOKEN_SECRET   — secret salt for signing tokens (same as verify-token.js)
//   RESEND_API_KEY — from resend.com dashboard
//   FROM_EMAIL     — verified sender, e.g. "OGame Tracker <noreply@yourdomain.com>"
//   SITE_URL       — your Netlify site URL, e.g. "https://yoursite.netlify.app"

exports.handler = async function(event) {
    if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors() };
    if (event.httpMethod !== 'POST')    return { statusCode: 405, headers: cors(), body: 'Method not allowed' };

    const secret = process.env.TOKEN_SECRET;
    if (!secret) {
        console.error('[generate-token] TOKEN_SECRET not set');
        return { statusCode: 500, headers: cors(), body: JSON.stringify({ error: 'Server misconfiguration' }) };
    }

    let days, email, sessionId, adminGenerated;
    try {
        const body   = JSON.parse(event.body || '{}');
        days          = Math.min(Math.max(parseInt(body.days, 10) || 30, 1), 365);
        email         = (body.email || '').trim().toLowerCase() || null;
        sessionId     = (body.sessionId || '').trim() || null;
        adminGenerated = !!body.adminGenerated;
    } catch {
        return { statusCode: 400, headers: cors(), body: JSON.stringify({ error: 'Invalid body' }) };
    }

    // Build token: RAND-SIG-EXPIRY
    const rand   = crypto.randomBytes(4).toString('hex').toUpperCase();
    const expiry = Date.now() + days * 86400000;
    const sig    = crypto.createHash('sha256')
        .update(secret + rand + expiry.toString())
        .digest('hex')
        .slice(0, 12);
    const token = `${rand}-${sig}-${expiry}`;

    // Store pending token keyed by sessionId (in-memory won't survive restarts,
    // so we use a simple signed approach: the poll endpoint re-derives the token
    // from the sessionId stored client-side — see poll-token.js for details).
    // For email delivery we call Resend here.
    if (email) {
        await sendTokenEmail({ email, token, expiry, days });
    }

    // If called from webhook (sessionId present), store in a simple KV via
    // a signed cookie-like value so poll-token can verify it.
    // Since Netlify Functions are stateless, we encode the result in a signed
    // blob that poll-token can validate without shared state.
    const pollPayload = sessionId
        ? signPollPayload({ sessionId, token, expiry, secret })
        : null;

    const siteUrl = process.env.SITE_URL || '';
    const expiryDate = new Date(expiry).toLocaleDateString('it-IT', { day:'2-digit', month:'2-digit', year:'numeric' });

    return {
        statusCode: 200,
        headers: cors(),
        body: JSON.stringify({ token, expiry, expiryDate, pollPayload })
    };
};

// ── EMAIL ──────────────────────────────────────────────────────────────────────
async function sendTokenEmail({ email, token, expiry, days }) {
    const resendKey = process.env.RESEND_API_KEY;
    const fromEmail = process.env.FROM_EMAIL || 'OGame Tracker <noreply@resend.dev>';
    const siteUrl   = process.env.SITE_URL   || '';

    if (!resendKey) {
        console.warn('[generate-token] RESEND_API_KEY not set — skipping email');
        return;
    }

    const expiryDate = new Date(expiry).toLocaleDateString('it-IT', {
        day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit'
    });

    const html = `
<!DOCTYPE html>
<html lang="it">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#111110;font-family:'Segoe UI',sans-serif">
  <div style="max-width:520px;margin:40px auto;padding:0 20px">
    <div style="background:#1a1a18;border:1px solid #2e2e2b;border-radius:8px;overflow:hidden">
      <div style="padding:28px 32px;border-bottom:1px solid #2e2e2b">
        <div style="font-size:1.4rem;font-weight:700;color:#ffffff;margin-bottom:4px">OGame <span style="color:#e8a020">Universe</span> Tracker</div>
        <div style="font-size:0.75rem;color:#5a5752;letter-spacing:2px;text-transform:uppercase">Token Premium</div>
      </div>
      <div style="padding:28px 32px">
        <p style="color:#9e9a94;font-size:0.9rem;margin:0 0 20px">Grazie per aver supportato il progetto! Ecco il tuo token premium valido per <strong style="color:#f0ede8">${days} giorni</strong>.</p>
        <div style="background:#111110;border:1px solid #3a3a36;border-radius:6px;padding:16px;font-family:monospace;font-size:0.9rem;letter-spacing:1.5px;color:#ffffff;word-break:break-all;margin-bottom:16px">${token}</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
          <span style="font-size:0.78rem;color:#5a5752;font-family:monospace">Valido fino al</span>
          <span style="background:rgba(232,160,32,.12);border:1px solid rgba(232,160,32,.2);color:#e8a020;padding:3px 10px;border-radius:10px;font-family:monospace;font-size:0.72rem">${expiryDate}</span>
        </div>
        <p style="color:#9e9a94;font-size:0.85rem;margin:0 0 20px">Per usarlo: vai alla mappa, carica un universo, e clicca il chip <strong style="color:#f0ede8">🔒 Slot 8 liberi</strong>. Incolla il token e premi Sblocca.</p>
        ${siteUrl ? `<a href="${siteUrl}/index.html" style="display:block;background:#e8a020;color:#111;padding:12px 20px;border-radius:6px;text-decoration:none;font-weight:600;text-align:center;font-size:0.92rem">→ Vai alla mappa</a>` : ''}
      </div>
      <div style="padding:16px 32px;border-top:1px solid #2e2e2b;font-size:0.72rem;color:#5a5752;text-align:center;font-family:monospace;letter-spacing:1px">
        CONSERVA QUESTO TOKEN · NON CONDIVIDERLO
      </div>
    </div>
  </div>
</body>
</html>`;

    try {
        const res = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${resendKey}`,
                'Content-Type':  'application/json'
            },
            body: JSON.stringify({
                from:    fromEmail,
                to:      [email],
                subject: '⭐ Il tuo token OGame Universe Tracker',
                html
            })
        });
        if (!res.ok) {
            const err = await res.text();
            console.error('[generate-token] Resend error:', err);
        }
    } catch(e) {
        console.error('[generate-token] Email send failed:', e.message);
    }
}

// ── SIGNED POLL PAYLOAD ────────────────────────────────────────────────────────
// Encodes { sessionId, token, expiry } as a signed base64 string so poll-token
// can verify it without shared in-memory state.
function signPollPayload({ sessionId, token, expiry, secret }) {
    const data = JSON.stringify({ sessionId, token, expiry });
    const sig  = crypto.createHash('sha256').update(secret + data).digest('hex').slice(0, 16);
    return Buffer.from(data).toString('base64') + '.' + sig;
}

function cors() {
    return {
        'Content-Type':                 'application/json',
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    };
}
