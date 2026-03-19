const crypto = require('crypto');

// Required Netlify environment variables:
//   TOKEN_SECRET        — same as generate-token.js and verify-token.js
//   KOFI_VERIFICATION_TOKEN — from Ko-fi dashboard → API → Webhook Verification Token
//   RESEND_API_KEY      — from resend.com
//   FROM_EMAIL          — verified sender email
//   SITE_URL            — your site URL

// Ko-fi sends a POST with Content-Type: application/x-www-form-urlencoded
// Body contains: data=<JSON string>

exports.handler = async function(event) {
    if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors() };
    if (event.httpMethod !== 'POST')    return { statusCode: 405, body: 'Method not allowed' };

    const secret      = process.env.TOKEN_SECRET;
    const kofiToken   = process.env.KOFI_VERIFICATION_TOKEN;

    if (!secret) {
        console.error('[kofi-webhook] TOKEN_SECRET not set');
        return { statusCode: 500, body: 'Server misconfiguration' };
    }

    // Parse Ko-fi payload
    let payload;
    try {
        // Ko-fi sends form-encoded: data=<urlencoded JSON>
        const bodyStr = event.isBase64Encoded
            ? Buffer.from(event.body, 'base64').toString('utf-8')
            : (event.body || '');

        let jsonStr;
        if (bodyStr.startsWith('data=')) {
            jsonStr = decodeURIComponent(bodyStr.slice(5));
        } else {
            // Some Ko-fi setups send raw JSON
            jsonStr = bodyStr;
        }
        payload = JSON.parse(jsonStr);
    } catch(e) {
        console.error('[kofi-webhook] Failed to parse payload:', e.message, event.body);
        return { statusCode: 400, body: 'Invalid payload' };
    }

    console.log('[kofi-webhook] Received:', JSON.stringify(payload));

    // Verify Ko-fi verification token (optional but recommended)
    if (kofiToken && payload.verification_token !== kofiToken) {
        console.warn('[kofi-webhook] Verification token mismatch');
        return { statusCode: 401, body: 'Unauthorized' };
    }

    // Only process completed payments (not refunds, subscriptions cancelled, etc.)
    if (payload.type !== 'Donation' && payload.type !== 'Shop Order' && payload.type !== 'Subscription') {
        console.log('[kofi-webhook] Ignoring event type:', payload.type);
        return { statusCode: 200, body: 'OK' };
    }

    if (!payload.is_public && payload.type === 'Donation') {
        // Private donations still valid — continue
    }

    // Extract donor email
    // Ko-fi puts the donor email in payload.email
    const donorEmail = (payload.email || '').trim().toLowerCase();

    if (!donorEmail) {
        console.warn('[kofi-webhook] No email in payload — cannot send token');
        return { statusCode: 200, body: 'OK — no email' };
    }

    // Generate token (30 days)
    const DAYS   = 30;
    const rand   = crypto.randomBytes(4).toString('hex').toUpperCase();
    const expiry = Date.now() + DAYS * 86400000;
    const sig    = crypto.createHash('sha256')
        .update(secret + rand + expiry.toString())
        .digest('hex')
        .slice(0, 12);
    const token = `${rand}-${sig}-${expiry}`;

    console.log(`[kofi-webhook] Generated token for ${donorEmail}, expiry ${new Date(expiry).toISOString()}`);

    // Send email
    await sendTokenEmail({ email: donorEmail, token, expiry, days: DAYS, donorName: payload.from_name });

    // Store the token in a signed poll payload so the browser can pick it up.
    // We encode it as a query param on a redirect URL — Ko-fi supports a
    // "Thank you page" redirect. But since we can't control that here,
    // we instead write the payload to a short-lived signed blob the poll endpoint reads.
    // Implementation: poll-token reads a payload signed by this webhook.
    const pollData = JSON.stringify({ email: donorEmail, token, expiry, ts: Date.now() });
    const pollSig  = crypto.createHash('sha256').update(secret + pollData).digest('hex').slice(0, 16);
    const pollBlob = Buffer.from(pollData).toString('base64') + '.' + pollSig;

    // We can't store state in Netlify Functions directly.
    // Solution: store the blob in a Netlify Blobs store (if available),
    // OR encode it in a deterministic way from email so poll-token can find it.
    //
    // Simplest stateless approach: sign the token with the email so poll-token
    // can verify by re-computing. We return 200 and let the email do the work.
    // The browser polling will call poll-token with { email, sessionId }.
    // poll-token calls THIS function indirectly, but that's circular.
    //
    // ACTUAL SOLUTION: Use Netlify Blobs (built-in KV store, no extra service needed).
    try {
        await storeTokenBlob(donorEmail, { token, expiry, pollBlob });
    } catch(e) {
        console.error('[kofi-webhook] Failed to store blob:', e.message);
        // Email was still sent — user can still use the token from email
    }

    return { statusCode: 200, body: 'OK' };
};

// ── NETLIFY BLOBS ─────────────────────────────────────────────────────────────
// Netlify Blobs is available natively in Netlify Functions v2.
// For Functions v1 (which we're using), we use the @netlify/blobs package.
async function storeTokenBlob(email, data) {
    const { getStore } = require('@netlify/blobs');
    const store = getStore('pending-tokens');
    // Key by email hash to avoid leaking emails in blob names
    const keyHash = crypto.createHash('sha256').update(email).digest('hex').slice(0, 24);
    await store.set(keyHash, JSON.stringify({ ...data, email }), { ttl: 600 }); // 10 min TTL
    console.log(`[kofi-webhook] Stored blob for key ${keyHash}`);
}

// ── EMAIL ──────────────────────────────────────────────────────────────────────
async function sendTokenEmail({ email, token, expiry, days, donorName }) {
    const resendKey = process.env.RESEND_API_KEY;
    const fromEmail = process.env.FROM_EMAIL || 'OGame Tracker <noreply@resend.dev>';
    const siteUrl   = process.env.SITE_URL   || '';

    if (!resendKey) {
        console.warn('[kofi-webhook] RESEND_API_KEY not set — skipping email');
        return;
    }

    const expiryDate = new Date(expiry).toLocaleDateString('it-IT', {
        day:'2-digit', month:'2-digit', year:'numeric'
    });

    const greeting = donorName ? `Ciao ${donorName},` : 'Ciao,';

    const html = `
<!DOCTYPE html>
<html lang="it">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#111110;font-family:'Segoe UI',sans-serif">
  <div style="max-width:520px;margin:40px auto;padding:0 20px">
    <div style="background:#1a1a18;border:1px solid #2e2e2b;border-radius:8px;overflow:hidden">
      <div style="padding:28px 32px;border-bottom:1px solid #2e2e2b">
        <div style="font-size:1.4rem;font-weight:700;color:#ffffff;margin-bottom:4px">
          OGame <span style="color:#e8a020">Universe</span> Tracker
        </div>
        <div style="font-size:0.72rem;color:#5a5752;letter-spacing:2px;text-transform:uppercase;font-family:monospace">
          Token Premium — ${days} giorni
        </div>
      </div>
      <div style="padding:28px 32px">
        <p style="color:#9e9a94;font-size:0.92rem;margin:0 0 6px">${greeting}</p>
        <p style="color:#9e9a94;font-size:0.9rem;margin:0 0 24px">
          Grazie per il tuo supporto! 🙏<br>
          Ecco il tuo token premium valido per <strong style="color:#f0ede8">${days} giorni</strong>.
        </p>

        <div style="margin-bottom:8px;font-size:0.72rem;color:#5a5752;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase">Il tuo token</div>
        <div style="background:#111110;border:1px solid #3a3a36;border-radius:6px;padding:16px;font-family:monospace;font-size:0.88rem;letter-spacing:1.5px;color:#ffffff;word-break:break-all;margin-bottom:16px">
          ${token}
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:8px">
          <span style="font-size:0.78rem;color:#5a5752;font-family:monospace">Valido fino al</span>
          <span style="background:rgba(232,160,32,.12);border:1px solid rgba(232,160,32,.2);color:#e8a020;padding:4px 12px;border-radius:10px;font-family:monospace;font-size:0.72rem;letter-spacing:1px">
            ⏳ ${expiryDate}
          </span>
        </div>

        <div style="background:#222220;border:1px solid #2e2e2b;border-radius:6px;padding:16px;margin-bottom:24px">
          <div style="font-size:0.78rem;color:#5a5752;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:10px">Come usarlo</div>
          <ol style="margin:0;padding-left:18px;color:#9e9a94;font-size:0.85rem;line-height:2">
            <li>Vai alla mappa e carica un universo</li>
            <li>Clicca il chip <strong style="color:#f0ede8">🔒 Slot 8 liberi</strong></li>
            <li>Incolla il token nel campo e premi <strong style="color:#f0ede8">Sblocca</strong></li>
          </ol>
        </div>

        ${siteUrl ? `
        <a href="${siteUrl}/index.html"
           style="display:block;background:#e8a020;color:#111;padding:13px 20px;border-radius:6px;
                  text-decoration:none;font-weight:600;text-align:center;font-size:0.92rem">
          → Vai alla mappa
        </a>` : ''}
      </div>
      <div style="padding:16px 32px;border-top:1px solid #2e2e2b;font-size:0.7rem;color:#5a5752;text-align:center;font-family:monospace;letter-spacing:1px">
        CONSERVA QUESTO TOKEN · NON CONDIVIDERLO · VALIDO UNA SOLA INSTALLAZIONE
      </div>
    </div>
  </div>
</body>
</html>`;

    const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${resendKey}`,
            'Content-Type':  'application/json'
        },
        body: JSON.stringify({
            from:    fromEmail,
            to:      [email],
            subject: `⭐ Il tuo token OGame Universe Tracker (${days} giorni)`,
            html
        })
    });

    if (!res.ok) {
        const err = await res.text();
        console.error('[kofi-webhook] Resend error:', err);
    } else {
        console.log(`[kofi-webhook] Email sent to ${email}`);
    }
}

function cors() {
    return {
        'Content-Type':                 'application/json',
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    };
}
