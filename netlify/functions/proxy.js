const axios = require('axios');

// Whitelist of allowed API paths
const ALLOWED_PATHS = [
    '/api/universe.xml',
    '/api/players.xml',
    '/api/alliances.xml',
    '/api/serverData.xml',
    '/api/universes.xml'
];

exports.handler = async function(event, context) {
    const targetUrl = event.queryStringParameters?.url;

    if (!targetUrl) {
        return { statusCode: 400, body: 'Parametro URL mancante.' };
    }

    // Security: must be a Gameforge OGame API endpoint
    const isGameforgeHost  = targetUrl.includes('.ogame.gameforge.com');
    const isAllowedPath    = ALLOWED_PATHS.some(p => targetUrl.includes(p));

    if (!isGameforgeHost || !isAllowedPath) {
        return { statusCode: 403, body: 'URL non autorizzato.' };
    }

    try {
        const response = await axios.get(targetUrl, {
            timeout: 30000,               // 30s timeout
            maxContentLength: 50_000_000, // 50 MB max
            maxBodyLength:    50_000_000,
            responseType: 'text',
            headers: {
                'Accept': 'text/xml, application/xml',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'OGame-Universe-Tracker/2.0'
            }
        });

        return {
            statusCode: 200,
            headers: {
                'Content-Type':                'text/xml; charset=utf-8',
                'Access-Control-Allow-Origin': '*',
                'Cache-Control':               'public, max-age=300' // 5 min cache
            },
            body: response.data
        };

    } catch (error) {
        const status = error.response?.status ?? 500;
        const msg    = error.code === 'ECONNABORTED'
            ? 'Timeout: il server Gameforge non ha risposto in tempo.'
            : `Errore nel caricamento dell'API da Gameforge: ${error.message}`;

        console.error(`[proxy] Errore fetch ${targetUrl}:`, error.message);
        return { statusCode: status, body: msg };
    }
};