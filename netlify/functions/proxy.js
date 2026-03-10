const axios = require('axios');

exports.handler = async function(event, context) {
    // Netlify passa i parametri GET dentro event.queryStringParameters
    const targetUrl = event.queryStringParameters.url;

    // Controllo di sicurezza
    if (!targetUrl || !targetUrl.includes('ogame.gameforge.com/api/')) {
        return {
            statusCode: 400,
            body: 'URL non valido o non fornito.'
        };
    }

    try {
        const response = await axios.get(targetUrl, {
            maxContentLength: Infinity,
            maxBodyLength: Infinity,
            responseType: 'text' // Forza la risposta come testo per l'XML
        });
        
        return {
            statusCode: 200,
            headers: {
                'Content-Type': 'text/xml',
                'Access-Control-Allow-Origin': '*' // Abilita CORS per il frontend
            },
            body: response.data
        };
    } catch (error) {
        console.error(`Errore nel fetch di ${targetUrl}:`, error.message);
        return {
            statusCode: 500,
            body: 'Errore nel caricamento dell\'API da Gameforge'
        };
    }
};