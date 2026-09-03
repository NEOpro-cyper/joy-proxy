const express = require('express');
const { Agent } = require('undici'); // Built into Node.js 18+
const app = express();

app.use(express.raw({ type: '*/*' }));

// Create an Agent that ignores SSL errors, mimicking PHP's CURLOPT_SSL_VERIFYPEER => false
const insecureAgent = new Agent({
    connect: {
        rejectUnauthorized: false
    }
});

app.use(async (req, res) => {
    // 1. Handle CORS
    res.set({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': '*'
    });

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    // 2. Extract Target URL (Exactly like PHP)
    const requestUri = req.originalUrl;
    const posHttp = requestUri.indexOf('http://');
    const posHttps = requestUri.indexOf('https://');

    if (posHttp === -1 && posHttps === -1) {
        return res.status(400).set('Content-Type', 'text/plain').send(
            'Invalid proxy usage. Format: https://your-domain.com/https://target.com/path'
        );
    }

    const startPos = (posHttp !== -1 && (posHttps === -1 || posHttp < posHttps)) ? posHttp : posHttps;
    const targetUrlStr = requestUri.substring(startPos);

    // 3. Prepare Headers (Matching PHP)
    const modifiedHeaders = {
        'Referer': 'https://cinejoy.to/',
        'Origin': 'https://cinejoy.to',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'sec-ch-ua': '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
    };

    const fetchOptions = {
        method: req.method,
        headers: modifiedHeaders,
        redirect: 'follow',
        dispatcher: insecureAgent // Ignore SSL validation
    };

    if (req.method !== 'GET' && req.method !== 'HEAD') {
        fetchOptions.body = req.body;
    }

    try {
        const response = await fetch(targetUrlStr, fetchOptions);
        const finalUrl = response.url; // Where it finally ended up after redirects

        // SPECIAL CHECK: dontscrape loop
        if (finalUrl.includes('dontscrape')) {
            return res.status(403).set('Content-Type', 'text/plain').send(
                `WAF Block Detected!\nThe target server trapped this request in the dontscrape loop.\nFinal URL: ${finalUrl}\nThis means the server is actively blocking your VPS IP or the spoofed headers.`
            );
        }

        const contentType = response.headers.get('content-type') || '';
        const isM3u8 = contentType.includes('mpegurl') || targetUrlStr.endsWith('.m3u8');

        res.status(response.status);

        if (!isM3u8) {
            // Not an m3u8, pass through directly
            if (response.headers.get('content-type')) {
                res.set('Content-Type', response.headers.get('content-type'));
            }
            
            // Pipe the stream directly to save memory
            const reader = response.body.getReader();
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                res.write(Buffer.from(value));
            }
            return res.end();
        }

        // IT IS AN M3U8 - REWRITE URLS (Matching PHP Logic exactly)
        const bodyText = await response.text();
        
        const scriptUrl = req.protocol + '://' + req.get('host') + req.baseUrl;
        const workerBase = scriptUrl + '/';

        const targetUrlParts = new URL(finalUrl);
        const targetOrigin = targetUrlParts.origin;
        const targetProtocol = targetUrlParts.protocol.replace(':', '');
        const targetPath = targetUrlParts.pathname;
        const targetDir = targetPath.substring(0, targetPath.lastIndexOf('/') + 1);

        const lines = bodyText.split('\n');
        const rewrittenLines = lines.map(line => {
            const trimmed = line.trim();
            if (trimmed === '') return line;

            if (trimmed.startsWith('#')) {
                // Handle URI="..." attributes inside tags
                return line.replace(/URI="([^"]+)"/g, (match, uri) => {
                    let absolute = uri;
                    if (uri.startsWith('http://') || uri.startsWith('https://')) {
                        absolute = uri;
                    } else if (uri.startsWith('//')) {
                        absolute = targetProtocol + ':' + uri;
                    } else if (uri.startsWith('/')) {
                        absolute = targetOrigin + uri;
                    } else {
                        absolute = targetOrigin + targetDir + uri;
                    }
                    return 'URI="' + workerBase + absolute + '"';
                });
            } else {
                // Non-comment line = segment/playlist URL
                let absolute = trimmed;
                if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
                    absolute = trimmed;
                } else if (trimmed.startsWith('//')) {
                    absolute = targetProtocol + ':' + trimmed;
                } else if (trimmed.startsWith('/')) {
                    absolute = targetOrigin + trimmed;
                } else {
                    absolute = targetOrigin + targetDir + trimmed;
                }
                return workerBase + absolute;
            }
        });

        const rewrittenText = rewrittenLines.join('\n');

        res.set('Content-Type', 'application/vnd.apple.mpegurl');
        return res.send(rewrittenText);

    } catch (error) {
        console.error('[PROXY] Fetch Error:', error.message);
        if (!res.headersSent) {
            return res.status(500).set('Content-Type', 'text/plain').send('Error: ' + error.message);
        }
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Proxy server running on port ${PORT}`);
});
