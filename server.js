// Bypass SSL verification globally (Mimics PHP's CURLOPT_SSL_VERIFYPEER => false)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const http = require('http');

const server = http.createServer(async (req, res) => {
    // 1. Handle CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        return res.end();
    }

    // 2. Extract Target URL directly from the raw request
    let requestUri = req.url;
    
    // Decode in case the proxy/player URL-encoded the slashes (e.g., %2F)
    try {
        if (requestUri.includes('%')) {
            requestUri = decodeURIComponent(requestUri);
        }
    } catch (e) {}

    const posHttp = requestUri.indexOf('http://');
    const posHttps = requestUri.indexOf('https://');

    if (posHttp === -1 && posHttps === -1) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        return res.end(
            `Invalid proxy usage. Format: https://your-domain.com/?t=https://target.com/path\n\n` +
            `Debug Info:\nreq.url: ${req.url}\nDecoded: ${requestUri}`
        );
    }

    const startPos = (posHttp !== -1 && (posHttps === -1 || posHttp < posHttps)) ? posHttp : posHttps;
    const targetUrlStr = requestUri.substring(startPos);

    // 3. Prepare Headers (Matching your PHP cURL headers)
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
        redirect: 'follow'
    };

    // Handle POST/PUT bodies manually
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        const chunks = [];
        for await (const chunk of req) {
            chunks.push(chunk);
        }
        fetchOptions.body = Buffer.concat(chunks);
    }

    try {
        const response = await fetch(targetUrlStr, fetchOptions);
        const finalUrl = response.url; // Get final URL after redirects

        // SPECIAL CHECK: dontscrape loop
        if (finalUrl.includes('dontscrape')) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            return res.end(
                `WAF Block Detected!\nThe target server trapped this request in the dontscrape loop.\n` +
                `Final URL: ${finalUrl}\nThis means the server is actively blocking your VPS IP or the spoofed headers.`
            );
        }

        const contentType = response.headers.get('content-type') || '';
        const isM3u8 = contentType.includes('mpegurl') || targetUrlStr.endsWith('.m3u8');

        res.writeHead(response.status, {
            'Content-Type': isM3u8 ? 'application/vnd.apple.mpegurl' : (contentType || 'application/octet-stream')
        });

        if (!isM3u8) {
            // Not an m3u8, pipe the stream directly to save memory
            const reader = response.body.getReader();
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                res.write(Buffer.from(value));
            }
            return res.end();
        }

        // IT IS AN M3U8 - REWRITE URLS
        const bodyText = await response.text();
        
        // Respect Coolify's reverse proxy headers for HTTPS
        const host = req.headers.host;
        const protocol = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
        
        // CHANGED HERE: Use ?t= format so the player doesn't get 400 Bad Request
        const workerBase = `${protocol}://${host}/?t=`;

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
        return res.end(rewrittenText);

    } catch (error) {
        console.error('[PROXY] Fetch Error:', error.message);
        if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            return res.end('Error: ' + error.message);
        }
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Pure Node.js proxy server running on port ${PORT}`);
});
