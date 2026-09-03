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
        const contentType = response.headers.get('content-type') || '';

        // SPECIAL CHECK: dontscrape loop
        if (finalUrl.includes('dontscrape')) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            return res.end(
                `WAF Block Detected!\nThe target server trapped this request in the dontscrape loop.\n` +
                `Final URL: ${finalUrl}\nThis means the server is actively blocking your VPS IP or the spoofed headers.`
            );
        }

        // Determine if this URL might be a disguised M3U8 file (to avoid loading huge video files into memory)
        const isPotentialM3u8 = 
            targetUrlStr.endsWith('.m3u8') || 
            targetUrlStr.endsWith('.jpg') || 
            targetUrlStr.endsWith('.png') || 
            targetUrlStr.endsWith('.jpeg') || 
            contentType.includes('mpegurl') || 
            contentType.includes('text/');

        if (isPotentialM3u8) {
            // Safe to read into memory because these are usually small text/base64 files
            const arrayBuffer = await response.arrayBuffer();
            const buffer = Buffer.from(arrayBuffer);
            let bodyText = buffer.toString('utf-8');
            
            let isBase64 = false;
            let isM3u8 = false;

            // Check if the response is Base64 encoded
            if (/^[a-zA-Z0-9+/=\s]+$/.test(bodyText.trim())) {
                try {
                    const decoded = Buffer.from(bodyText, 'base64').toString('utf-8');
                    if (decoded.trim().startsWith('#EXTM3U')) {
                        isBase64 = true;
                        isM3u8 = true;
                        bodyText = decoded; // Use the decoded text for rewriting
                    }
                } catch (e) {}
            }
            
            // Check if it's a plain text M3U8
            if (!isM3u8 && bodyText.trim().startsWith('#EXTM3U')) {
                isM3u8 = true;
            }

            if (isM3u8) {
                // REWRITE URLS
                const host = req.headers.host;
                const protocol = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
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

                let rewrittenText = rewrittenLines.join('\n');

                // If it was originally Base64, re-encode it before sending
                if (isBase64) {
                    rewrittenText = Buffer.from(rewrittenText).toString('base64');
                    res.writeHead(response.status, { 'Content-Type': contentType || 'application/octet-stream' });
                    return res.end(rewrittenText);
                } else {
                    res.writeHead(response.status, { 'Content-Type': 'application/vnd.apple.mpegurl' });
                    return res.end(rewrittenText);
                }
            }

            // If it wasn't an M3U8 (e.g., a real image), just send the original buffer
            res.writeHead(response.status, { 'Content-Type': contentType || 'application/octet-stream' });
            return res.end(buffer);
        }

        // For all other files (large video segments, audio, etc.), stream directly to save memory
        res.writeHead(response.status, { 'Content-Type': contentType || 'application/octet-stream' });
        const reader = response.body.getReader();
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            res.write(Buffer.from(value));
        }
        return res.end();

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
