const express = require('express');
const app = express();

// Needed to parse the raw body for POST/PUT requests if they occur
app.use(express.raw({ type: '*/*' }));

app.all('*', async (req, res) => {
  const workerOrigin = req.protocol + '://' + req.get('host');

  // Handle CORS preflight requests directly
  if (req.method === 'OPTIONS') {
    return res.status(204).set({
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': '*'
    }).end();
  }

  // Extract the target URL from the path (removes the leading slash)
  // req.originalUrl includes the path and query string (e.g., /https://target.com/path?q=1)
  const rawPath = req.originalUrl.replace(/^\//, '');

  // Ensure the path starts with a valid http/https URL
  if (!rawPath.startsWith('http://') && !rawPath.startsWith('https://')) {
    return res.status(400).set('Content-Type', 'text/plain').send(
      'Invalid proxy usage. Format: http://your-vps-ip:port/https://target.com/path'
    );
  }

  // Construct the target URL object
  let targetUrl;
  try {
    targetUrl = new URL(rawPath);
  } catch (e) {
    return res.status(400).send('Invalid target URL provided in path.');
  }

  // Match exactly what the browser sends
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

  // Attach body for non-GET/HEAD requests
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    fetchOptions.body = req.body;
  }

  try {
    const response = await fetch(targetUrl.toString(), fetchOptions);
    const contentType = response.headers.get('Content-Type') || '';
    
    // Set common CORS headers for the response
    res.set({
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': '*'
    });

    // Check if the response is an HLS playlist
    if (contentType.includes('mpegurl') || targetUrl.pathname.endsWith('.m3u8')) {
      let text = await response.text();
      
      // 1. Rewrite absolute URLs (http:// or https://) to route through the proxy
      text = text.replace(/(https?:\/\/[^\s<>"']+)/g, (match) => {
        if (match.startsWith(workerOrigin)) return match; // Prevent double-proxying
        return `${workerOrigin}/${match}`;
      });
      
      // 2. Handle relative URLs
      text = text.split('\n').map(line => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('http')) {
          const absoluteUrl = new URL(trimmed, targetUrl).toString();
          return `${workerOrigin}/${absoluteUrl}`;
        }
        return line;
      }).join('\n');
      
      return res.status(response.status).set('Content-Type', 'application/vnd.apple.mpegurl').send(text);
    }

    // For non-m3u8 responses (e.g., video segments, images, etc.), pass them through normally
    // We pipe the response body directly to the client to save memory on large video chunks
    res.status(response.status);
    
    // Forward relevant headers
    if (response.headers.get('Content-Type')) res.set('Content-Type', response.headers.get('Content-Type'));
    if (response.headers.get('Content-Length')) res.set('Content-Length', response.headers.get('Content-Length'));
    
    // Pipe the readable stream directly to the response
    const reader = response.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(Buffer.from(value));
    }
    res.end();

  } catch (error) {
    console.error('Proxy Error:', error);
    if (!res.headersSent) {
      return res.status(500).send('Error: ' + error.message);
    }
  }
});

// Coolify sets the PORT environment variable automatically
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
});
