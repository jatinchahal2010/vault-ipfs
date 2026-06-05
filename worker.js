// Cloudflare Worker — VaultIPFS S3 CORS Proxy
// Deploy to: dash.cloudflare.com → Workers & Pages → Create Worker
// Free tier: 100,000 requests/day

export default {
  async fetch(request) {
    // Only allow requests from your GitHub Pages site
    const origin = request.headers.get('Origin') || '';
    const allowedOrigins = [
      'https://jatinchahal2010.github.io',
      'http://localhost:8000'
    ];
    
    if (!allowedOrigins.includes(origin)) {
      return new Response('Forbidden', { status: 403 });
    }

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'GET, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Amz-Date, X-Amz-Content-Sha256',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    // Proxy the request to Filebase S3
    const url = new URL(request.url);
    const s3Path = url.pathname.replace(/^\/proxy/, '');
    const s3Url = 'https://s3.filebase.io' + s3Path + url.search;

    const proxyReq = new Request(s3Url, {
      method: request.method,
      headers: request.headers,
      body: request.body
    });

    const response = await fetch(proxyReq);
    
    // Clone response and add CORS headers
    const modified = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });

    modified.headers.set('Access-Control-Allow-Origin', origin);
    modified.headers.set('Access-Control-Expose-Headers', 'ETag, Content-Length');

    return modified;
  }
};
