// Cloudflare Worker — VaultIPFS S3 CORS Proxy
export default {
  async fetch(request) {
    const origin = request.headers.get('Origin') || '';

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Amz-Date, X-Amz-Content-Sha256, X-Amz-Security-Token',
          'Access-Control-Max-Age': '86400',
          'Vary': 'Origin'
        }
      });
    }

    // Health check at root
    const url = new URL(request.url);
    const s3Path = url.pathname.replace(/^\/proxy/, '');
    if (!s3Path || s3Path === '/') {
      return new Response('VaultIPFS CORS Proxy — OK', {
        status: 200,
        headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' }
      });
    }

    const s3Url = 'https://s3.filebase.io' + s3Path + url.search;

    // Forward the request with correct host header
    const fwdHeaders = new Headers(request.headers);
    fwdHeaders.set('Host', 's3.filebase.io');

    const proxyReq = new Request(s3Url, {
      method: request.method,
      headers: fwdHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined
    });

    try {
      const response = await fetch(proxyReq);

      // Clone response and add CORS headers
      const modifiedHeaders = new Headers(response.headers);
      modifiedHeaders.set('Access-Control-Allow-Origin', '*');
      modifiedHeaders.set('Access-Control-Expose-Headers', 'ETag, Content-Length, x-amz-request-id, x-amz-id-2');
      modifiedHeaders.set('Vary', 'Origin');

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: modifiedHeaders
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 502,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
  }
};
