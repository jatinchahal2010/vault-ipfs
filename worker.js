// Cloudflare Worker — VaultIPFS S3 CORS Proxy
// Deploy to: dash.cloudflare.com → Workers & Pages → Create Worker
// Free tier: 100,000 requests/day

export default {
  async fetch(request) {
    const origin = request.headers.get('Origin') || '';

    // Allow any origin from github.io, localhost, pages.dev, or any origin in dev
    const isAllowed = !origin || // no origin (non-browser)
      origin.includes('github.io') ||
      origin.includes('localhost') ||
      origin.includes('pages.dev') ||
      origin.includes('127.0.0.1');

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      const headers = new Headers();
      headers.set('Access-Control-Allow-Origin', isAllowed ? origin : '*');
      headers.set('Access-Control-Allow-Methods', 'GET, PUT, DELETE, OPTIONS');
      headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Amz-Date, X-Amz-Content-Sha256, X-Amz-Security-Token');
      headers.set('Access-Control-Max-Age', '86400');
      headers.set('Vary', 'Origin');
      return new Response(null, { status: 204, headers });
    }

    // Proxy the request to Filebase S3
    const url = new URL(request.url);
    const s3Path = url.pathname.replace(/^\/proxy/, '');
    const s3Url = 'https://s3.filebase.io' + s3Path + url.search;

    // Forward the request, stripping the Host header so S3 gets the right one
    const fwdHeaders = new Headers(request.headers);
    fwdHeaders.delete('Host');
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
      modifiedHeaders.set('Access-Control-Allow-Origin', isAllowed ? origin : '*');
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
          'Access-Control-Allow-Origin': isAllowed ? origin : '*'
        }
      });
    }
  }
};
