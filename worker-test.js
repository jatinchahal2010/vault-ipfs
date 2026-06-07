addEventListener('fetch', event => {
  event.respondWith(handle(event.request));
});

async function handle(request) {
  const url = new URL(request.url);
  if (url.pathname === '/') {
    return new Response('VaultIPFS Proxy OK', {
      headers: { 'Access-Control-Allow-Origin': '*' }
    });
  }
  return new Response('Not found: ' + url.pathname, {
    status: 404,
    headers: { 'Access-Control-Allow-Origin': '*' }
  });
}
