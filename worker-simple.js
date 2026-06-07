addEventListener('fetch', event => {
  event.respondWith(new Response('OK', { status: 200 }));
});
