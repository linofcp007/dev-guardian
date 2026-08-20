const Fastify = require('fastify');
const fastify = Fastify({ logger: true });

// L10 shorthand (control, should match)
fastify.get('/f/health', async () => ({ ok: true }));

// L11 full route object — the canonical Fastify form
fastify.route({
  method: 'GET',
  url: '/f/orders',
  handler: async () => []
});

// L12 with options object
fastify.post('/f/orders', { schema: {} }, async () => ({}));

// L13 register a plugin with a prefix (Fastify's mount equivalent)
fastify.register(require('./orders'), { prefix: '/api' });
