import test from 'node:test';
import assert from 'node:assert/strict';
process.env.NODE_ENV = 'test';
process.env.COVE_ACCESS_KEY = 'test-owner-'.repeat(5);
const { createHttpServer } = await import('../src/server.js');

test('account HTTP endpoints require owner authorization before any provider request', async () => {
  const server = createHttpServer();
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as { port: number };
  const base = `http://127.0.0.1:${address.port}`;
  try {
    for (const path of ['/mcp','/mcp/music','/admin/login/start','/admin/login/check','/events']) {
      const r = await fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
      assert.equal(r.status,401,path);
    }
    const r = await fetch(base+'/admin/login/check',{
      method:'POST',headers:{authorization:`Bearer ${process.env.COVE_ACCESS_KEY}`,'content-type':'application/json'},body:'{"session":"unrelated"}',
    });
    assert.equal(r.status,200);
    assert.equal((await r.json() as any).code,800);
    const publicHealth = await fetch(base+'/'); assert.equal(publicHealth.status,200);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
