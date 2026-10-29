import test from 'node:test';
import assert from 'node:assert/strict';
import { NeteaseLogin, ownerAuthorized } from '../src/neteaseLogin.js';

test('owner access is fail-closed and rejects missing/wrong bearer', () => {
  const key = 'a'.repeat(40);
  assert.equal(ownerAuthorized(undefined, key), false);
  assert.equal(ownerAuthorized('Bearer '+key, ''), false);
  assert.equal(ownerAuthorized('Bearer '+key+'a', key), false);
  assert.equal(ownerAuthorized('Bearer '+key, key), true);
});
test('QR login hides provider keys, validates account, and connects exactly once', async () => {
  let connected = 0, checks = 0;
  const sdk = {
    login_qr_key: async () => ({ body: { data: { unikey: 'provider-secret' } } }),
    login_qr_create: async () => ({ body: { data: { qrimg: 'data:image/png;base64,test' } } }),
    login_qr_check: async () => { checks++; return { body: { code: 803 }, cookie: ['MUSIC_U=private-session'] }; },
    user_account: async () => ({ body: { code: 200, account: { id: 123 }, profile: { nickname: 'test' } } }),
  };
  const login = new NeteaseLogin(c => { assert.equal(c,'MUSIC_U=private-session'); connected++; }, sdk);
  const start = await login.start();
  assert.equal(JSON.stringify(start).includes('provider-secret'), false);
  assert.equal((await login.start() as any).session, (start as any).session);
  const result = await login.check((start as any).session);
  assert.equal(result.loggedIn, true);
  assert.equal(JSON.stringify(result).includes('private-session'), false);
  await login.check((start as any).session);
  assert.equal(connected, 1); assert.equal(checks, 1);
});
test('expired or unrelated QR session never contacts provider', async () => {
  let now = 0, checks = 0;
  const login = new NeteaseLogin(() => {}, {
    login_qr_key: async () => ({body:{data:{unikey:'secret'}}}),
    login_qr_create: async () => ({body:{data:{qrimg:'data:image/png;base64,test'}}}),
    login_qr_check: async () => { checks++; return {}; },
  }, () => now);
  const start = await login.start() as any;
  await login.check('wrong'); now = 120001;
  assert.equal((await login.check(start.session) as any).code,800);
  assert.equal(checks,0);
});
