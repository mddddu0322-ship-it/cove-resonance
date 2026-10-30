import test from 'node:test';
import assert from 'node:assert/strict';
import { Script } from 'node:vm';
import { loginPage } from '../src/loginPage.js';
test('login page script parses and includes no persistent credential storage',()=>{
  const html=loginPage('test-nonce');
  const script=html.match(/<script nonce="test-nonce">([\s\S]*?)<\/script>/)![1];
  assert.doesNotThrow(()=>new Script(script));
  assert.equal(/localStorage|sessionStorage|document.cookie/.test(script),false);
  assert.match(html,/autocomplete="one-time-code"/);
});
