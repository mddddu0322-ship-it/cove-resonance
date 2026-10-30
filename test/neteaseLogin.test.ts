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

test('SMS login binds the phone, validates account and never returns a cookie', async () => {
  let sent=0, confirmed=0, connections=0;
  const login=new NeteaseLogin(()=>{connections++;},{
    captcha_sent:async()=>{sent++;return{body:{code:200}};},
    login_cellphone:async args=>{confirmed++;assert.equal(args.captcha,'123456');return{body:{code:200},cookie:['MUSIC_U=secret-session']};},
    user_account:async()=>({body:{code:200,account:{id:42},profile:{nickname:'test'}}}),
  });
  assert.equal((await login.sendSms('15500000000','86') as any).sent,true);
  await assert.rejects(login.sendSms('15500000000','86'),/sms_rate_limited/);
  await assert.rejects(login.loginSms('15500000001','86','123456'),/sms_session_expired/);
  assert.equal(confirmed,0);
  const result=await login.loginSms('15500000000','86','123456');
  assert.equal(result.loggedIn,true);
  assert.equal(JSON.stringify(result).includes('secret-session'),false);
  await login.loginSms('15500000000','86','123456');
  assert.equal(sent,1);assert.equal(confirmed,1);assert.equal(connections,1);
});
test('SMS blocks invalid input, expired sessions and excessive attempts', async () => {
  let now=0, calls=0;
  const login=new NeteaseLogin(()=>{}, {
    captcha_sent:async()=>({body:{code:200}}),
    login_cellphone:async()=>{calls++;return{body:{code:503,cookie:'MUSIC_U=must-not-leak'}};},
  },()=>now);
  await assert.rejects(login.sendSms('bad','86'),/invalid_phone/);
  await login.sendSms('15500000000','86');
  for(let i=0;i<5;i++)assert.equal((await login.loginSms('15500000000','86','123456') as any).code,503);
  await assert.rejects(login.loginSms('15500000000','86','123456'),/sms_attempts_exceeded/);
  now=300001;
  await assert.rejects(login.loginSms('15500000000','86','123456'),/sms_session_expired/);
  assert.equal(calls,5);
});
test('failed SMS send consumes cooldown and does not permit confirmation', async()=>{
  const login=new NeteaseLogin(()=>{}, {captcha_sent:async()=>({body:{code:405}})});
  assert.equal((await login.sendSms('15500000000','86') as any).sent,false);
  await assert.rejects(login.sendSms('15500000000','86'),/sms_rate_limited/);
  await assert.rejects(login.loginSms('15500000000','86','123456'),/sms_session_expired/);
});

test('SDK security rejection preserves code, hides sensitive fields and ends SMS session', async()=>{
  let confirmations=0;
  const login=new NeteaseLogin(()=>{assert.fail('must not connect');},{
    captcha_sent:async()=>({body:{code:200}}),
    login_cellphone:async()=>{confirmations++;throw {status:400,body:{code:10004,message:'private provider details',cookie:'MUSIC_U=private'},cookie:['private']};},
  });
  await login.sendSms('15500000000','86');
  assert.deepEqual(await login.loginSms('15500000000','86','123456'),{loggedIn:false,code:10004,reason:'security_check'});
  await assert.rejects(login.loginSms('15500000000','86','123456'),/sms_session_expired/);
  assert.equal(confirmations,1);
});

test('SMS transport failure does not claim captcha was incorrect',async()=>{
  const login=new NeteaseLogin(()=>{}, {captcha_sent:async()=>{throw new Error('private network details');}});
  assert.deepEqual(await login.sendSms('15500000000','86'),{sent:false,code:502,reason:'upstream_unavailable'});
});
