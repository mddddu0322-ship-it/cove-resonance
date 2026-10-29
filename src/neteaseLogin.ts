import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createRequire } from 'node:module';

type Result = { body?: any; cookie?: string[] };
type Api = Record<string, (args: Record<string, unknown>) => Promise<Result>>;
const require = createRequire(import.meta.url);
const api = require('NeteaseCloudMusicApi') as Api;

export function ownerAuthorized(header: string | undefined, key: string): boolean {
  if (key.length < 32 || !header?.startsWith('Bearer ')) return false;
  const actual = Buffer.from(header.slice(7));
  const expected = Buffer.from(key);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

// Cookie and QR provider keys stay inside this server-side adapter.
export class NeteaseLogin {
  private pending: { id: string; key: string; qrimg: string; expires: number } | null = null;
  private account: { id: string; nickname: string | null } | null = null;
  private busy = false;
  private sms: { phone: string; country: string; expires: number; attempts: number } | null = null;
  private sentAt: number[] = [];
  status() { return { loggedIn: Boolean(this.account), account: this.account }; }
  private validatePhone(phone: unknown, country: unknown) {
    if (typeof phone !== 'string' || !/^\d{5,15}$/.test(phone) || typeof country !== 'string' || !/^\d{1,3}$/.test(country)) throw new Error('invalid_phone');
    return { phone, country };
  }
  async sendSms(phone: unknown, country: unknown) {
    const input = this.validatePhone(phone, country);
    if (this.account) return this.status();
    if (this.busy) throw new Error('login_busy');
    const now = this.now();
    this.sentAt = this.sentAt.filter(t => now - t < 3600_000);
    if (this.sentAt.length >= 5 || (this.sentAt.length && now - this.sentAt[this.sentAt.length - 1] < 60_000)) throw new Error('sms_rate_limited');
    this.sentAt.push(now);
    this.sms = null;
    this.busy = true;
    try {
      const result = await this.sdk.captcha_sent({ phone: input.phone, ctcode: input.country });
      const code = Number(result.body?.code);
      if (code !== 200) return { sent: false, code: Number.isFinite(code) ? code : 502 };
      this.sms = { ...input, expires: now + 300_000, attempts: 0 };
      return { sent: true, retryAfter: 60 };
    } catch { return { sent: false, code: 502 }; }
    finally { this.busy = false; }
  }
  async loginSms(phone: unknown, country: unknown, captcha: unknown) {
    const input = this.validatePhone(phone, country);
    if (typeof captcha !== 'string' || !/^\d{4,8}$/.test(captcha)) throw new Error('invalid_captcha');
    if (this.account) return this.status();
    if (!this.sms || this.sms.phone !== input.phone || this.sms.country !== input.country || this.sms.expires <= this.now()) throw new Error('sms_session_expired');
    if (this.sms.attempts >= 5) throw new Error('sms_attempts_exceeded');
    if (this.busy) throw new Error('login_busy');
    this.sms.attempts++;
    this.busy = true;
    try {
      let result: Result;
      try { result = await this.sdk.login_cellphone({ phone: input.phone, countrycode: input.country, captcha }); }
      catch { return { loggedIn: false, code: 502 }; }
      const code = Number(result.body?.code);
      if (code !== 200) return { loggedIn: false, code: Number.isFinite(code) ? code : 502 };
      const connected = await this.acceptCookie(result);
      this.sms = null;
      return connected;
    } finally { this.busy = false; }
  }
  private async acceptCookie(r: Result) {
    const cookies = r.cookie?.length ? r.cookie.join(';') : r.body?.cookie;
    if (typeof cookies !== 'string' || !/(?:^|;)\s*MUSIC_U=[^;]+/.test(cookies)) throw new Error('invalid_session');
    const profile = await this.sdk.user_account({ cookie: cookies });
    const accountId = profile.body?.account?.id ?? profile.body?.profile?.userId;
    if (Number(profile.body?.code) !== 200 || !accountId) throw new Error('account_validation_failed');
    this.connected(cookies);
    this.account = { id: String(accountId), nickname: profile.body?.profile?.nickname ?? null };
    this.pending = null;
    return { loggedIn: true, account: this.account };
  }
  constructor(
    private readonly connected: (cookie: string) => void,
    private readonly sdk: Api = api,
    private readonly now: () => number = Date.now,
  ) {}
  async start() {
    if (this.account) return { loggedIn: true, account: this.account };
    if (this.busy) throw new Error('login_busy');
    if (this.pending && this.pending.expires > this.now()) return this.view();
    this.busy = true;
    try {
      const r = await this.sdk.login_qr_key({ timestamp: this.now() });
      const key = r.body?.data?.unikey;
      if (typeof key !== 'string' || !key) throw new Error('qr_unavailable');
      const q = await this.sdk.login_qr_create({ key, qrimg: true });
      const qrimg = q.body?.data?.qrimg;
      if (typeof qrimg !== 'string' || !qrimg.startsWith('data:image/png;base64,')) throw new Error('qr_unavailable');
      this.pending = { id: randomBytes(24).toString('base64url'), key, qrimg, expires: this.now() + 120_000 };
      return this.view();
    } finally { this.busy = false; }
  }
  private view() {
    return { loggedIn: false, session: this.pending!.id, qrimg: this.pending!.qrimg, expiresAt: new Date(this.pending!.expires).toISOString() };
  }
  async check(id: string) {
    if (this.account) return { loggedIn: true, account: this.account };
    if (!this.pending || this.pending.id !== id || this.pending.expires <= this.now()) return { loggedIn: false, code: 800 };
    if (this.busy) return { loggedIn: false, code: 801 };
    this.busy = true;
    try {
      const r = await this.sdk.login_qr_check({ key: this.pending.key, timestamp: this.now() });
      const code = Number(r.body?.code);
      if (code !== 803) return { loggedIn: false, code: [800, 801, 802].includes(code) ? code : 502 };
      return await this.acceptCookie(r);
    } finally { this.busy = false; }
  }
}
