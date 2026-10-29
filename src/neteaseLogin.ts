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
      const cookies = r.cookie?.length ? r.cookie.join(';') : r.body?.cookie;
      if (typeof cookies !== 'string' || !/(?:^|;)\s*MUSIC_U=[^;]+/.test(cookies)) throw new Error('invalid_session');
      const profile = await this.sdk.user_account({ cookie: cookies });
      const accountId = profile.body?.account?.id ?? profile.body?.profile?.userId;
      if (Number(profile.body?.code) !== 200 || !accountId) throw new Error('account_validation_failed');
      this.connected(cookies);
      this.account = { id: String(accountId), nickname: profile.body?.profile?.nickname ?? null };
      this.pending = null;
      return { loggedIn: true, account: this.account };
    } finally { this.busy = false; }
  }
}
