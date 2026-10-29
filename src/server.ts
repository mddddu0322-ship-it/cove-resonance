import { NeteaseLogin, ownerAuthorized } from "./neteaseLogin.js";
import { loginPage } from "./loginPage.js";
import { randomBytes, randomUUID } from "node:crypto";
import { chmodSync, existsSync, unlinkSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createMcpServer } from "./mcp.js";
import { buildBridgeEvent } from "./bridge/events.js";
export { buildBridgeEvent } from "./bridge/events.js";
import { MCP_PATHS } from "./profiles.js";
import { listenerWakeHub } from "./listenerWake.js";
import { PlaybackStateStore } from "./netease/playbackState.js";
import { createTogetherWorker } from "./netease/togetherWorker.js";
import { InMemoryEventQueue } from "./queue.js";

const PORT = Number(process.env.PORT ?? 8787);
const INGEST_TOKEN = process.env.BRIDGE_INGEST_TOKEN ?? "";
const UNIX_SOCKET = process.env.BRIDGE_UNIX_SOCKET?.trim() ?? "";
const queue = new InMemoryEventQueue();
const playbackState = new PlaybackStateStore();

function enqueueTogetherEvent(
  source: string,
  text: string,
  additionalModelContext?: string,
): boolean {
  const id = randomUUID();
  const created = queue.enqueue(buildBridgeEvent(
    id,
    source,
    text,
    new Date().toISOString(),
    additionalModelContext,
  ));
  if (created) listenerWakeHub.wake(source);
  return created;
}

let togetherWorker = createTogetherWorker(enqueueTogetherEvent, playbackState);

const OWNER_KEY = process.env.COVE_ACCESS_KEY ?? "";
const LOGIN_KEY = process.env.COVE_LOGIN_KEY ?? "";
const login = new NeteaseLogin((cookie) => {
  if (togetherWorker.getStatus().enabled) throw new Error("account_already_configured");
  process.env.NETEASE_COOKIE = cookie;
  process.env.TOGETHER_ENABLED = "true";
  togetherWorker = createTogetherWorker(enqueueTogetherEvent, playbackState);
  togetherWorker.start();
});

const eventInput = z.object({
  eventId: z.string().trim().min(1).max(200).optional(),
  source: z.string().trim().min(1).max(80).default("test"),
  text: z.string().trim().min(1).max(4000),
});

function writeJson(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(value));
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 64 * 1024) throw new Error("request_too_large");
    chunks.push(buffer);
  }
  const body = Buffer.concat(chunks).toString("utf8");
  return body ? JSON.parse(body) : {};
}

function authorized(req: IncomingMessage): boolean {
  return OWNER_KEY ? ownerAuthorized(req.headers.authorization, OWNER_KEY) : (!INGEST_TOKEN || req.headers.authorization === `Bearer ${INGEST_TOKEN}`);
}

export function createHttpServer() {
  return createServer(async (req, res) => {
    if (!req.url || !req.method) {
      res.writeHead(400).end("Bad Request");
      return;
    }
    const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);

    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, GET, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "content-type, authorization, mcp-session-id",
        "Access-Control-Expose-Headers": "Mcp-Session-Id",
      });
      res.end();
      return;
    }

    if (req.method === "GET" && url.pathname === "/") {
      writeJson(res, 200, {
        ok: true,
        service: "cove-bridge",
        version: "0.1.0",
        queue: queue.status(),
        listener: listenerWakeHub.status(),
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/login") {
      const nonce = randomBytes(18).toString("base64");
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      });
      res.end(loginPage(nonce)); return;
    }

    if (req.method === "GET" && url.pathname === "/listener/events") {
      const authorization = req.headers.authorization ?? "";
      const bearerToken = authorization.startsWith("Bearer ")
        ? authorization.slice("Bearer ".length).trim()
        : "";
      const token = bearerToken || url.searchParams.get("session")?.trim() || "";
      const session = token ? listenerWakeHub.consumeSession(token) : null;
      if (!session) {
        writeJson(res, 401, { error: "invalid_or_expired_listener_session" });
        return;
      }
      listenerWakeHub.subscribe(res, session.expiresAtMs);
      return;
    }

    if (req.method === "POST" && url.pathname === "/events") {
      if (!authorized(req)) {
        writeJson(res, 401, { error: "unauthorized" });
        return;
      }
      try {
        const parsed = eventInput.safeParse(await readJson(req));
        if (!parsed.success) {
          writeJson(res, 400, { error: parsed.error.flatten() });
          return;
        }
        const createdAt = new Date().toISOString();
        const id = parsed.data.eventId ?? randomUUID();
        const event = buildBridgeEvent(id, parsed.data.source, parsed.data.text, createdAt);
        const created = queue.enqueue(event);
        if (created) listenerWakeHub.wake(parsed.data.source);
        writeJson(res, created ? 201 : 200, { ok: true, created, eventId: id });
      } catch (error) {
        const message = error instanceof Error ? error.message : "invalid_request";
        writeJson(res, message === "request_too_large" ? 413 : 400, { error: message });
      }
      return;
    }

    if (url.pathname.startsWith("/admin/login/")) {
      res.setHeader("Cache-Control", "no-store");
      if (!ownerAuthorized(req.headers.authorization, OWNER_KEY) && !ownerAuthorized(req.headers.authorization, LOGIN_KEY)) {
        writeJson(res, 401, { error: "unauthorized" });
        return;
      }
      if (req.headers.origin && req.headers.origin !== process.env.BRIDGE_PUBLIC_ORIGIN) {
        writeJson(res, 403, { error: "origin_rejected" }); return;
      }
      if (req.method !== "POST") { writeJson(res, 405, { error: "method_not_allowed" }); return; }
      try {
        if (url.pathname === "/admin/login/start") {
          writeJson(res, 200, await login.start());
        } else if (url.pathname === "/admin/login/check") {
          const body = await readJson(req) as { session?: unknown };
          writeJson(res, 200, await login.check(typeof body.session === "string" ? body.session : ""));
        } else if (url.pathname === "/admin/login/sms/send") {
          const b = await readJson(req) as Record<string, unknown>;
          writeJson(res, 200, await login.sendSms(b.phone, b.country));
        } else if (url.pathname === "/admin/login/sms/confirm") {
          const b = await readJson(req) as Record<string, unknown>;
          writeJson(res, 200, await login.loginSms(b.phone, b.country, b.captcha));
        } else if (url.pathname === "/admin/login/status") {
          writeJson(res, 200, login.status());
        } else { writeJson(res, 404, { error: "not_found" }); }
      } catch (error) {
        const name = error instanceof Error ? error.message : "";
        const safeErrors = ["sms_rate_limited", "sms_session_expired", "sms_attempts_exceeded", "invalid_phone", "invalid_captcha", "login_busy"];
        if (safeErrors.includes(name)) { writeJson(res, name === "sms_rate_limited" ? 429 : 400, { error: name }); return; }
        // Never relay provider errors or response headers/cookies to the client or logs.
        writeJson(res, 502, { error: "netease_login_unavailable" });
      }
      return;
    }

    const mcpMethods = new Set(["POST", "GET", "DELETE"]);
    const mcpProfile = MCP_PATHS.get(url.pathname);
    if (mcpProfile && mcpMethods.has(req.method)) {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
      if (OWNER_KEY && !ownerAuthorized(req.headers.authorization, OWNER_KEY)) {
        res.setHeader("WWW-Authenticate", 'Bearer realm="cove-resonance"');
        writeJson(res, 401, { error: "unauthorized" });
        return;
      }
      const server = createMcpServer(queue, playbackState, togetherWorker, mcpProfile);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      try {
        await server.connect(transport);
        await transport.handleRequest(req, res);
      } catch (error) {
        console.error("MCP request failed", error);
        if (!res.headersSent) writeJson(res, 500, { error: "internal_server_error" });
      }
      return;
    }

    res.writeHead(404).end("Not Found");
  });
}

if (process.env.NODE_ENV !== "test") {
  createHttpServer().listen(PORT, "0.0.0.0", () => {
    console.log("Cove Resonance listening on http://0.0.0.0:" + PORT + " (MCP: /mcp, /mcp/music)");
    togetherWorker.start();
  });

  if (UNIX_SOCKET) {
    if (existsSync(UNIX_SOCKET)) unlinkSync(UNIX_SOCKET);
    createHttpServer().listen(UNIX_SOCKET, () => {
      chmodSync(UNIX_SOCKET, 0o666);
      console.log("Cove Resonance listening on unix://" + UNIX_SOCKET + " (MCP: /mcp, /mcp/music)");
    });
  }
}
