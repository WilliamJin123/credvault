/**
 * The read relay: a loopback proxy that sends a sandboxed role's signed-out reads out through a
 * vendor proxy (residential), whose login stays in this process. The client's proxy user is a
 * session, not a secret: each session keeps one sticky vendor port (one exit IP), so a call's
 * requests share an IP. No user: the vendor's own port (rotation). TLS passes through untouched.
 */
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, request, type Server } from "node:http";
import { connect } from "node:net";
import type { Duplex } from "node:stream";

export interface RelayUpstream {
  host: string;
  /** The vendor's rotating port. */
  port: number;
  /** `Proxy-Authorization` for the vendor. */
  auth: string;
}

/** `login:pass@host:port` (scheme optional); `suffix` goes on the login (`__cr.us`). */
export function upstreamOf(proxy: string, suffix = ""): RelayUpstream {
  const u = new URL(proxy.includes("://") ? proxy : `http://${proxy}`);
  if (!u.username || !u.port) throw new Error("relay upstream needs login and port");
  const login = `${decodeURIComponent(u.username)}${suffix}`;
  const pass = decodeURIComponent(u.password);
  return {
    host: u.hostname,
    port: Number(u.port),
    auth: `Basic ${Buffer.from(`${login}:${pass}`).toString("base64")}`,
  };
}

/** The client's proxy user, or null. */
export function sessionOf(req: IncomingMessage): string | null {
  const h = req.headers["proxy-authorization"];
  const m = typeof h === "string" ? /^Basic\s+(\S+)/i.exec(h) : null;
  if (!m) return null;
  const user = Buffer.from(m[1] as string, "base64")
    .toString()
    .split(":")[0];
  return user || null;
}

/** One sticky port per session, stable for its life; no session: the rotating port. */
export function portFor(
  session: string | null,
  base: number,
  sticky?: readonly [number, number],
): number {
  if (!session || !sticky) return base;
  const [lo, hi] = sticky;
  return lo + (createHash("sha256").update(session).digest().readUInt32BE(0) % (hi - lo + 1));
}

const HEAD_MAX = 16 * 1024;
const IDLE_MS = 120_000;

/** Listens on 127.0.0.1:`port`. `onError`: one line per failed tunnel, never the login. */
export function startRelay(o: {
  port: number;
  upstream: RelayUpstream;
  sticky?: readonly [number, number];
  onError?: (why: string) => void;
}): Promise<Server> {
  const up = o.upstream;
  const fail = o.onError ?? (() => {});
  const server = createServer((req, res) => {
    // plain http: the absolute URL goes to the vendor as a proxy request
    if (!/^http:\/\//i.test(req.url ?? "")) {
      res.writeHead(400).end("read relay: proxy requests only\n");
      return;
    }
    const headers = { ...req.headers };
    delete headers["proxy-authorization"];
    delete headers["proxy-connection"];
    const out = request(
      {
        host: up.host,
        port: portFor(sessionOf(req), up.port, o.sticky),
        method: req.method,
        path: req.url,
        headers: { ...headers, "proxy-authorization": up.auth },
      },
      (r) => {
        res.writeHead(r.statusCode ?? 502, r.headers);
        r.pipe(res);
      },
    );
    out.on("error", (err) => {
      fail(`http ${req.url}: ${err.message}`);
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.pipe(out);
  });

  server.on("connect", (req: IncomingMessage, client: Duplex, head: Buffer) => {
    const target = req.url ?? "";
    const s = connect(portFor(sessionOf(req), up.port, o.sticky), up.host);
    s.setTimeout(IDLE_MS, () => s.destroy());
    const close = () => {
      s.destroy();
      client.destroy();
    };
    s.on("error", (err) => {
      fail(`connect ${target}: ${err.message}`);
      if (client.writable) client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    });
    client.on("error", close);
    s.once("connect", () =>
      s.write(
        `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: ${up.auth}\r\n\r\n`,
      ),
    );
    let buf = Buffer.alloc(0);
    const onHead = (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) {
        if (buf.length > HEAD_MAX) close();
        return;
      }
      s.off("data", onHead);
      const status = buf.subarray(0, end).toString().split(" ")[1] ?? "";
      if (status !== "200") {
        fail(`connect ${target}: vendor ${status}`);
        // a 407 is our login, not the client's: never ask the client to sign in
        client.end(`HTTP/1.1 ${status === "407" ? "502" : status || "502"} Relay Upstream\r\n\r\n`);
        s.destroy();
        return;
      }
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      const rest = buf.subarray(end + 4);
      if (rest.length) client.write(rest);
      if (head.length) s.write(head);
      s.pipe(client);
      client.pipe(s);
    };
    s.on("data", onHead);
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(o.port, "127.0.0.1", () => resolve(server));
  });
}
