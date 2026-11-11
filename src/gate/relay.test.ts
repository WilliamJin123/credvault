import { createServer as httpServer, type IncomingMessage, type Server } from "node:http";
import { type AddressInfo, connect, createServer, type Server as NetServer } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { portFor, startRelay, upstreamOf } from "./relay.js";

const portOf = (s: Server | NetServer) => (s.address() as AddressInfo).port;
const listen = <T extends Server | NetServer>(s: T) =>
  new Promise<T>((r) => s.listen(0, "127.0.0.1", () => r(s)));

/** CONNECT through `relay` as `user`; the first line back and what the tunnel echoes. */
function tunnel(
  relay: number,
  target: string,
  user?: string,
): Promise<{ status: string; echo: string }> {
  return new Promise((resolve, reject) => {
    const s = connect(relay, "127.0.0.1");
    const auth = user
      ? `Proxy-Authorization: Basic ${Buffer.from(`${user}:x`).toString("base64")}\r\n`
      : "";
    let buf = "";
    let status = "";
    s.on("connect", () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}\r\n`));
    s.on("data", (d) => {
      buf += d.toString();
      if (!status && buf.includes("\r\n\r\n")) {
        status = buf.split(" ")[1] as string;
        buf = buf.slice(buf.indexOf("\r\n\r\n") + 4);
        if (status === "200") s.write("ping");
        else return resolve({ status, echo: "" });
      }
      if (status === "200" && buf.includes("ping")) {
        s.destroy();
        resolve({ status, echo: buf });
      }
    });
    s.on("error", reject);
  });
}

const open: (Server | NetServer)[] = [];
afterEach(() => {
  for (const s of open.splice(0)) s.close();
});

describe("read relay", () => {
  it("tunnels with the vendor login and suffix; the client never holds it", async () => {
    const echo = await listen(createServer((c) => c.pipe(c)));
    const seen: string[] = [];
    const vendor = await listen(
      httpServer().on("connect", (req: IncomingMessage, c, head) => {
        seen.push(req.headers["proxy-authorization"] as string);
        const t = connect(portOf(echo), "127.0.0.1", () => {
          c.write("HTTP/1.1 200 OK\r\n\r\n");
          if (head.length) t.write(head);
          t.pipe(c);
          c.pipe(t);
        });
      }),
    );
    const relay = await startRelay({
      port: 0,
      upstream: upstreamOf(`login:pass@127.0.0.1:${portOf(vendor)}`, "__cr.us"),
    });
    open.push(echo, vendor, relay);
    const r = await tunnel(portOf(relay), "www.youtube.com:443", "s1");
    expect(r).toEqual({ status: "200", echo: "ping" });
    expect(seen).toEqual([`Basic ${Buffer.from("login__cr.us:pass").toString("base64")}`]);
  });

  it("answers 502 when the vendor refuses our login", async () => {
    const vendor = await listen(
      httpServer().on("connect", (_req, c) => c.end("HTTP/1.1 407 Proxy Auth\r\n\r\n")),
    );
    const relay = await startRelay({
      port: 0,
      upstream: upstreamOf(`a:b@127.0.0.1:${portOf(vendor)}`),
    });
    open.push(vendor, relay);
    expect((await tunnel(portOf(relay), "example.com:443")).status).toBe("502");
  });

  it("pins a session to one sticky port; no session rotates", () => {
    const a = portFor("s1", 823, [10000, 20000]);
    expect(portFor("s1", 823, [10000, 20000])).toBe(a);
    expect(a).toBeGreaterThanOrEqual(10000);
    expect(a).toBeLessThanOrEqual(20000);
    expect(portFor(null, 823, [10000, 20000])).toBe(823);
  });
});
