/**
 * The key gate process: plans from the sources, writes each role's env file
 * (sentinels), starts mitmdump with one listener per keyed role, hands the map
 * to the addon over fd 3 and audits each swap or refusal it reports on fd 4.
 * Real values live in this process and the addon only.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import { fileAudit, type SecretAudit } from "../audit.js";
import { keychainKey } from "../cipher.js";
import { parseDotenv, toDotenv } from "../env-store.js";
import {
  allowHostsRegex,
  type GateConfig,
  type GatePlan,
  gateConfigSchema,
  layer,
  planGate,
} from "./plan.js";
import { startRelay, upstreamOf } from "./relay.js";

/** Shipped beside dist: `<package>/gate/addon.py`. */
const ADDON = new URL("../../gate/addon.py", import.meta.url).pathname;
const CA_CERT = "mitmproxy-ca-cert.pem";
/** macOS's roots; Python and curl read `SSL_CERT_FILE` as the whole store, so the bundle adds the gate CA to them. */
const SYSTEM_ROOTS = "/etc/ssl/cert.pem";

export interface GateEvent {
  t: "use" | "deny";
  role: string | null;
  host: string;
  path: string;
  /** The key's name; none for an unknown sentinel. */
  name?: string | null;
  /** The role the key belongs to (differs from `role` on a refusal). */
  key_role?: string | null;
  why?: string;
}

async function writePrivate(path: string, text: string): Promise<void> {
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, text, { mode: 0o600 });
  await rename(tmp, path);
}

export async function loadGateConfig(path: string): Promise<GateConfig> {
  return gateConfigSchema.parse(JSON.parse(await readFile(path, "utf8")));
}

export async function readSources(paths: string[]): Promise<Map<string, string>> {
  const read = (p: string) => (existsSync(p) ? readFileSync(p, "utf8") : null);
  return layer(
    await Promise.all(
      paths.map(async (p) => {
        if (!existsSync(p)) throw new Error(`gate source ${p} is missing`);
        return parseDotenv(await readFile(p, "utf8"), read);
      }),
    ),
  );
}

/** `<dir>/<role>.env` per role, 0600. */
export async function writeRoleFiles(dir: string, plan: GatePlan): Promise<string[]> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await chmod(dir, 0o700);
  const out: string[] = [];
  for (const [role, entries] of plan.files) {
    const path = join(dir, `${role}.env`);
    await writePrivate(path, toDotenv(entries));
    out.push(path);
  }
  return out;
}

/** The audit line for one addon event. No value, no query. */
export function auditLine(e: GateEvent, plan: GatePlan): Parameters<SecretAudit["record"]>[0] {
  const name = e.name ?? "unknown";
  const k = [...plan.keys.values()].find((x) => x.name === name && x.role === e.key_role);
  return {
    at: new Date().toISOString(),
    credential: name,
    field: "secret",
    site: k?.site ?? e.host,
    url: `https://${e.host}${e.path}`,
    by: `gate:${e.role ?? "?"}`,
    allowed: e.t === "use",
    owner: "wren",
    ...(k ? { keyId: k.keyId } : {}),
    ...(e.why ? { reason: e.why } : {}),
  };
}

export interface RunningGate {
  child: ChildProcess;
  plan: GatePlan;
  /** Resolves with the child's exit code. */
  done: Promise<number>;
  stop(): void;
}

export interface GateOptions {
  /** Defaults to the config's Keychain item. */
  gateKey?: Buffer;
  audit?: SecretAudit;
  /** A refused sentinel: a canary. Default: one stderr line. */
  onDeny?: (e: GateEvent) => void;
}

/** Writes the role files and the CA bundle, starts mitmdump; returns once it runs. */
export async function gate(config: GateConfig, o: GateOptions = {}): Promise<RunningGate> {
  const { service, account } = config.keychain;
  const key = o.gateKey ?? keychainKey(account ? { service, account } : { service });
  const values = await readSources(config.sources);
  const plan = planGate(config, values, key);
  const relay = config.relay ? await relayOf(config.relay, values) : null;
  await writeRoleFiles(config.dir, plan);
  const confdir = join(config.dir, "ca");
  await mkdir(confdir, { recursive: true, mode: 0o700 });

  const keyed = Object.entries(config.roles).filter(([role]) =>
    [...plan.keys.values()].some((k) => k.role === role),
  );
  if (!keyed.length) throw new Error("no role holds a key: nothing to gate");
  const args = [
    "-q",
    ...keyed.flatMap(([, r]) => ["--mode", `upstream:${r.upstream}@127.0.0.1:${r.port}`]),
    "--set",
    `confdir=${confdir}`,
    "--set",
    `allow_hosts=${allowHostsRegex(plan.hosts)}`,
    "--set",
    "termlog_verbosity=warn",
    "--set",
    "flow_detail=0",
    "-s",
    ADDON,
  ];
  const child = spawn(config.mitmdump, args, {
    stdio: ["ignore", "inherit", "inherit", "pipe", "pipe"],
  });
  const map = {
    ports: Object.fromEntries(keyed.map(([role, r]) => [String(r.port), role])),
    keys: Object.fromEntries(
      [...plan.keys].map(([s, k]) => [
        s,
        { role: k.role, name: k.name, value: k.value, hosts: k.hosts },
      ]),
    ),
  };
  (child.stdio[3] as Writable).end(JSON.stringify(map));

  const audit = o.audit ?? fileAudit(config.audit);
  const onDeny =
    o.onDeny ??
    ((e: GateEvent) =>
      console.error(
        `credvault gate: ALERT ${e.name ?? "unknown sentinel"} refused on ${e.host}${e.path} (role ${e.role}): ${e.why}`,
      ));
  createInterface({ input: child.stdio[4] as Readable }).on("line", (line) => {
    let e: GateEvent;
    try {
      e = JSON.parse(line) as GateEvent;
    } catch {
      return;
    }
    if (e.t === "deny") onDeny(e);
    void audit
      .record(auditLine(e, plan))
      .catch((err) => console.error(`credvault gate: audit failed: ${(err as Error).message}`));
  });

  const done = new Promise<number>((resolve) => child.on("exit", (code) => resolve(code ?? 1)));
  await waitFor(() => existsSync(join(confdir, CA_CERT)), done, "the gate CA");
  await writeBundle(config.dir, confdir);
  for (const [role, r] of keyed) await waitPort(r.port, done, `role ${role}`);
  return {
    child,
    plan,
    done,
    stop: () => {
      relay?.close();
      child.kill("SIGTERM");
    },
  };
}

async function relayOf(r: NonNullable<GateConfig["relay"]>, values: Map<string, string>) {
  const proxy = values.get(r.key);
  if (!proxy) throw new Error(`relay: ${r.key} is in no source`);
  const sticky = r.sticky?.split("-").map(Number) as [number, number] | undefined;
  return startRelay({
    port: r.port,
    upstream: upstreamOf(proxy, r.suffix),
    ...(sticky ? { sticky } : {}),
    onError: (why) => console.error(`credvault gate: relay ${why}`),
  });
}

/** `<dir>/ca.pem` (the gate CA, for `NODE_EXTRA_CA_CERTS`) and `<dir>/ca-bundle.pem` (system roots + it). */
async function writeBundle(dir: string, confdir: string): Promise<void> {
  const ca = await readFile(join(confdir, CA_CERT), "utf8");
  const roots = existsSync(SYSTEM_ROOTS) ? await readFile(SYSTEM_ROOTS, "utf8") : "";
  await writeFile(join(dir, "ca.pem"), ca, { mode: 0o644 });
  await writeFile(join(dir, "ca-bundle.pem"), `${roots.trimEnd()}\n${ca}`, { mode: 0o644 });
}

async function waitFor(ok: () => boolean, died: Promise<number>, what: string): Promise<void> {
  let dead = false;
  void died.then(() => {
    dead = true;
  });
  for (let i = 0; i < 300; i++) {
    if (ok()) return;
    if (dead) throw new Error(`mitmdump exited before ${what} was ready`);
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${what} not ready after 30 s`);
}

async function waitPort(port: number, died: Promise<number>, what: string): Promise<void> {
  let dead = false;
  void died.then(() => {
    dead = true;
  });
  const probe = () =>
    new Promise<boolean>((resolve) => {
      const s = connect(port, "127.0.0.1");
      s.once("connect", () => {
        s.destroy();
        resolve(true);
      });
      s.once("error", () => resolve(false));
    });
  for (let i = 0; i < 300; i++) {
    if (await probe()) return;
    if (dead) throw new Error(`mitmdump exited before ${what} listened`);
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${what}: port ${port} not listening after 30 s`);
}
