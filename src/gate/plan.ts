/**
 * The key gate's plan: which names each role holds, as stand-ins (sentinels)
 * or as plain values, and the sentinel → real key map the proxy addon swaps
 * from. Pure: the gate key and the source entries come in, nothing is read here.
 */
import { createHmac } from "node:crypto";
import { z } from "zod";
import { ENV_KEY, type EnvEntry } from "../env-store.js";
import { keyId, parseVendorKeyName } from "../keys.js";

/** Where each vendor's keys may go. A key whose vendor is not here needs a `hosts` entry in the config. */
export const VENDOR_HOSTS: Readonly<Record<string, readonly string[]>> = {
  anthropic: ["api.anthropic.com"],
  cerebras: ["api.cerebras.ai"],
  cohere: ["api.cohere.com", "api.cohere.ai"],
  exa: ["api.exa.ai"],
  gemini: ["generativelanguage.googleapis.com"],
  groq: ["api.groq.com"],
  mistral: ["api.mistral.ai"],
  openai: ["api.openai.com"],
  openalex: ["api.openalex.org"],
  openrouter: ["openrouter.ai"],
  perplexity: ["api.perplexity.ai"],
  typesafe: ["api.typesafe.ai"],
  youtube: ["www.googleapis.com", "youtube.googleapis.com"],
};

/** `wsk_` + 28 base32 characters: what a process holds in place of a key. */
export const SENTINEL = /wsk_[a-z2-7]{28}/g;

const HOST = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
/** A name, or a name with `*` in it (`EXA_API_KEY*`). */
const NAME_GLOB = /^[A-Z*][A-Z0-9_*]*$/;

const roleSchema = z.object({
  /** The port this role's processes send through (`HTTPS_PROXY`). */
  port: z.number().int().min(1024).max(65535),
  /** The role's own egress proxy (smokescreen): every request leaves through it. */
  upstream: z.string().url(),
  /** Names the role holds as sentinels. */
  keys: z.array(z.string().regex(NAME_GLOB)).default([]),
  /** Names the role holds as they are (`NUM_EXA`, a URL). Never a key. */
  plain: z.array(z.string().regex(NAME_GLOB)).default([]),
});

export const gateConfigSchema = z.object({
  /** Where the role env files, the CA and its bundle go. 0700. */
  dir: z.string().min(1),
  /** The `mitmdump` binary (a pinned venv). */
  mitmdump: z.string().min(1),
  /** The hash-chained audit file (`fileAudit`). */
  audit: z.string().min(1),
  /** The Keychain item that holds the gate key: sentinels are an HMAC of it. */
  keychain: z.object({ service: z.string().min(1), account: z.string().optional() }).default({
    service: "credvault-gate",
  }),
  /** Env files with the real values. An earlier file wins a name. */
  sources: z.array(z.string().min(1)).min(1),
  /** Hosts per name or glob, for a key with no vendor (`RESTATE_AUTH_TOKEN`), or to replace the vendor's list. */
  hosts: z.record(z.string().regex(NAME_GLOB), z.array(z.string().regex(HOST)).min(1)).default({}),
  roles: z.record(z.string().regex(/^[a-z][a-z0-9-]{0,31}$/), roleSchema),
  /** The read relay (`relay.ts`): a loopback proxy to a vendor proxy whose login is `key`. */
  relay: z
    .object({
      port: z.number().int().min(1024).max(65535),
      /** The source name holding `login:pass@host:port`. */
      key: z.string().regex(/^[A-Z][A-Z0-9_]*$/),
      /** On the login: the vendor's targeting (`__cr.us`). */
      suffix: z
        .string()
        .regex(/^[\w.;-]*$/)
        .default(""),
      /** The vendor's sticky ports, "10000-20000": one per client session. */
      /** An alert in the gate log each time a UTC day passes another this many GB. */
      alertGb: z.number().positive().default(0.5),
      /** The vendor's price, for the usage summary. */
      pricePerGb: z.number().nonnegative().default(1),
      sticky: z
        .string()
        .regex(/^\d+-\d+$/)
        .optional(),
    })
    .optional(),
});
export type GateConfig = z.infer<typeof gateConfigSchema>;

export interface GateKey {
  role: string;
  name: string;
  value: string;
  hosts: string[];
  /** The vendor, or the first host for a key with none. */
  site: string;
  keyId: string;
}

export interface GatePlan {
  /** Per role: the env file's entries, sentinels in place of keys. */
  files: Map<string, EnvEntry[]>;
  /** Sentinel → the real key. Only the gate and its addon hold this. */
  keys: Map<string, GateKey>;
  /** Every host a sentinel may go to: the proxy ends TLS on these only. */
  hosts: string[];
}

const glob = (pattern: string): RegExp => new RegExp(`^${pattern.replace(/\*/g, "[A-Z0-9_]*")}$`);
const matchesAny = (name: string, patterns: string[]): boolean =>
  patterns.some((p) => glob(p).test(name));

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
function base32(buf: Buffer): string {
  let bits = 0;
  let acc = 0;
  let out = "";
  for (const byte of buf) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out;
}

/** Stable per gate key, role and name: a restart or a rotated value keeps the file as it is. */
export function sentinel(gateKey: Buffer, role: string, name: string): string {
  const mac = createHmac("sha256", gateKey).update(`${role}/${name}`).digest();
  return `wsk_${base32(mac).slice(0, 28)}`;
}

function hostsFor(name: string, overrides: Record<string, string[]>): string[] | null {
  const exact = overrides[name];
  if (exact) return exact;
  const byGlob = Object.entries(overrides).find(([p]) => p.includes("*") && glob(p).test(name));
  if (byGlob) return byGlob[1];
  const vendor = parseVendorKeyName(name)?.vendor;
  const listed = vendor ? VENDOR_HOSTS[vendor] : undefined;
  return listed ? [...listed] : null;
}

/** Layers the sources: an earlier file wins a name. */
export function layer(sources: EnvEntry[][]): Map<string, string> {
  const out = new Map<string, string>();
  for (const entries of sources)
    for (const { name, value } of entries) if (!out.has(name)) out.set(name, value);
  return out;
}

export function planGate(
  config: GateConfig,
  values: Map<string, string>,
  gateKey: Buffer,
): GatePlan {
  const files = new Map<string, EnvEntry[]>();
  const keys = new Map<string, GateKey>();
  const hosts = new Set<string>();
  const ports = new Set<number>();
  for (const [role, r] of Object.entries(config.roles)) {
    if (ports.has(r.port)) throw new Error(`role ${role}: port ${r.port} is taken by another role`);
    ports.add(r.port);
    const entries: EnvEntry[] = [];
    for (const name of [...values.keys()].sort()) {
      const value = values.get(name) as string;
      if (!ENV_KEY.test(name)) continue;
      if (matchesAny(name, r.keys)) {
        const to = hostsFor(name, config.hosts);
        if (!to) throw new Error(`role ${role}: ${name} has no hosts; add it to "hosts"`);
        const s = sentinel(gateKey, role, name);
        const vendor = parseVendorKeyName(name)?.vendor;
        keys.set(s, {
          role,
          name,
          value,
          hosts: to,
          site: vendor ?? (to[0] as string),
          keyId: keyId(value),
        });
        for (const h of to) hosts.add(h);
        entries.push({ name, value: s });
      } else if (matchesAny(name, r.plain)) {
        if (hostsFor(name, config.hosts) && parseVendorKeyName(name))
          throw new Error(`role ${role}: ${name} is a key; list it in "keys", not "plain"`);
        entries.push({ name, value });
      }
    }
    files.set(role, entries);
  }
  return { files, keys, hosts: [...hosts].sort() };
}

/** mitmproxy's `allow_hosts`: TLS is ended on these hosts only; the rest pass as opaque tunnels. */
export function allowHostsRegex(hosts: string[]): string {
  const alt = hosts
    .map((h) =>
      h.startsWith("*.")
        ? `(?:[a-z0-9-]+\\.)+${h.slice(2).replace(/\./g, "\\.")}`
        : h.replace(/\./g, "\\."),
    )
    .join("|");
  return `^(?:${alt})(?::\\d+)?$`;
}
