/**
 * The one place a secret lives across machines: SSM Parameter Store, one
 * SecureString per name under the app's path (`/myapp/config/NAME`). KMS
 * at rest, IAM at the door, every read in CloudTrail. Values never enter
 * argv, logs or errors.
 */

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import {
  DeleteParameterCommand,
  DescribeParametersCommand,
  GetParametersCommand,
  ParameterNotFound,
  PutParameterCommand,
  type SSMClient,
} from "@aws-sdk/client-ssm";

/** SSM throttles writes at a few a second; a push of thirty keys backs off and goes on rather than dying. */
async function patient<T>(
  call: () => Promise<T>,
  sleep = (ms: number) => new Promise((r) => setTimeout(r, ms)),
): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await call();
    } catch (err) {
      const throttled =
        err instanceof Error &&
        (err.name === "ThrottlingException" || /Rate exceeded/i.test(err.message));
      if (!throttled || attempt >= 8) throw err;
      await sleep(200 * 2 ** attempt);
    }
  }
}

export const ENV_KEY = /^[A-Z][A-Z0-9_]*$/;

export interface EnvEntry {
  name: string;
  value: string;
}

/** What the store knows about an entry besides its value. */
export interface EnvListing {
  name: string;
  /** When the value last changed. */
  updatedAt: string | null;
  /** The store's own count of changes (SSM's parameter version), when it keeps one. */
  version?: number;
  /** When the value stops working (a token's expiry), if whoever stored it knew. */
  expiresAt: string | null;
}

export interface PutOptions {
  /** ISO time the value stops working; absent = it does not, or nobody knows. */
  expiresAt?: string | undefined;
  /**
   * The name may hold another value, and this put replaces it. Without it such a put
   * throws `WouldReplace` and writes nothing. Code that owns the name (a token refresh,
   * a projection) sets it; a surface sets it after a person or an agent confirmed.
   */
  replace?: boolean | undefined;
}

/**
 * A put met another value under its name and did not write. Holds no value.
 * 2026-11-05: an agent's write replaced a live token twice with no question asked.
 */
export class WouldReplace extends Error {
  constructor(
    /** The env name. */
    readonly key: string,
    /** Length of the held value: enough to tell a token from an id. */
    readonly heldLength: number,
    /** Where it is held, in words: "the shared store", "this machine". */
    readonly where = "the store",
  ) {
    super(`${key} already holds another value in ${where}; nothing was written`);
    this.name = "WouldReplace";
  }
}

/** Throws `WouldReplace` when `held` is another value and the put did not say `replace`. */
function guard(
  name: string,
  value: string,
  held: string | null | undefined,
  o: PutOptions | undefined,
  where?: string,
): void {
  if (o?.replace || held === null || held === undefined || held === value) return;
  throw new WouldReplace(name, held.length, where);
}

export interface EnvStore {
  /** Names, change and expiry times; never values. */
  list(): Promise<EnvListing[]>;
  get(name: string): Promise<string | null>;
  /** The named entries that exist, in as few round trips as the store allows (SSM: ten a call). */
  getMany(names: string[]): Promise<Record<string, string>>;
  /** Every entry, decrypted: what a pull or a deploy reads. */
  all(): Promise<EnvEntry[]>;
  put(name: string, value: string, o?: PutOptions): Promise<void>;
  remove(name: string): Promise<boolean>;
}

/**
 * Entries that stop working within `withinMs` of `now` (already expired
 * included), soonest first: what a watcher re-mints.
 */
export function expiring(
  entries: readonly EnvListing[],
  withinMs: number,
  now = Date.now(),
): EnvListing[] {
  return entries
    .filter((e) => e.expiresAt !== null && Date.parse(e.expiresAt) - now <= withinMs)
    .sort((a, b) => (a.expiresAt ?? "").localeCompare(b.expiresAt ?? ""));
}

/** SSM keeps expiry in the parameter's description, which reads without decrypting. */
const EXPIRES = "expires ";
const describe = (o: PutOptions = {}) =>
  o.expiresAt ? `${EXPIRES}${new Date(o.expiresAt).toISOString()}` : "no expiry";
const expiryOf = (description: string | undefined): string | null =>
  description?.startsWith(EXPIRES) ? description.slice(EXPIRES.length) : null;

/** SSM under `prefix`: `/prefix/NAME`. The client comes in so tests pass a fake. */
export function ssmEnvStore(ssm: SSMClient, prefix: string): EnvStore {
  const path = (name: string) => {
    if (!ENV_KEY.test(name)) throw new Error(`env store: bad name ${name}`);
    return `${prefix}/${name}`;
  };
  const nameOf = (p: string | undefined) => p?.slice(prefix.length + 1) ?? "";
  const byName = <T extends { name: string }>(rows: T[]) =>
    rows.sort((a, b) => a.name.localeCompare(b.name));
  // One command lists several times (credentials, env, needs): one listing a
  // few seconds serves them all; a write here drops it.
  let listed: { at: number; rows: Promise<EnvListing[]> } | null = null;
  const LIST_REUSE_MS = 5_000;
  const listNow = async () => {
    const out: EnvListing[] = [];
    let next: string | undefined;
    do {
      const r = await patient(() =>
        ssm.send(
          new DescribeParametersCommand({
            ParameterFilters: [{ Key: "Path", Option: "OneLevel", Values: [prefix] }],
            // The default page is 10; 50 is the most SSM gives.
            MaxResults: 50,
            NextToken: next,
          }),
        ),
      );
      for (const p of r.Parameters ?? [])
        out.push({
          name: nameOf(p.Name),
          updatedAt: p.LastModifiedDate?.toISOString() ?? null,
          ...(p.Version ? { version: p.Version } : {}),
          expiresAt: expiryOf(p.Description),
        });
      next = r.NextToken;
    } while (next);
    return byName(out);
  };
  const list = async () => {
    if (!listed || Date.now() - listed.at > LIST_REUSE_MS) {
      const rows = listNow();
      listed = { at: Date.now(), rows };
      rows.catch(() => {
        listed = null;
      });
    }
    return (await listed.rows).map((r) => ({ ...r }));
  };
  // Every SecureString read is a KMS decrypt, and KMS is billed per request.
  // So each value read is kept with the version it was read at, and read
  // again only once the listing (which reads no value) shows it changed.
  const known = new Map<string, { stamp: string; value: string }>();
  const stampOf = (e: EnvListing) => `${e.version ?? ""}@${e.updatedAt ?? ""}`;
  const readNow = async (names: string[]) => {
    const out: Record<string, string> = {};
    for (let i = 0; i < names.length; i += 10) {
      const r = await ssm.send(
        new GetParametersCommand({
          Names: names.slice(i, i + 10).map(path),
          WithDecryption: true,
        }),
      );
      for (const p of r.Parameters ?? [])
        if (p.Name && p.Value !== undefined) out[p.Name.slice(prefix.length + 1)] = p.Value;
    }
    return out;
  };
  const read = async (names: string[], rows: EnvListing[]) => {
    const stamps = new Map(rows.map((e) => [e.name, stampOf(e)]));
    const out: Record<string, string> = {};
    const need: string[] = [];
    for (const n of names) {
      const k = known.get(n);
      if (k && k.stamp === stamps.get(n)) out[n] = k.value;
      else need.push(n);
    }
    if (need.length)
      for (const [n, v] of Object.entries(await readNow(need))) {
        out[n] = v;
        const stamp = stamps.get(n);
        if (stamp) known.set(n, { stamp, value: v });
      }
    return out;
  };
  const getMany = async (names: string[]) => read(names, await list().catch(() => []));
  return {
    list,
    async all() {
      // Fresh, not the reused listing: everything means everything there now.
      const rows = await listNow();
      listed = { at: Date.now(), rows: Promise.resolve(rows) };
      const values = await read(
        rows.map((e) => e.name),
        rows,
      );
      return byName(Object.entries(values).map(([name, value]) => ({ name, value })));
    },
    getMany,
    get: async (name) => (await getMany([name]))[name] ?? null,
    async put(name, value, o) {
      if (!value) throw new Error(`env store: ${name} is empty`);
      // Read, then write: SSM has no put-if-equal. Two writers in one second can both pass.
      if (!o?.replace) guard(name, value, (await getMany([name]))[name], o);
      listed = null;
      known.delete(name);
      await patient(() =>
        ssm.send(
          new PutParameterCommand({
            Name: path(name),
            Value: value,
            // Always said, so a re-mint without an expiry clears the old one.
            Description: describe(o),
            Type: "SecureString",
            // Past 4 KB (a service-account JSON) SSM needs the advanced tier; this picks it only then.
            Tier: "Intelligent-Tiering",
            Overwrite: true,
          }),
        ),
      );
    },
    async remove(name) {
      // SSM's delete takes every version. The last value goes to `removed/NAME` first;
      // a copy that fails stops the remove.
      const held = (await readNow([name]))[name];
      if (held === undefined) return false;
      await patient(() =>
        ssm.send(
          new PutParameterCommand({
            Name: `${prefix}/${REMOVED}/${name}`,
            Value: held,
            Description: `removed ${new Date().toISOString()}`,
            Type: "SecureString",
            Tier: "Intelligent-Tiering",
            Overwrite: true,
          }),
        ),
      );
      listed = null;
      known.delete(name);
      try {
        await ssm.send(new DeleteParameterCommand({ Name: path(name) }));
        return true;
      } catch (err) {
        if (err instanceof ParameterNotFound) return false;
        throw err;
      }
    },
  };
}

/** The level under a store's prefix that keeps the last value of each removed name. */
export const REMOVED = "removed";

export function memoryEnvStore(initial: Record<string, string> = {}): EnvStore & {
  values: Record<string, string>;
} {
  const values = { ...initial };
  const expires = new Map<string, string>();
  return {
    values,
    list: async () =>
      Object.keys(values)
        .sort()
        .map((name) => ({ name, updatedAt: null, expiresAt: expiryOf(expires.get(name)) })),
    all: async () =>
      Object.entries(values)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([name, value]) => ({ name, value })),
    get: async (name) => values[name] ?? null,
    getMany: async (names) =>
      Object.fromEntries(names.flatMap((n) => (n in values ? [[n, values[n] as string]] : []))),
    async put(name, value, o) {
      if (!ENV_KEY.test(name)) throw new Error(`env store: bad name ${name}`);
      guard(name, value, values[name], o);
      values[name] = value;
      expires.set(name, describe(o));
    },
    async remove(name) {
      const had = name in values;
      delete values[name];
      expires.delete(name);
      return had;
    },
  };
}

/**
 * A machine's own copy in front of the shared store: every put lands in
 * both, so a token minted on a laptop is on every machine and the box too,
 * and survives the laptop. The local copy is written first, so a mint is
 * never lost to a dropped network; the shared write failing is an error
 * all the same (the value is not durable yet). Reads prefer the local copy
 * and fall through to the shared store for what it lacks.
 */
export function syncedEnvStore(
  local: EnvStore,
  shared: EnvStore,
  o: { unshared?: Unshared } = {},
): SyncedEnvStore {
  const unshared = o.unshared ?? memoryUnshared();
  /**
   * Each name whose last put stayed here: its local value, with its expiry, into the shared store.
   * A name whose shared value changed meanwhile stays unshared and the call throws `WouldReplace`,
   * unless `replace` says this machine's value wins.
   */
  async function share(so: { replace?: boolean } = {}): Promise<string[]> {
    const names = unshared.names();
    if (!names.length) return [];
    const [values, listed] = await Promise.all([local.getMany(names), local.list()]);
    const expiry = new Map(listed.map((e) => [e.name, e.expiresAt]));
    const sent: string[] = [];
    let refused: WouldReplace | null = null;
    for (const name of names) {
      const value = values[name];
      // Gone from this machine since: nothing is left to share.
      if (value !== undefined) {
        const expiresAt = expiry.get(name) ?? undefined;
        try {
          await shared.put(name, value, {
            ...(expiresAt ? { expiresAt } : {}),
            ...(so.replace ? { replace: true } : {}),
          });
        } catch (err) {
          if (!(err instanceof WouldReplace)) throw err;
          // Stays unshared; the rest still go.
          refused ??= new WouldReplace(name, err.heldLength, "the shared store");
          continue;
        }
        sent.push(name);
      }
      unshared.drop(name);
    }
    if (refused) throw refused;
    return sent;
  }
  return {
    share,
    async list() {
      const [mine, theirs] = await Promise.all([local.list(), shared.list()]);
      const byName = new Map(theirs.map((e) => [e.name, e]));
      for (const e of mine) {
        const s = byName.get(e.name);
        byName.set(e.name, s ? { ...s, expiresAt: s.expiresAt ?? e.expiresAt } : e);
      }
      return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
    },
    get: async (name) => (await local.get(name)) ?? (await shared.get(name)),
    async getMany(names) {
      const mine = await local.getMany(names);
      const rest = names.filter((n) => !(n in mine));
      return { ...(rest.length ? await shared.getMany(rest) : {}), ...mine };
    },
    async all() {
      const byName = new Map((await shared.all()).map((e) => [e.name, e]));
      for (const e of await local.all()) byName.set(e.name, e);
      return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
    },
    async put(name, value, o) {
      // Both sides are asked before either is written: a refusal leaves both as they were.
      // A shared store that does not answer is not asked; `share()` asks it later.
      if (!o?.replace) {
        guard(name, value, await local.get(name), o, "this machine");
        guard(name, value, await shared.get(name).catch(() => null), o, "the shared store");
      }
      const checked = { ...o, replace: true };
      await local.put(name, value, checked);
      // Remembered before the shared write: a crash in between still shares it later.
      unshared.add(name);
      try {
        await shared.put(name, value, checked);
        unshared.drop(name);
      } catch (err) {
        throw new Error(
          `${name} kept on this machine only; the shared store refused it (${err instanceof Error ? err.message : String(err)}): the next put or share() sends it`,
        );
      }
      // The shared store answers again: what an earlier put left here goes too.
      await share().catch(() => undefined);
    },
    async remove(name) {
      const [a, b] = await Promise.all([local.remove(name), shared.remove(name)]);
      unshared.drop(name);
      return a || b;
    },
  };
}

/** A synced store, and the one call that sends what a refused shared write left on this machine. */
export interface SyncedEnvStore extends EnvStore {
  /** Put every unshared name's local value into the shared store; answers the names sent. */
  share(o?: { replace?: boolean }): Promise<string[]>;
}

/** Names whose last put reached only this machine. Names only, never values. */
export interface Unshared {
  names(): string[];
  add(name: string): void;
  drop(name: string): void;
}

export function memoryUnshared(): Unshared {
  const set = new Set<string>();
  return {
    names: () => [...set].sort(),
    add: (n) => void set.add(n),
    drop: (n) => void set.delete(n),
  };
}

/**
 * Unshared names in a file (a JSON array, 0600), so they outlive the process: a token minted while
 * the shared store refused writes is sent by the next process that reaches it.
 */
export function unsharedFile(path: string): Unshared {
  const read = (): string[] => {
    if (!existsSync(path)) return [];
    try {
      const v: unknown = JSON.parse(readFileSync(path, "utf8"));
      return Array.isArray(v) ? v.filter((n): n is string => typeof n === "string") : [];
    } catch {
      return [];
    }
  };
  const write = (names: string[]) => {
    const tmp = `${path}.tmp`;
    writeFileSync(tmp, `${JSON.stringify([...new Set(names)].sort())}\n`, { mode: 0o600 });
    renameSync(tmp, path);
  };
  return {
    names: read,
    add: (n) => {
      const now = read();
      if (!now.includes(n)) write([...now, n]);
    },
    drop: (n) => {
      const now = read();
      if (now.includes(n)) write(now.filter((x) => x !== n));
    },
  };
}

/** The comment above a line that says when its value stops working: `# NAME expires <ISO>`. */
const EXPIRY_LINE = /^# ([A-Z][A-Z0-9_]*) expires (\S+)$/;

/**
 * A local `.env` as a store: 0600, one line per name, other lines untouched.
 * Expiry is a comment directly above the line, so a person reading the file
 * sees it too. A put also sets `env[name]`, so this process sees the value.
 */
export function envFileStore(path: string, env: NodeJS.ProcessEnv = process.env): EnvStore {
  const file = path.startsWith("~/") ? `${homedir()}${path.slice(1)}` : path;
  const text = () => (existsSync(file) ? readFileSync(file, "utf8") : "");
  const lines = () => {
    const out = text().split("\n");
    if (out.at(-1) === "") out.pop();
    return out;
  };
  const write = (out: string[]) => {
    const tmp = `${file}.tmp`;
    writeFileSync(tmp, out.length ? `${out.join("\n")}\n` : "", { mode: 0o600 });
    renameSync(tmp, file);
  };
  /** The file without `name`'s line and expiry comment; where the line was, or -1. */
  const without = (name: string) => {
    const out: string[] = [];
    let at = -1;
    for (const l of lines()) {
      if (EXPIRY_LINE.exec(l)?.[1] === name) continue;
      if (l.startsWith(`${name}=`)) {
        at = out.length;
        continue;
      }
      out.push(l);
    }
    return { out, at };
  };
  return {
    async list() {
      const expires = new Map<string, string>();
      for (const l of lines()) {
        const m = EXPIRY_LINE.exec(l);
        if (m?.[1] && m[2]) expires.set(m[1], m[2]);
      }
      return parseDotenv(text()).map(({ name }) => ({
        name,
        updatedAt: null,
        expiresAt: expires.get(name) ?? null,
      }));
    },
    all: async () => parseDotenv(text()),
    get: async (name) => parseDotenv(text()).find((e) => e.name === name)?.value ?? null,
    getMany: async (names) =>
      Object.fromEntries(
        parseDotenv(text())
          .filter((e) => names.includes(e.name))
          .map((e) => [e.name, e.value]),
      ),
    async put(name, value, o) {
      if (!ENV_KEY.test(name)) throw new Error(`env file: bad name ${name}`);
      if (/[\r\n]/.test(value)) throw new Error(`env file: ${name} spans lines`);
      guard(name, value, parseDotenv(text()).find((e) => e.name === name)?.value, o, file);
      const { out, at } = without(name);
      const add = [...(o?.expiresAt ? [`# ${name} ${describe(o)}`] : []), `${name}=${value}`];
      out.splice(at < 0 ? out.length : at, 0, ...add);
      write(out);
      env[name] = value;
    },
    async remove(name) {
      const { out, at } = without(name);
      if (at < 0) return false;
      write(out);
      delete env[name];
      return true;
    },
  };
}

/**
 * `KEY=VALUE` lines → entries. Comments, blanks and quotes as a shell would
 * read them; a value naming a readable file whose content is JSON (a
 * service account) is inlined so the store holds the secret, not a path.
 */
export function parseDotenv(text: string, readFile?: (path: string) => string | null): EnvEntry[] {
  const out: EnvEntry[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const i = line.indexOf("=");
    const name = line
      .slice(0, i)
      .trim()
      .replace(/^export\s+/, "");
    let value = line.slice(i + 1).trim();
    const q = value[0];
    if (q === '"' || q === "'") {
      const end = value.indexOf(q, 1);
      value = end > 0 ? value.slice(1, end) : value.slice(1);
    } else value = value.replace(/\s+#.*$/, "");
    if (!ENV_KEY.test(name) || !value) continue;
    if (readFile && !value.trimStart().startsWith("{") && /\.json$/.test(value)) {
      const inlined = readFile(value);
      if (inlined?.trimStart().startsWith("{")) value = inlined;
    }
    out.push({ name, value });
  }
  return out;
}

/** Entries → `KEY=VALUE` lines. A multi-line value cannot live in one line: `files` takes it and the line names the path. */
export function toDotenv(
  entries: EnvEntry[],
  files?: (name: string, value: string) => string,
): string {
  return `${entries
    .map(({ name, value }) => {
      if (!/[\r\n]/.test(value)) return `${name}=${value}`;
      if (!files) throw new Error(`${name} spans lines; give it a file`);
      return `${name}=${files(name, value)}`;
    })
    .join("\n")}\n`;
}

/** Entries → `export KEY='…'` lines for `eval "$(…)"`; single quotes are the one thing escaped. */
export function toExports(entries: EnvEntry[]): string {
  return `${entries
    .map(({ name, value }) => `export ${name}='${value.replace(/'/g, `'\\''`)}'`)
    .join("\n")}\n`;
}

/** Upsert `entries` into an env file's text; other lines untouched. */
export function upsertDotenv(text: string, entries: EnvEntry[]): string {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  for (const { name, value } of entries) {
    const line = `${name}=${value}`;
    const i = lines.findIndex((l) => l.startsWith(`${name}=`));
    if (i >= 0) lines[i] = line;
    else lines.push(line);
  }
  return `${lines.join("\n")}\n`;
}
