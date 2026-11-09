/**
 * What it takes to sign in to a site, by site name (`github`, or
 * `google@ops` for a second account). Stored outside any repo or journal:
 * a sealed 0600 JSON file on a laptop, env entries in a container. Read at
 * the moment a login needs it, never carried on a plan or in a memo.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { type Cipher, isSealed, plainCipher } from "./cipher.js";
import type { CredentialHistory } from "./history.js";

const expandHome = (p: string) => (p.startsWith("~/") ? `${homedir()}${p.slice(1)}` : p);

/** A role name: lowercase, starts with a letter; never an `@`, so it cannot pass for a username. */
export const ROLE_NAME = /^[a-z][a-z0-9.-]{0,31}$/;

/** A detail name: camelCase, starts with a letter (`memberNumber`, `deliveryPostal`). */
export const DETAIL_NAME = /^[a-z][A-Za-z0-9]{0,31}$/;
/** Names a caller already gives a login's own fields; a detail never takes one. */
export const RESERVED_DETAILS: readonly string[] = [
  "username",
  "password",
  "code",
  "phone",
  "phoneLocal",
  "email",
];

export const credentialSchema = z
  .object({
    username: z.string().min(1),
    /** Absent when the account has none: it signs in through a provider (`via`). */
    password: z.string().min(1).optional(),
    /** The password before the last rotation: tried once when the site rejects the current one. */
    previousPassword: z.string().min(1).optional(),
    /** Base32 TOTP seed (the site's "manual entry key", spaces and dashes allowed); never a 6-digit code. */
    totpSecret: z
      .string()
      .transform((s) => s.replace(/[\s=-]/g, "").toUpperCase())
      .pipe(
        z
          .string()
          .regex(
            /^[A-Z2-7]{16,}$/,
            "totpSecret must be the base32 seed (16+ letters/digits), not a 6-digit code",
          ),
      )
      .optional(),
    /** One-time recovery codes the site handed out; used, then dropped. */
    recoveryCodes: z.array(z.string().min(1)).default([]),
    /** Where the site sends email codes; defaults to `username` when that is an address. */
    codesInbox: z.string().email().optional(),
    /** Passkeys enrolled by us (the virtual authenticator's export); loaded into the site's browser session. */
    passkeys: z
      .array(
        z.object({
          rpId: z.string(),
          credentialId: z.string(),
          privateKey: z.string(),
          userHandle: z.string().optional(),
          signCount: z.number(),
          isResidentCredential: z.boolean(),
        }),
      )
      .default([]),
    /** Sign in through this identity provider's button (`google`) instead of a password; the provider's own credential does the work. */
    via: z.string().min(1).optional(),
    /**
     * A tripwire, not an account: nothing legitimate ever reads it. A `get`
     * of a canary is an alarm (see canary.ts), and its password belongs on
     * no host.
     */
    canary: z.boolean().optional(),
    /** Where the sign-in page is, when the caller knows no login page of its own for the site. */
    url: z.string().url().optional(),
    /** When the account was made; a minted credential without it is a signup still owed. */
    madeAt: z.string().datetime().optional(),
    /**
     * What the account is for on its site (`main`, `alt`, `brand`): names a
     * caller asks for instead of the username. One account per role per
     * site is the caller's rule to keep; the store only holds them.
     */
    roles: z
      .array(z.string().regex(ROLE_NAME, "a role is a lowercase word (a-z, 0-9, . and -)"))
      .optional(),
    /**
     * Fixed facts the site asks for besides the login (a member number, a
     * delivery postal code, a home store), by name. Sealed with the rest.
     */
    details: z
      .record(
        z
          .string()
          .regex(DETAIL_NAME, "a detail name is camelCase (a-z, A-Z, 0-9), starts with a-z")
          .refine((k) => !RESERVED_DETAILS.includes(k), "that name is a login field"),
        z.string().min(1),
      )
      .optional(),
  })
  .refine((c) => c.password || c.via, { message: "a credential has a password or a via provider" });

export type Credential = z.infer<typeof credentialSchema>;
export type CredentialInput = z.input<typeof credentialSchema>;

export interface CredentialStore {
  get(site: string): Promise<Credential | null>;
  put(site: string, cred: CredentialInput): Promise<void>;
  /** Site names only; never values. */
  list(): Promise<string[]>;
  /** Forget a site's credential; true when there was one. Kept history stays (restorable). Absent on read-only stores. */
  remove?(site: string): Promise<boolean>;
}

const fileSchema = z.object({ sites: z.record(z.string(), credentialSchema) });

/**
 * `{ "sites": { "<site>": Credential } }` at `path`, mode 0600, written
 * atomically, sealed with `cipher` (a plain file written earlier is still
 * read, and sealed on the next write).
 */
export function fileCredentials(path: string, cipher: Cipher = plainCipher): CredentialStore {
  const file = expandHome(path);
  type Data = { sites: Record<string, Credential> };
  // Opened and parsed once per version of the file: a `list` + `get` per name is one read, and
  // a file another process rewrote (its mtime or size moved) is read again. A stat per call.
  let cached: { stamp: string; data: Data } | null = null;
  const read = (): Data => {
    if (!existsSync(file)) {
      cached = null;
      return { sites: {} };
    }
    const st = statSync(file);
    const stamp = `${st.mtimeMs}:${st.size}`;
    if (cached?.stamp === stamp) return cached.data;
    const raw = readFileSync(file, "utf8");
    const data = fileSchema.parse(JSON.parse(isSealed(raw) ? cipher.open(raw) : raw));
    cached = { stamp, data };
    return data;
  };
  return {
    async get(site) {
      return read().sites[site] ?? null;
    },
    async put(site, cred) {
      const data = { sites: { ...read().sites, [site]: credentialSchema.parse(cred) } };
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
      const tmp = `${file}.tmp`;
      writeFileSync(tmp, cipher.seal(JSON.stringify(data, null, 2)), { mode: 0o600 });
      renameSync(tmp, file);
      cached = null;
    },
    async list() {
      return Object.keys(read().sites);
    },
    async remove(site) {
      const { [site]: had, ...rest } = read().sites;
      if (!had) return false;
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
      const tmp = `${file}.tmp`;
      writeFileSync(tmp, cipher.seal(JSON.stringify({ sites: rest }, null, 2)), { mode: 0o600 });
      renameSync(tmp, file);
      cached = null;
      return true;
    },
  };
}

export function memoryCredentials(init: Record<string, CredentialInput> = {}): CredentialStore {
  const sites = new Map(Object.entries(init).map(([k, v]) => [k, credentialSchema.parse(v)]));
  return {
    async get(site) {
      return sites.get(site) ?? null;
    },
    async put(site, cred) {
      sites.set(site, credentialSchema.parse(cred));
    },
    async list() {
      return [...sites.keys()];
    },
    async remove(site) {
      return sites.delete(site);
    },
  };
}

/** How credentials travel as env: `<prefix><SITE>_<FIELD>`. Each app picks its own prefix. */
export interface EnvNaming {
  /** Default `CRED_`. */
  prefix?: string;
}

const DEFAULT_PREFIX = "CRED_";

/** `CRED_<SITE>_<FIELD>`: the env name a credential field travels under. */
export function credentialEnvName(site: string, field: string, o: EnvNaming = {}): string {
  return `${o.prefix ?? DEFAULT_PREFIX}${envSiteName(site)}_${field}`;
}

/**
 * `google@ops` → `GOOGLE__OPS`, `google-admin` → `GOOGLE_ADMIN`,
 * `google@will@a.com` → `GOOGLE__WILL__A___COM`: `@` and `.` keep their
 * own marks so `list` reads the site back as it was put.
 */
export const envSiteName = (site: string): string =>
  site
    .replace(/@/g, "__")
    .replace(/\./g, "___")
    .replace(/[^a-zA-Z0-9_]+/g, "_")
    .toUpperCase();
const USERNAME = "_USERNAME";
export const siteFromEnvName = (s: string): string =>
  s.toLowerCase().replace(/___/g, ".").replace(/__/g, "@").replace(/_/g, "-");

/** Fields that travel as plain strings, and the list fields that travel as JSON. */
const STRING_FIELDS = [
  ["USERNAME", "username"],
  ["PASSWORD", "password"],
  ["PREVIOUS_PASSWORD", "previousPassword"],
  ["TOTP_SECRET", "totpSecret"],
  ["VIA", "via"],
  ["CODES_INBOX", "codesInbox"],
  ["URL", "url"],
  ["MADE_AT", "madeAt"],
] as const;
const JSON_FIELDS = [
  ["RECOVERY_CODES", "recoveryCodes"],
  ["PASSKEYS", "passkeys"],
  ["ROLES", "roles"],
  ["DETAILS", "details"],
] as const;
/** Every env field a credential can use: what a push clears when the credential no longer has it. */
export const CREDENTIAL_ENV_FIELDS: readonly string[] = [...STRING_FIELDS, ...JSON_FIELDS].map(
  ([f]) => f,
);

/**
 * A credential as env entries, every field of it: the strings as they are,
 * recovery codes, passkeys, roles and details as JSON. Empty fields are left out. A
 * canary's entries are never asked for (see `pushCredentials`).
 */
export function credentialEnv(
  site: string,
  cred: Credential,
  o: EnvNaming = {},
): { name: string; value: string }[] {
  const fields: [string, string | undefined][] = [
    ...STRING_FIELDS.map(([f, k]): [string, string | undefined] => [f, cred[k]]),
    ...JSON_FIELDS.map(([f, k]): [string, string | undefined] => [
      f,
      cred[k] && Object.keys(cred[k]).length ? JSON.stringify(cred[k]) : undefined,
    ]),
  ];
  return fields
    .filter((f): f is [string, string] => Boolean(f[1]))
    .map(([field, value]) => ({ name: credentialEnvName(site, field, o), value }));
}

/**
 * `CRED_<SITE>_<FIELD>`: the container form, where a Secret becomes env,
 * and the shape a pull reads back. Read-only.
 */
export function envCredentials(
  env: NodeJS.ProcessEnv = process.env,
  o: EnvNaming = {},
): CredentialStore {
  const prefix = o.prefix ?? DEFAULT_PREFIX;
  const key = (site: string, field: string) => credentialEnvName(site, field, o);
  return {
    async get(site) {
      const username = env[key(site, "USERNAME")];
      if (!username || !(env[key(site, "PASSWORD")] || env[key(site, "VIA")])) return null;
      const out: Record<string, unknown> = {};
      for (const [f, k] of STRING_FIELDS) {
        const v = env[key(site, f)];
        if (v) out[k] = v;
      }
      for (const [f, k] of JSON_FIELDS) {
        const v = env[key(site, f)];
        if (!v) continue;
        try {
          out[k] = JSON.parse(v);
        } catch {
          throw new Error(`credentials for ${site}: ${key(site, f)} is not JSON`);
        }
      }
      return credentialSchema.parse(out);
    },
    async put(site) {
      throw new Error(`credentials for ${site}: env store is read-only; set ${key(site, "*")}`);
    },
    async list() {
      return Object.keys(env)
        .map((k) =>
          k.startsWith(prefix) && k.endsWith(USERNAME)
            ? k.slice(prefix.length, -USERNAME.length)
            : undefined,
        )
        .filter((s): s is string => Boolean(s))
        .map(siteFromEnvName);
    },
  };
}

/** The shared store's side of a sync (SSM, see env-store.ts). */
export interface CredentialEnvStore {
  all(): Promise<{ name: string; value: string }[]>;
  put(name: string, value: string, o?: { replace?: boolean }): Promise<void>;
  /** Names only. With `remove`, a push clears the fields a credential no longer has (used codes, a dropped password). */
  list?(): Promise<{ name: string }[]>;
  remove?(name: string): Promise<boolean>;
  /** The named entries that exist; with it, a push keeps what the store held before overwriting it. */
  getMany?(names: string[]): Promise<Record<string, string>>;
}

export interface PushOptions extends EnvNaming {
  /**
   * Where every state of a credential is kept. A push keeps what the store
   * held, then what it writes: a wrong write is one `get(site, version)` away.
   * A push that cannot keep the old state writes nothing.
   */
  history?: CredentialHistory;
}

/**
 * This machine's credentials into the env store, every site or the named
 * ones, every field (passkeys and recovery codes as JSON). Canaries never
 * travel: a tripwire belongs to one machine. Answers what was pushed, never
 * a value.
 */
export async function pushCredentials(
  local: CredentialStore,
  store: CredentialEnvStore,
  sites?: string[],
  o: PushOptions = {},
): Promise<{ site: string; names: string[] }[]> {
  const naming: EnvNaming = o.prefix ? { prefix: o.prefix } : {};
  const chosen = sites?.length ? sites : await local.list();
  const out: { site: string; names: string[] }[] = [];
  const there =
    store.list && store.remove ? new Set((await store.list()).map((e) => e.name)) : null;
  for (const site of chosen) {
    const cred = await local.get(site);
    if (!cred) throw new Error(`no credential stored here for ${site}`);
    if (cred.canary) continue;
    if (o.history && store.getMany) {
      const names = CREDENTIAL_ENV_FIELDS.map((f) => credentialEnvName(site, f, naming));
      const before = await envCredentials(await store.getMany(names), naming).get(site);
      if (before) await o.history.keep(site, before);
    }
    const entries = credentialEnv(site, cred, naming);
    // A push owns its names; what they held is in `history` above.
    for (const e of entries) await store.put(e.name, e.value, { replace: true });
    if (there && store.remove) {
      const kept = new Set(entries.map((e) => e.name));
      for (const f of CREDENTIAL_ENV_FIELDS) {
        const name = credentialEnvName(site, f, naming);
        if (there.has(name) && !kept.has(name)) await store.remove(name);
      }
    }
    await o.history?.keep(site, cred);
    out.push({ site, names: entries.map((e) => e.name) });
  }
  return out;
}

/**
 * The env store's credentials into this machine's file, the other way: a
 * new laptop, or a box's file for a passkey site. A site already here is
 * kept unless `overwrite`, and even then passkeys here are never dropped:
 * the shared ones join them. Answers what was written and what was kept.
 */
export async function pullCredentials(
  store: CredentialEnvStore,
  local: CredentialStore,
  sites?: string[],
  o: { overwrite?: boolean } & EnvNaming = {},
): Promise<{ written: string[]; kept: string[] }> {
  const env = Object.fromEntries((await store.all()).map((e) => [e.name, e.value]));
  const remote = envCredentials(env, o);
  const chosen = sites?.length ? sites : await remote.list();
  const written: string[] = [];
  const kept: string[] = [];
  for (const site of chosen) {
    const cred = await remote.get(site);
    if (!cred) throw new Error(`no credential in the shared store for ${site}: push it first`);
    const here = await local.get(site);
    if (here && !o.overwrite) {
      kept.push(site);
      continue;
    }
    const shared = new Set(cred.passkeys.map((p) => p.credentialId));
    await local.put(site, {
      ...cred,
      // A store pushed before codes travelled has none: the ones here stay.
      recoveryCodes: cred.recoveryCodes.length ? cred.recoveryCodes : (here?.recoveryCodes ?? []),
      // Details here the store lacks stay; the store's win on a clash.
      ...(cred.details || here?.details ? { details: { ...here?.details, ...cred.details } } : {}),
      passkeys: [
        ...cred.passkeys,
        ...(here?.passkeys ?? []).filter((p) => !shared.has(p.credentialId)),
      ],
    });
    written.push(site);
  }
  return { written, kept };
}

/** First store that has the site wins; writes go to `write`, which defaults to the last store. */
export function layeredCredentials(
  stores: CredentialStore[],
  write: CredentialStore | undefined = stores.at(-1),
): CredentialStore {
  const first = write;
  if (!first) throw new Error("layeredCredentials needs at least one store");
  return {
    async get(site) {
      for (const s of stores) {
        const c = await s.get(site);
        if (c) return c;
      }
      return null;
    },
    put: (site, cred) => first.put(site, cred),
    async list() {
      const all = await Promise.all(stores.map((s) => s.list()));
      return [...new Set(all.flat())];
    },
    async remove(site) {
      const gone = await Promise.all(stores.map((s) => s.remove?.(site) ?? false));
      return gone.some(Boolean);
    },
  };
}

/**
 * The shared store a synced credential store reads and writes (an `EnvStore` fits).
 * `list` says when each row last changed without reading a value; a store that
 * knows (SSM) is read only when a row changed, one that does not every `ttlMs`.
 */
export interface SharedCredentialStore extends CredentialEnvStore {
  list(): Promise<{ name: string; updatedAt?: string | null; version?: number }[]>;
  getMany(names: string[]): Promise<Record<string, string>>;
}

/**
 * Which version of each site the local copy holds, so another process on this
 * machine trusts the copy instead of reading the shared store again. See `versionsFile`.
 */
export interface SeenVersions {
  get(site: string): string | null;
  set(site: string, version: string | null): void;
}

/** `SeenVersions` in a small JSON file (names and change times only, no values). */
export function versionsFile(path: string): SeenVersions {
  const read = (): Record<string, string> => {
    try {
      return JSON.parse(readFileSync(path, "utf8")) as Record<string, string>;
    } catch {
      return {};
    }
  };
  return {
    get: (site) => read()[site] ?? null,
    set(site, version) {
      const all = read();
      if (version === null) delete all[site];
      else all[site] = version;
      mkdirSync(dirname(path), { recursive: true });
      const tmp = `${path}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify(all), { mode: 0o600 });
      renameSync(tmp, path);
    },
  };
}

export interface SyncOptions extends PushOptions {
  /** A shared store that keeps no change times: how long a read is reused in this process. Default 60s. */
  ttlMs?: number;
  /** A shared read slower than this falls back to the local copy. Default 3s. */
  timeoutMs?: number;
  /** A failed shared read or copy: the local copy carried on. Default: reads fall back silently, copies throw. */
  onSharedError?: (site: string, err: unknown, during: "read" | "write") => void;
  /** The version the local copy holds, shared across processes; default this process only. */
  versions?: SeenVersions;
  now?: () => number;
}

/**
 * The shared store is the truth; `local` is the offline copy. A read asks
 * the shared store when the site's rows last changed (its listing, no
 * value read) and reads the values only when that moved since the copy
 * was taken: each version is read once, not once per use. Every value
 * read from SSM costs a KMS decrypt, so this is the budget. A store with
 * no change times is read again every `ttlMs`. The copy is refreshed when
 * they differ; when the shared store is slow or down, or lacks the site,
 * `local` answers. A write lands in `local`, then in the shared store.
 * Canaries never leave `local`. No pull chore: a new machine's first read
 * of a site fills its copy.
 */
export function syncedCredentials(
  local: CredentialStore,
  shared: SharedCredentialStore,
  o: SyncOptions = {},
): CredentialStore {
  const naming: EnvNaming = o.prefix ? { prefix: o.prefix } : {};
  const ttl = o.ttlMs ?? 60_000;
  const timeout = o.timeoutMs ?? 3_000;
  const now = o.now ?? Date.now;
  const seen = new Map<string, { at: number; version: string | null; cred: Credential | null }>();
  const versions = o.versions ?? memoryVersions();
  const withTimeout = <T>(p: Promise<T>): Promise<T> =>
    Promise.race([
      p,
      new Promise<T>((_, rej) =>
        setTimeout(
          () => rej(new Error(`shared store: no answer in ${timeout}ms`)),
          timeout,
        ).unref(),
      ),
    ]);
  const fieldNames = (site: string) =>
    CREDENTIAL_ENV_FIELDS.map((f) => credentialEnvName(site, f, naming));
  /** The site's rows and when each changed, from the listing; null when the store keeps no times. */
  const versionOf = async (site: string): Promise<string | null> => {
    const names = new Set(fieldNames(site));
    const rows = (await withTimeout(shared.list())).filter((r) => names.has(r.name));
    if (rows.some((r) => !r.updatedAt)) return null;
    return rows
      .map((r) => `${r.name}@${r.version ?? ""}@${r.updatedAt}`)
      .sort()
      .join(",");
  };
  /** The shared copy, or `undefined`: the local one is that version already. */
  const fromShared = async (
    site: string,
    here: Credential | null,
  ): Promise<{ cred: Credential | null; version: string | null } | undefined> => {
    const hit = seen.get(site);
    const version = await versionOf(site);
    if (version === null) {
      if (hit && now() - hit.at < ttl) return hit;
    } else {
      if (hit && hit.version === version) return hit;
      // No rows: nothing there to read.
      if (version === "") return { cred: null, version };
      if (here && versions.get(site) === version) {
        seen.set(site, { at: now(), version, cred: here });
        return undefined;
      }
    }
    const cred = await envCredentials(
      await withTimeout(shared.getMany(fieldNames(site))),
      naming,
    ).get(site);
    seen.set(site, { at: now(), version, cred });
    return { cred, version };
  };
  return {
    async get(site) {
      const here = await local.get(site);
      if (here?.canary) return here;
      let there: { cred: Credential | null; version: string | null } | undefined;
      try {
        there = await fromShared(site, here);
      } catch (err) {
        o.onSharedError?.(site, err, "read");
        return here;
      }
      if (!there) return here;
      if (!there.cred) return here;
      if (!isDeepStrictEqual(here, there.cred)) await local.put(site, there.cred);
      if (there.version) versions.set(site, there.version);
      return there.cred;
    },
    async put(site, cred) {
      await local.put(site, cred);
      // Until the shared store has it, the copy here is not any version there.
      seen.delete(site);
      versions.set(site, null);
      try {
        await pushCredentials(local, shared, [site], {
          ...naming,
          ...(o.history ? { history: o.history } : {}),
        });
      } catch (err) {
        if (!o.onSharedError) throw err;
        o.onSharedError(site, err, "write");
        return;
      }
      // What was just written is what is there: no read back.
      const version = await versionOf(site).catch(() => null);
      const kept = await local.get(site);
      if (version) {
        seen.set(site, { at: now(), version, cred: kept });
        versions.set(site, version);
      }
    },
    async list() {
      const here = await local.list();
      const suffix = "_USERNAME";
      const prefix = naming.prefix ?? DEFAULT_PREFIX;
      let there: string[] = [];
      try {
        there = (await withTimeout(shared.list()))
          .map((e) => e.name)
          .filter((n) => n.startsWith(prefix) && n.endsWith(suffix))
          .map((n) => siteFromEnvName(n.slice(prefix.length, -suffix.length)));
      } catch (err) {
        o.onSharedError?.("*", err, "read");
      }
      return [...new Set([...here, ...there])];
    },
    async remove(site) {
      seen.delete(site);
      versions.set(site, null);
      const here = (await local.remove?.(site)) ?? false;
      if (!shared.remove) return here;
      const names = new Set((await shared.list()).map((e) => e.name));
      const rows = CREDENTIAL_ENV_FIELDS.map((f) => credentialEnvName(site, f, naming)).filter(
        (n) => names.has(n),
      );
      for (const n of rows) await shared.remove(n);
      return here || rows.length > 0;
    },
  };
}

function memoryVersions(): SeenVersions {
  const m = new Map<string, string>();
  return {
    get: (site) => m.get(site) ?? null,
    set: (site, v) => (v === null ? m.delete(site) : m.set(site, v)),
  };
}
