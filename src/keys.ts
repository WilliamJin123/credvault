/**
 * API keys as credentials. A key belongs to a vendor (`site`), has a label
 * (`account`), an owner and purposes, and lives in an `EnvStore` one row per
 * key, so it travels, syncs and keeps history like any other stored value.
 * The ring (`keysFor`) and the env projection (`projectKeys`) are derived
 * from the keys; env is a view of the vault, one way.
 *
 * No value goes into an error or a return other than `ApiKey` and the
 * projection's entries. Errors name addresses, row names and ids.
 */
import { createHash } from "node:crypto";
import { z } from "zod";
import type { SecretUse } from "./audit.js";
import { envSiteName, ROLE_NAME } from "./credentials.js";
import {
  ENV_KEY,
  type EnvEntry,
  type EnvStore,
  memoryEnvStore,
  WouldReplace,
} from "./env-store.js";
import { OWNER_NAME } from "./owner.js";

/** A vendor: lowercase, starts with a letter (`anthropic`, `exa`, `google-maps`). */
export const KEY_SITE = /^[a-z][a-z0-9-]{0,39}$/;
/** A key's label: lowercase letters and digits with `.` and `-` inside (`autobrowse-prod`, `env-0`). */
export const KEY_ACCOUNT = /^[a-z0-9][a-z0-9.-]{0,63}$/;

const iso = z.string().datetime();

export const apiKeySchema = z
  .object({
    /** The vendor. */
    site: z.string().regex(KEY_SITE, "a site is a lowercase word (a-z, 0-9 and -), 40 at most"),
    /** The label; with the site it makes the address `site@account`. */
    account: z
      .string()
      .regex(KEY_ACCOUNT, "an account is lowercase letters, digits, . and -, 64 at most"),
    /** `wren` (the operator) or an owner name. */
    owner: z
      .string()
      .regex(OWNER_NAME, "an owner is lowercase letters, digits and _, starting with a letter"),
    secret: z.string().trim().min(1),
    /** The login credential the key was minted from (`anthropic@william`). */
    via: z.string().min(1).optional(),
    /** The vendor's own name or id for the key (the Console key name). */
    vendorId: z.string().min(1).optional(),
    /** What the key is for. `default` is the one the bare env name projects from. */
    purposes: z
      .array(z.string().regex(ROLE_NAME, "a purpose is a lowercase word (a-z, 0-9, . and -)"))
      .default([]),
    status: z.enum(["live", "spent", "revoked"]).default("live"),
    /** When a spent key comes back. A spent key with no date stays out until it is put again. */
    spentUntil: iso.optional(),
    madeAt: iso,
    revokedAt: iso.optional(),
    /** A monthly cap. */
    cap: z.object({ amount: z.number().positive(), unit: z.enum(["calls", "micros"]) }).optional(),
    /**
     * Env names this key fills besides the vendor's ring names (`CLOUDFLARE_API_TOKEN`).
     * The projection writes them. No two keys of one owner that can be used share one.
     */
    env: z
      .array(z.string().regex(ENV_KEY, "an env name is capital letters, digits and _"))
      .default([]),
    /** The keys this one replaced: ids and times, never a secret. */
    previous: z
      .array(
        z.object({
          id: z.string().regex(/^[0-9a-f]{12}$/, "an id is 12 hex characters"),
          vendorId: z.string().min(1).optional(),
          revokedAt: iso,
        }),
      )
      .default([]),
  })
  .refine((k) => k.status === "spent" || k.spentUntil === undefined, {
    message: "spentUntil goes with status spent only",
    path: ["spentUntil"],
  })
  .refine((k) => k.status === "revoked" || k.revokedAt === undefined, {
    message: "revokedAt goes with status revoked only",
    path: ["revokedAt"],
  });

export type ApiKey = z.infer<typeof apiKeySchema>;
export type ApiKeyInput = z.input<typeof apiKeySchema>;

/** A key without its secret: what every listing returns. */
export type KeyInfo = Omit<ApiKey, "secret"> & { address: string; id: string };

/** A short name for a key that is safe to log: sha256 of the secret, 12 hex characters. */
export const keyId = (secret: string): string =>
  createHash("sha256").update(secret).digest("hex").slice(0, 12);

/** `site@account`. Throws, naming the rule broken, when either part is not valid. */
export function keyAddress(site: string, account: string): string {
  if (!KEY_SITE.test(site))
    throw new Error(`key site "${site}": a lowercase word (a-z, 0-9 and -), 40 at most`);
  if (!KEY_ACCOUNT.test(account))
    throw new Error(
      `key account "${account}": lowercase letters, digits, . and -, starting with a letter or digit, 64 at most`,
    );
  return `${site}@${account}`;
}

export function parseKeyAddress(address: string): { site: string; account: string } {
  const at = address.indexOf("@");
  if (at < 0) throw new Error(`key address "${address}": must be site@account`);
  const site = address.slice(0, at);
  const account = address.slice(at + 1);
  keyAddress(site, account);
  return { site, account };
}

export function keyInfo(key: ApiKey): KeyInfo {
  const { secret, ...rest } = key;
  return { ...rest, address: keyAddress(key.site, key.account), id: keyId(secret) };
}

/** Live now: `live`, or `spent` with a `spentUntil` that has passed. `now` is epoch ms. */
export function liveAt(key: Pick<ApiKey, "status" | "spentUntil">, now = Date.now()): boolean {
  if (key.status === "live") return true;
  return (
    key.status === "spent" && key.spentUntil !== undefined && Date.parse(key.spentUntil) <= now
  );
}

/** Digits compare as numbers, so `env-2` comes before `env-10`. */
function naturalCompare(a: string, b: string): number {
  const x = a.match(/\d+|\D+/g) ?? [];
  const y = b.match(/\d+|\D+/g) ?? [];
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const p = x[i] as string;
    const q = y[i] as string;
    if (p === q) continue;
    if (/^\d/.test(p) && /^\d/.test(q)) {
      const pn = p.replace(/^0+(?=\d)/, "");
      const qn = q.replace(/^0+(?=\d)/, "");
      if (pn.length !== qn.length) return pn.length - qn.length;
      if (pn !== qn) return pn < qn ? -1 : 1;
    }
    return p < q ? -1 : 1;
  }
  return x.length - y.length;
}

/**
 * The one ring order: the key holding `purpose` (when given), then the
 * `default` key, then the rest by `madeAt`; ties by account in natural order.
 * `keysFor` and the env projection both use it.
 */
function ringOrder<T extends Pick<ApiKey, "account" | "purposes" | "madeAt">>(
  keys: readonly T[],
  purpose?: string,
): T[] {
  const rank = (k: T) =>
    purpose !== undefined && k.purposes.includes(purpose)
      ? 0
      : k.purposes.includes("default")
        ? 1
        : 2;
  return [...keys].sort(
    (a, b) =>
      rank(a) - rank(b) ||
      Date.parse(a.madeAt) - Date.parse(b.madeAt) ||
      naturalCompare(a.account, b.account),
  );
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

export interface KeyStore {
  get(address: string): Promise<ApiKey | null>;
  /** The address comes from `site` and `account`. Refuses a purpose another live key of the owner holds. */
  put(key: ApiKeyInput): Promise<ApiKey>;
  /** Every key without its secret, sorted by address. */
  list(): Promise<KeyInfo[]>;
  remove(address: string): Promise<boolean>;
}

/** The row a key sits in: the address as an env name (`exa@env-1` is `EXA__ENV_1`). */
export function keyRowName(address: string): string {
  parseKeyAddress(address);
  return envSiteName(address);
}

const addressOf = (k: Pick<ApiKey, "site" | "account">) => keyAddress(k.site, k.account);

/**
 * Keys in an `EnvStore`, one row per key: the value is the key as JSON, the
 * name is `keyRowName(address)`. Point the store at a place of its own (SSM
 * keeps 100 versions of each row: the key's history).
 */
export function envKeys(store: EnvStore): KeyStore {
  const parseRow = (name: string, raw: string): ApiKey => {
    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch {
      // Not the parser's message: it quotes the start of the text.
      throw new Error(`key row ${name}: not JSON`);
    }
    const parsed = apiKeySchema.safeParse(json);
    if (!parsed.success)
      throw new Error(
        `key row ${name}: ${parsed.error.issues.map((i) => `${i.path.join(".") || "row"} ${i.message}`).join("; ")}`,
      );
    const home = keyRowName(addressOf(parsed.data));
    if (home !== name)
      throw new Error(`key row ${name} holds ${addressOf(parsed.data)}, which belongs in ${home}`);
    return parsed.data;
  };
  const readAll = async (): Promise<ApiKey[]> =>
    (await store.all()).map((e) => parseRow(e.name, e.value));

  return {
    async get(address) {
      const name = keyRowName(address);
      const raw = await store.get(name);
      if (raw === null) return null;
      const key = parseRow(name, raw);
      // Two addresses can share a row name (`x@a-.b` and `x@a.-b`): put refuses the second.
      return addressOf(key) === address ? key : null;
    },

    async put(input) {
      const key = apiKeySchema.parse(input);
      const address = addressOf(key);
      const name = keyRowName(address);
      const there = await store.get(name);
      if (there !== null) {
        const before = parseRow(name, there);
        const held = addressOf(before);
        if (held !== address) throw new Error(`key ${address}: row ${name} already holds ${held}`);
        // A new secret at a held address is a rotation: it names the key it replaced.
        const was = keyId(before.secret);
        if (before.secret !== key.secret && !key.previous.some((p) => p.id === was))
          throw new Error(
            `key ${address} already holds another secret (${was}); nothing was written. A second key takes its own label; a rotation lists ${was} in \`previous\``,
          );
      }
      for (const n of key.env)
        if (isProjectedName(n))
          throw new Error(`key ${address}: ${n} is a ring name, set by the projection`);
      // A revoked key holds nothing, so only a key that can be used is checked.
      if (key.status !== "revoked") {
        for (const other of await readAll()) {
          if (other.owner !== key.owner || other.status === "revoked") continue;
          const otherAddress = addressOf(other);
          if (otherAddress === address) continue;
          const names = key.env.filter((n) => other.env.includes(n));
          if (names.length)
            throw new Error(
              `key ${address}: ${otherAddress} already fills ${names.join(", ")} for ${key.owner}; one env name, one key`,
            );
          if (other.site !== key.site) continue;
          const shared = key.purposes.filter((p) => other.purposes.includes(p));
          if (shared.length)
            throw new Error(
              `key ${address}: ${otherAddress} already holds ${shared.join(", ")} for ${key.owner}; \`creds key purpose ${address} ${shared[0]}\` moves it`,
            );
        }
      }
      const row = JSON.stringify(key);
      // An unchanged key writes nothing: no version churn in the key's history.
      // The row is the vault's own: the checks above are its replace rule.
      if (there !== row) await store.put(name, row, { replace: true });
      return key;
    },

    async list() {
      return (await readAll()).map(keyInfo).sort((a, b) => naturalCompare(a.address, b.address));
    },

    async remove(address) {
      const name = keyRowName(address);
      const raw = await store.get(name);
      if (raw === null) return false;
      try {
        if (addressOf(parseRow(name, raw)) !== address) return false;
      } catch {
        // A row that does not parse is still this address's row: it can go.
      }
      return store.remove(name);
    },
  };
}

/** Keys in memory, for tests and callers. `init` is put in without the purpose check. */
export function memoryKeys(init: ApiKeyInput[] = []): KeyStore {
  const rows: Record<string, string> = {};
  for (const input of init) {
    const key = apiKeySchema.parse(input);
    rows[keyRowName(addressOf(key))] = JSON.stringify(key);
  }
  return envKeys(memoryEnvStore(rows));
}

/**
 * Gives `address` these purposes (added to the ones it has) and takes them
 * off any other key of the same site and owner that can still be used.
 * The others are written first, so a stop in between leaves a purpose with
 * no holder, never two. Answers the keys that changed, the target first.
 */
export async function movePurposes(
  store: KeyStore,
  address: string,
  purposes: string[],
): Promise<KeyInfo[]> {
  for (const p of purposes)
    if (!ROLE_NAME.test(p)) throw new Error(`purpose "${p}": a lowercase word (a-z, 0-9, . and -)`);
  const target = await store.get(address);
  if (!target) throw new Error(`no key ${address}`);
  if (target.status === "revoked")
    throw new Error(`key ${address} is revoked: it holds no purpose`);
  const changed: KeyInfo[] = [];
  for (const info of await store.list()) {
    if (
      info.address === address ||
      info.site !== target.site ||
      info.owner !== target.owner ||
      info.status === "revoked" ||
      !info.purposes.some((p) => purposes.includes(p))
    )
      continue;
    const other = await store.get(info.address);
    if (!other) continue;
    const kept = other.purposes.filter((p) => !purposes.includes(p));
    changed.push(keyInfo(await store.put({ ...other, purposes: kept })));
  }
  const next = [...new Set([...target.purposes, ...purposes])];
  if (next.length !== target.purposes.length)
    changed.unshift(keyInfo(await store.put({ ...target, purposes: next })));
  return changed;
}

// ---------------------------------------------------------------------------
// The ring
// ---------------------------------------------------------------------------

export interface KeysForOptions {
  owner: string;
  vendor: string;
  purpose?: string | undefined;
  /** Epoch ms; default now. */
  now?: number | undefined;
}

/**
 * The live keys of `vendor` for `owner`, in ring order: the key holding
 * `purpose`, then the `default` key, then the rest by `madeAt` (ties by
 * account, `env-2` before `env-10`). The same key id appears once.
 */
export async function keysFor(store: KeyStore, o: KeysForOptions): Promise<ApiKey[]> {
  const now = o.now ?? Date.now();
  const ring = ringOrder(
    (await store.list()).filter(
      (k) => k.site === o.vendor && k.owner === o.owner && liveAt(k, now),
    ),
    o.purpose,
  );
  const out: ApiKey[] = [];
  const seen = new Set<string>();
  for (const info of ring) {
    if (seen.has(info.id)) continue;
    seen.add(info.id);
    const key = await store.get(info.address);
    if (key) out.push(key);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The env projection
// ---------------------------------------------------------------------------

/** `google-maps` is `GOOGLE_MAPS`: the stem of its env names. */
export const vendorBase = (site: string): string => site.toUpperCase().replace(/-/g, "_");

const KEY_NAME = /^([A-Z][A-Z0-9_]*)_API_KEY(?:_([1-9][0-9]*))?$/;
const NUM_NAME = /^NUM_([A-Z][A-Z0-9_]*)$/;
const vendorOfBase = (base: string): string | null => {
  const vendor = base.toLowerCase().replace(/_/g, "-");
  return KEY_SITE.test(vendor) ? vendor : null;
};

/** `EXA_API_KEY` is `{ vendor: "exa", slot: null }`, `EXA_API_KEY_2` is slot 2; anything else is null. */
export function parseVendorKeyName(name: string): { vendor: string; slot: number | null } | null {
  const m = KEY_NAME.exec(name);
  const vendor = m?.[1] ? vendorOfBase(m[1]) : null;
  if (!m || !vendor) return null;
  return { vendor, slot: m[2] === undefined ? null : Number(m[2]) };
}

/**
 * A name the projection owns: `X_API_KEY`, `X_API_KEY_<n>` or `NUM_X`. Any
 * `NUM_<WORD>` counts: the name alone cannot tell a ring count from another setting.
 */
export function isProjectedName(name: string): boolean {
  if (parseVendorKeyName(name)) return true;
  const m = NUM_NAME.exec(name);
  return Boolean(m?.[1] && vendorOfBase(m[1]));
}

/**
 * The env names for a set of keys of one owner, per vendor: `<BASE>_API_KEY`
 * from the first key in ring order (the `default` one when there is one),
 * `<BASE>_API_KEY_1..n` from the rest, `NUM_<BASE>` = n when n > 0, then each
 * key's own `env` names. Revoked keys are left out; a vendor whose keys are
 * all revoked answers an empty list. Keys of several owners throw: project one
 * owner at a time.
 */
export function projectKeys(keys: ApiKey[]): Map<string, EnvEntry[]> {
  const owners = [...new Set(keys.map((k) => k.owner))].sort();
  if (owners.length > 1)
    throw new Error(`projectKeys: keys of several owners (${owners.join(", ")}); one at a time`);
  const bySite = new Map<string, ApiKey[]>();
  for (const k of keys) bySite.set(k.site, [...(bySite.get(k.site) ?? []), k]);
  const out = new Map<string, EnvEntry[]>();
  for (const site of [...bySite.keys()].sort()) {
    const base = vendorBase(site);
    const ring = ringOrder((bySite.get(site) ?? []).filter((k) => k.status !== "revoked"));
    const entries = ring.map((k, i) => ({
      name: i === 0 ? `${base}_API_KEY` : `${base}_API_KEY_${i}`,
      value: k.secret,
    }));
    if (ring.length > 1) entries.push({ name: `NUM_${base}`, value: String(ring.length - 1) });
    for (const k of ring) for (const name of k.env) entries.push({ name, value: k.secret });
    out.set(site, entries);
  }
  return out;
}

export interface ProjectionOptions {
  /** Project these vendors, even ones with no key left (their names are cleared). Default: the vendors in `keys`. */
  vendors?: string[] | undefined;
  /**
   * A key's `env` name may hold a value the key never had, and the projection replaces it.
   * Without it `applyProjection` throws `WouldReplace` and writes nothing.
   */
  replace?: boolean | undefined;
}

/** One name where the store and the vault differ. Ids are `keyId`s; a `NUM_` row holds the number. */
export interface ProjectionChange {
  name: string;
  want: string | null;
  have: string | null;
}

const slotOrder = (name: string): number => {
  if (NUM_NAME.test(name)) return Number.POSITIVE_INFINITY;
  return parseVendorKeyName(name)?.slot ?? 0;
};

async function planProjection(
  store: EnvStore,
  keys: ApiKey[],
  o: ProjectionOptions,
): Promise<ProjectionStep[]> {
  const projected = projectKeys(keys);
  const vendors = [...new Set(o.vendors ?? projected.keys())].sort();
  const listed = (await store.list()).map((e) => e.name);
  const steps: ProjectionStep[] = [];
  for (const vendor of vendors) {
    if (!KEY_SITE.test(vendor)) throw new Error(`projection: "${vendor}" is not a vendor name`);
    const num = `NUM_${vendorBase(vendor)}`;
    const wanted = new Map((projected.get(vendor) ?? []).map((e) => [e.name, e.value]));
    const held = listed.filter((n) => n === num || parseVendorKeyName(n)?.vendor === vendor);
    const names = [...new Set([...wanted.keys(), ...held])].sort(
      (a, b) => slotOrder(a) - slotOrder(b),
    );
    const there = await store.getMany(names);
    // A key compares by id; the count is a number, and anything else in its place by id too.
    const mark = (name: string, v: string | undefined) =>
      v === undefined ? null : name === num && /^\d{1,4}$/.test(v) ? v : keyId(v);
    for (const name of names) {
      const value = wanted.get(name) ?? null;
      const want = mark(name, value ?? undefined);
      const have = mark(name, there[name]);
      if (want !== have)
        steps.push({ name, want, have, value, heldLength: there[name]?.length ?? 0 });
    }
  }
  return steps;
}

type ProjectionStep = ProjectionChange & { value: string | null; heldLength: number };

/**
 * What `applyProjection` would change: the names whose stored value is not
 * what the vault projects, as ids (never values). Empty means the env equals
 * the vault.
 */
export async function projectionDiff(
  store: EnvStore,
  keys: ApiKey[],
  o: ProjectionOptions = {},
): Promise<ProjectionChange[]> {
  return (await planProjection(store, keys, o)).map(({ name, want, have }) => ({
    name,
    want,
    have,
  }));
}

/**
 * Makes the store's key names equal the vault's projection: puts each name
 * whose value differs, removes stale `<BASE>_API_KEY_k` (k > n) and a stale
 * `NUM_<BASE>`. A name already equal is not written. Puts go first, then
 * removals. Answers names only.
 *
 * Ring names are the projection's own: they are replaced. A key's `env` name is
 * replaced only when it holds a secret that key had before (a rotation); any
 * other value throws `WouldReplace` before the first write, unless `o.replace`.
 * An `env` name no key fills any more is left as it is.
 */
export async function applyProjection(
  store: EnvStore,
  keys: ApiKey[],
  o: ProjectionOptions = {},
): Promise<{ put: string[]; removed: string[] }> {
  const steps = await planProjection(store, keys, o);
  const put: string[] = [];
  const removed: string[] = [];
  if (!o.replace)
    for (const s of steps) {
      if (s.value === null || s.have === null || isProjectedName(s.name)) continue;
      const before = keys.find((k) => k.status !== "revoked" && k.env.includes(s.name))?.previous;
      if (!before?.some((p) => p.id === s.have))
        throw new WouldReplace(s.name, s.heldLength, "the env store");
    }
  for (const s of steps) {
    if (s.value === null) continue;
    await store.put(s.name, s.value, { replace: true });
    put.push(s.name);
  }
  for (const s of steps) {
    if (s.value !== null) continue;
    await store.remove(s.name);
    removed.push(s.name);
  }
  return { put, removed };
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/**
 * Per key id: how many allowed uses the audit holds and when the last one
 * was. A key use is a `SecretUse` with `keyId` set (`credential` is the
 * address, `field` is `secret`). Refused uses and rows without a `keyId` are left out.
 */
export function keyUses(uses: SecretUse[]): Map<string, { uses: number; lastUsedAt: string }> {
  const out = new Map<string, { uses: number; lastUsedAt: string }>();
  for (const u of uses) {
    if (!u.allowed || !u.keyId) continue;
    const had = out.get(u.keyId);
    if (!had) out.set(u.keyId, { uses: 1, lastUsedAt: u.at });
    else
      out.set(u.keyId, {
        uses: had.uses + 1,
        lastUsedAt: Date.parse(u.at) > Date.parse(had.lastUsedAt) ? u.at : had.lastUsedAt,
      });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/**
 * The env store's keys as key inputs: `<BASE>_API_KEY` is account `env-0`
 * with purpose `default`, `<BASE>_API_KEY_<n>` is `env-<n>`, all `live`, all
 * `madeAt` the same time (the ring then orders them by account, which is
 * `_1..n` again). `NUM_<BASE>` is read, not kept: a numbered name above it
 * is skipped, as today's rings never read it. Within a vendor, one value
 * under two names is kept once, at the lower slot. Pure: values pass through,
 * and `skipped` names the entry and why, never a value.
 */
export function keysFromEnv(
  entries: EnvEntry[],
  o: { owner: string; madeAt: string },
): { keys: ApiKeyInput[]; skipped: { name: string; why: string }[] } {
  const counts = new Map<string, number>();
  for (const e of entries) {
    const m = NUM_NAME.exec(e.name);
    if (m?.[1]) counts.set(m[1], Number.parseInt(e.value, 10) || 0);
  }
  const keys: ApiKeyInput[] = [];
  const skipped: { name: string; why: string }[] = [];
  const named: { name: string; value: string; vendor: string; slot: number | null }[] = [];
  for (const e of entries) {
    const parsed = parseVendorKeyName(e.name);
    if (parsed) named.push({ ...e, ...parsed });
    else if (/_API_KEY(?:_\d+)?$/.test(e.name))
      skipped.push({ name: e.name, why: "not a vendor key name" });
  }
  named.sort((a, b) => a.vendor.localeCompare(b.vendor) || (a.slot ?? 0) - (b.slot ?? 0));
  const first = new Map<string, string>();
  for (const e of named) {
    const base = vendorBase(e.vendor);
    if (e.slot !== null && e.slot > (counts.get(base) ?? 0)) {
      skipped.push({ name: e.name, why: `past NUM_${base}` });
      continue;
    }
    const secret = e.value.trim();
    if (!secret) {
      skipped.push({ name: e.name, why: "empty" });
      continue;
    }
    const twin = first.get(`${e.vendor} ${secret}`);
    if (twin) {
      skipped.push({ name: e.name, why: `same key as ${twin}` });
      continue;
    }
    first.set(`${e.vendor} ${secret}`, e.name);
    keys.push({
      site: e.vendor,
      account: `env-${e.slot ?? 0}`,
      owner: o.owner,
      secret,
      purposes: e.slot === null ? ["default"] : [],
      status: "live",
      madeAt: o.madeAt,
    });
  }
  return { keys, skipped };
}
