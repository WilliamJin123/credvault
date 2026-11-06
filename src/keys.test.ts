import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { fileAudit, type SecretUse } from "./audit.js";
import { verifyChain } from "./chain.js";
import { siteFromEnvName } from "./credentials.js";
import { type EnvEntry, memoryEnvStore, type PutOptions, WouldReplace } from "./env-store.js";
import {
  type ApiKey,
  type ApiKeyInput,
  apiKeySchema,
  applyProjection,
  envKeys,
  isProjectedName,
  keyAddress,
  keyId,
  keyInfo,
  keyRowName,
  keysFor,
  keysFromEnv,
  keyUses,
  liveAt,
  memoryKeys,
  movePurposes,
  parseKeyAddress,
  parseVendorKeyName,
  projectionDiff,
  projectKeys,
  vendorBase,
} from "./keys.js";

const T0 = "2026-10-01T00:00:00.000Z";
const T1 = "2026-10-02T00:00:00.000Z";
const T2 = "2026-10-03T00:00:00.000Z";
const NOW = Date.parse("2026-10-15T00:00:00.000Z");
/** Synthetic keys only. */
const sk = (n: string) => `sk-test-${n.repeat(24)}`;

const mk = (site: string, account: string, over: Partial<ApiKeyInput> = {}): ApiKeyInput => ({
  site,
  account,
  owner: "wren",
  secret: sk(account.replace(/[^a-z0-9]/g, "x")),
  madeAt: T0,
  ...over,
});

const parse = (k: ApiKeyInput): ApiKey => apiKeySchema.parse(k);

describe("the key", () => {
  it("fills defaults and trims the secret", () => {
    const k = parse(mk("exa", "env-1", { secret: `  ${sk("a")}\n` }));
    expect(k.secret).toBe(sk("a"));
    expect(k.purposes).toEqual([]);
    expect(k.status).toBe("live");
    expect(k.previous).toEqual([]);
  });

  it("refuses spentUntil without spent and revokedAt without revoked", () => {
    expect(() => parse(mk("exa", "a", { spentUntil: T1 }))).toThrow(/spentUntil/);
    expect(() => parse(mk("exa", "a", { status: "revoked", spentUntil: T1 }))).toThrow(
      /spentUntil/,
    );
    expect(() => parse(mk("exa", "a", { revokedAt: T1 }))).toThrow(/revokedAt/);
    expect(parse(mk("exa", "a", { status: "spent", spentUntil: T1 })).spentUntil).toBe(T1);
    expect(parse(mk("exa", "a", { status: "revoked", revokedAt: T1 })).revokedAt).toBe(T1);
  });

  it("refuses a bad site, account, owner, purpose, secret, cap and time", () => {
    for (const site of ["Exa", "1exa", "ex_a", "", "a".repeat(41), "exa@x"])
      expect(() => parse(mk(site, "a"))).toThrow();
    for (const account of ["", "-a", ".a", "A", "a_b", "a@b", "a".repeat(65)])
      expect(() => parse(mk("exa", account))).toThrow();
    expect(() => parse(mk("exa", "a", { owner: "Wren" }))).toThrow();
    expect(() => parse(mk("exa", "a", { owner: "do_careers" }))).not.toThrow();
    expect(() => parse(mk("exa", "a", { purposes: ["Bulk"] }))).toThrow();
    expect(() => parse(mk("exa", "a", { secret: "   " }))).toThrow();
    expect(() => parse(mk("exa", "a", { madeAt: "yesterday" }))).toThrow();
    expect(() => parse(mk("exa", "a", { cap: { amount: 0, unit: "calls" } }))).toThrow();
    expect(() => parse(mk("exa", "a", { cap: { amount: 5, unit: "euros" as "calls" } }))).toThrow();
    expect(parse(mk("exa", "a", { cap: { amount: 2000, unit: "calls" } })).cap).toEqual({
      amount: 2000,
      unit: "calls",
    });
    expect(() => parse(mk("exa", "a", { previous: [{ id: "nope", revokedAt: T1 }] }))).toThrow();
  });

  it("keyId is a 12 character hash of the secret", () => {
    expect(keyId("abc")).toBe("ba7816bf8f01");
    expect(keyId(sk("a"))).toHaveLength(12);
    expect(keyId(sk("a"))).not.toBe(keyId(sk("b")));
  });

  it("addresses round trip, with . and -, and name the rule they break", () => {
    for (const [site, account] of [
      ["exa", "env-1"],
      ["google-maps", "autobrowse-prod"],
      ["anthropic", "console.v2"],
      ["x", "0"],
    ] as const) {
      const address = keyAddress(site, account);
      expect(address).toBe(`${site}@${account}`);
      expect(parseKeyAddress(address)).toEqual({ site, account });
      expect(siteFromEnvName(keyRowName(address))).toBe(address);
    }
    expect(keyRowName("exa@env-1")).toBe("EXA__ENV_1");
    expect(keyRowName("anthropic@console.v2")).toBe("ANTHROPIC__CONSOLE___V2");
    expect(() => parseKeyAddress("exa")).toThrow(/site@account/);
    expect(() => parseKeyAddress("Exa@a")).toThrow(/site/);
    expect(() => parseKeyAddress("exa@-a")).toThrow(/account/);
    expect(() => parseKeyAddress("exa@a@b")).toThrow(/account/);
    expect(() => keyAddress("exa", "A")).toThrow(/account/);
  });

  it("keyInfo drops the secret and adds the address and id", () => {
    const k = parse(mk("exa", "env-1", { purposes: ["bulk"] }));
    const info = keyInfo(k);
    expect(info).toMatchObject({ address: "exa@env-1", id: keyId(k.secret), purposes: ["bulk"] });
    expect(JSON.stringify(info)).not.toContain(k.secret);
    expect("secret" in info).toBe(false);
  });

  it("liveAt: live, or spent once its date has passed", () => {
    expect(liveAt(parse(mk("exa", "a")), NOW)).toBe(true);
    const spent = (until?: string) =>
      parse(mk("exa", "a", { status: "spent", ...(until ? { spentUntil: until } : {}) }));
    expect(liveAt(spent("2026-10-16T00:00:00.000Z"), NOW)).toBe(false);
    expect(liveAt(spent("2026-10-15T00:00:00.000Z"), NOW)).toBe(true);
    expect(liveAt(spent("2026-10-14T00:00:00.000Z"), NOW)).toBe(true);
    expect(liveAt(spent(), NOW)).toBe(false);
    expect(liveAt(parse(mk("exa", "a", { status: "revoked" })), NOW)).toBe(false);
  });
});

describe("envKeys", () => {
  it("puts, gets, lists and removes; a list never carries a secret", async () => {
    const env = memoryEnvStore();
    const keys = envKeys(env);
    const a = await keys.put(mk("exa", "env-2", { vendorId: "console-key-a" }));
    await keys.put(mk("exa", "env-10"));
    await keys.put(mk("anthropic", "autobrowse-prod", { owner: "do_acme" }));
    expect(Object.keys(env.values).sort()).toEqual([
      "ANTHROPIC__AUTOBROWSE_PROD",
      "EXA__ENV_10",
      "EXA__ENV_2",
    ]);
    expect(await keys.get("exa@env-2")).toEqual(a);
    expect(await keys.get("exa@env-3")).toBeNull();
    const list = await keys.list();
    expect(list.map((k) => k.address)).toEqual([
      "anthropic@autobrowse-prod",
      "exa@env-2",
      "exa@env-10",
    ]);
    const text = JSON.stringify(list);
    expect(text).not.toContain("sk-test");
    expect(text).not.toContain('"secret"');
    expect(list[1]).toMatchObject({ id: keyId(a.secret), vendorId: "console-key-a" });
    expect(await keys.remove("exa@env-2")).toBe(true);
    expect(await keys.remove("exa@env-2")).toBe(false);
    expect((await keys.list()).map((k) => k.address)).toEqual([
      "anthropic@autobrowse-prod",
      "exa@env-10",
    ]);
  });

  it("an unchanged put writes nothing", async () => {
    const env = memoryEnvStore();
    const writes: string[] = [];
    const watched = Object.assign(Object.create(env), {
      put: async (n: string, v: string, o?: PutOptions) => {
        writes.push(n);
        await env.put(n, v, o);
      },
    }) as typeof env;
    const keys = envKeys(watched);
    await keys.put(mk("exa", "a"));
    await keys.put(mk("exa", "a"));
    expect(writes).toEqual(["EXA__A"]);
  });

  it("a purpose clash throws, names both addresses, and writes nothing", async () => {
    const env = memoryEnvStore();
    const keys = envKeys(env);
    await keys.put(mk("exa", "env-0", { purposes: ["default"] }));
    const before = { ...env.values };
    const err = await keys
      .put(mk("exa", "env-1", { purposes: ["bulk", "default"] }))
      .catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain("exa@env-1");
    expect(err.message).toContain("exa@env-0");
    expect(err.message).toContain("creds key purpose exa@env-1 default");
    expect(err.message).not.toContain("sk-test");
    expect(env.values).toEqual(before);
    // Another owner, another vendor, a revoked holder, and the key itself are not clashes.
    await keys.put(mk("exa", "env-2", { purposes: ["default"], owner: "do_acme" }));
    await keys.put(mk("cohere", "env-0", { purposes: ["default"] }));
    await keys.put(mk("exa", "env-0", { purposes: ["default", "bulk"] }));
    await keys.put(mk("exa", "env-0", { purposes: ["default"], status: "revoked" }));
    await keys.put(mk("exa", "env-1", { purposes: ["default"] }));
  });

  it("a revoked key can be put with purposes it used to hold", async () => {
    const keys = memoryKeys([mk("exa", "old", { purposes: ["default"] })]);
    await keys.put(mk("exa", "old", { purposes: ["default"], status: "revoked", revokedAt: T1 }));
    await keys.put(mk("exa", "new", { purposes: ["default"] }));
    expect((await keys.list()).map((k) => [k.address, k.status])).toEqual([
      ["exa@new", "live"],
      ["exa@old", "revoked"],
    ]);
  });

  it("movePurposes gives purposes to one key and takes them off the others", async () => {
    const keys = memoryKeys([
      mk("exa", "a", { purposes: ["default", "drafts"] }),
      mk("exa", "b", { purposes: ["bulk"] }),
      mk("exa", "c", { purposes: ["default"], status: "revoked" }),
      mk("exa", "d", { purposes: ["drafts"], owner: "do_acme" }),
      mk("cohere", "a", { purposes: ["default"] }),
    ]);
    const changed = await movePurposes(keys, "exa@b", ["default"]);
    expect(changed.map((k) => k.address)).toEqual(["exa@b", "exa@a"]);
    const purposes = async (a: string) => (await keys.get(a))?.purposes;
    expect(await purposes("exa@a")).toEqual(["drafts"]);
    expect(await purposes("exa@b")).toEqual(["bulk", "default"]);
    // Not touched: a revoked key, another owner, another vendor.
    expect(await purposes("exa@c")).toEqual(["default"]);
    expect(await purposes("exa@d")).toEqual(["drafts"]);
    expect(await purposes("cohere@a")).toEqual(["default"]);
    expect(await movePurposes(keys, "exa@b", ["default"])).toEqual([]);
    await expect(movePurposes(keys, "exa@zzz", ["default"])).rejects.toThrow(/no key exa@zzz/);
    await expect(movePurposes(keys, "exa@c", ["bulk"])).rejects.toThrow(/revoked/);
    await expect(movePurposes(keys, "exa@b", ["Bad"])).rejects.toThrow(/purpose/);
  });

  it("a row that is not a key names the row and never the text", async () => {
    const env = memoryEnvStore({
      EXA__A: sk("z"),
      EXA__B: JSON.stringify({
        site: "Bad",
        account: "b",
        owner: "wren",
        secret: sk("y"),
        madeAt: T0,
      }),
      EXA__C: JSON.stringify(parse(mk("exa", "other"))),
    });
    const keys = envKeys(env);
    for (const name of ["EXA__A", "EXA__B", "EXA__C"]) {
      const err = await envKeys(memoryEnvStore({ [name]: env.values[name] as string }))
        .list()
        .catch((e) => e);
      expect(err.message).toContain(`key row ${name}`);
      expect(err.message).not.toContain("sk-test");
    }
    await expect(keys.list()).rejects.toThrow(/key row EXA__A/);
    // A broken row can still be removed by its address.
    expect(await keys.remove("exa@a")).toBe(true);
  });

  it("two addresses that share a row name do not overwrite each other", async () => {
    const keys = memoryKeys();
    expect(keyRowName("x@a-.b")).toBe(keyRowName("x@a.-b"));
    await keys.put(mk("x", "a-.b"));
    await expect(keys.put(mk("x", "a.-b"))).rejects.toThrow(/already holds x@a-\.b/);
    expect(await keys.get("x@a.-b")).toBeNull();
    expect(await keys.remove("x@a.-b")).toBe(false);
    expect(await keys.get("x@a-.b")).not.toBeNull();
  });
});

describe("keysFor", () => {
  const ring = async (over: { purpose?: string; owner?: string; now?: number } = {}) =>
    (await keysFor(store, { owner: "wren", vendor: "exa", now: NOW, ...over })).map(
      (k) => k.account,
    );
  const store = memoryKeys([
    mk("exa", "env-10", { madeAt: T0 }),
    mk("exa", "env-2", { madeAt: T0 }),
    mk("exa", "late", { madeAt: T2 }),
    mk("exa", "main", { madeAt: T1, purposes: ["default"] }),
    mk("exa", "drafty", { madeAt: T2, purposes: ["drafts"] }),
    mk("exa", "gone", { madeAt: T0, status: "revoked" }),
    mk("exa", "theirs", { madeAt: T0, owner: "do_acme" }),
    mk("cohere", "other", { madeAt: T0 }),
  ]);

  it("orders by default, then madeAt, then natural account order", async () => {
    expect(await ring()).toEqual(["main", "env-2", "env-10", "drafty", "late"]);
  });

  it("puts the key holding the purpose first", async () => {
    expect(await ring({ purpose: "drafts" })).toEqual([
      "drafty",
      "main",
      "env-2",
      "env-10",
      "late",
    ]);
    expect(await ring({ purpose: "nobody" })).toEqual(await ring());
  });

  it("leaves out revoked keys, other owners and other vendors", async () => {
    const all = await ring();
    expect(all).not.toContain("gone");
    expect(all).not.toContain("theirs");
    expect(all).not.toContain("other");
    expect(await ring({ owner: "do_acme" })).toEqual(["theirs"]);
    expect(await ring({ owner: "nobody" })).toEqual([]);
  });

  it("brings a spent key back on its date", async () => {
    const spent = memoryKeys([
      mk("exa", "a", { status: "spent", spentUntil: "2026-11-01T00:00:00.000Z" }),
      mk("exa", "b", { madeAt: T1 }),
    ]);
    const accounts = async (now: number) =>
      (await keysFor(spent, { owner: "wren", vendor: "exa", now })).map((k) => k.account);
    expect(await accounts(NOW)).toEqual(["b"]);
    expect(await accounts(Date.parse("2026-11-01T00:00:00.000Z"))).toEqual(["a", "b"]);
  });

  it("answers a key once, even under two accounts", async () => {
    const dup = memoryKeys([
      mk("exa", "a", { secret: sk("q") }),
      mk("exa", "b", { secret: sk("q"), madeAt: T1 }),
    ]);
    expect((await keysFor(dup, { owner: "wren", vendor: "exa" })).map((k) => k.account)).toEqual([
      "a",
    ]);
  });

  it("answers full keys, secret included", async () => {
    const [first] = await keysFor(store, { owner: "wren", vendor: "exa", now: NOW });
    expect(first?.secret).toBe(sk("main".replace(/[^a-z0-9]/g, "x")));
  });
});

describe("env projection", () => {
  const entries = (m: Map<string, EnvEntry[]>, vendor: string) =>
    Object.fromEntries((m.get(vendor) ?? []).map((e) => [e.name, e.value]));

  it("one key: the bare name only", () => {
    const k = parse(mk("exa", "env-0", { purposes: ["default"] }));
    expect(entries(projectKeys([k]), "exa")).toEqual({ EXA_API_KEY: k.secret });
  });

  it("three keys: bare, _1.._2 and NUM", () => {
    const [a, b, c] = ["env-0", "env-1", "env-2"].map((x, i) =>
      parse(mk("google-maps", x, { purposes: i === 0 ? ["default"] : [] })),
    ) as [ApiKey, ApiKey, ApiKey];
    expect(entries(projectKeys([c, a, b]), "google-maps")).toEqual({
      GOOGLE_MAPS_API_KEY: a.secret,
      GOOGLE_MAPS_API_KEY_1: b.secret,
      GOOGLE_MAPS_API_KEY_2: c.secret,
      NUM_GOOGLE_MAPS: "2",
    });
  });

  it("the default key is the bare name even when it is not the oldest", () => {
    const old = parse(mk("exa", "old", { madeAt: T0 }));
    const main = parse(mk("exa", "main", { madeAt: T2, purposes: ["default"] }));
    const mid = parse(mk("exa", "mid", { madeAt: T1 }));
    expect(entries(projectKeys([old, mid, main]), "exa")).toEqual({
      EXA_API_KEY: main.secret,
      EXA_API_KEY_1: old.secret,
      EXA_API_KEY_2: mid.secret,
      NUM_EXA: "2",
    });
  });

  it("with no default key the oldest is the bare name; revoked keys are out, spent ones stay", () => {
    const a = parse(mk("exa", "a", { madeAt: T0, status: "revoked" }));
    const b = parse(mk("exa", "b", { madeAt: T1 }));
    const c = parse(
      mk("exa", "c", { madeAt: T2, status: "spent", spentUntil: "2027-01-01T00:00:00.000Z" }),
    );
    expect(entries(projectKeys([a, b, c]), "exa")).toEqual({
      EXA_API_KEY: b.secret,
      EXA_API_KEY_1: c.secret,
      NUM_EXA: "1",
    });
  });

  it("a vendor with every key revoked is projected as empty", () => {
    const a = parse(mk("exa", "a", { status: "revoked" }));
    expect(projectKeys([a]).get("exa")).toEqual([]);
  });

  it("keys of several owners throw", () => {
    const a = parse(mk("exa", "a"));
    const b = parse(mk("exa", "b", { owner: "do_acme" }));
    expect(() => projectKeys([a, b])).toThrow(/several owners/);
  });

  it("names parse and project back", () => {
    expect(parseVendorKeyName("EXA_API_KEY")).toEqual({ vendor: "exa", slot: null });
    expect(parseVendorKeyName("GOOGLE_MAPS_API_KEY_12")).toEqual({
      vendor: "google-maps",
      slot: 12,
    });
    for (const bad of [
      "API_KEY",
      "EXA_API_KEY_0",
      "EXA_API_KEY_01",
      "EXA_API_KEY_X",
      "exa_api_key",
      "NUM_EXA",
      "1X_API_KEY",
    ])
      expect(parseVendorKeyName(bad)).toBeNull();
    expect(vendorBase("google-maps")).toBe("GOOGLE_MAPS");
    expect(isProjectedName("EXA_API_KEY")).toBe(true);
    expect(isProjectedName("EXA_API_KEY_3")).toBe(true);
    expect(isProjectedName("NUM_EXA")).toBe(true);
    expect(isProjectedName("EXA_API_TOKEN")).toBe(false);
    expect(isProjectedName("NUM_")).toBe(false);
    expect(isProjectedName("PATH")).toBe(false);
  });

  it("apply writes the names, removes stale ones after a revoke, and a second apply writes nothing", async () => {
    const env = memoryEnvStore({ KEEP: "1", OTHER_API_KEY: sk("o") });
    const writes: string[] = [];
    const removes: string[] = [];
    const watched = Object.assign(Object.create(env), {
      put: async (n: string, v: string, o?: PutOptions) => {
        writes.push(n);
        await env.put(n, v, o);
      },
      remove: async (n: string) => {
        removes.push(n);
        return env.remove(n);
      },
    }) as typeof env;
    const k = (x: string, over: Partial<ApiKeyInput> = {}) => parse(mk("exa", x, over));
    const keys = [k("env-0", { purposes: ["default"] }), k("env-1"), k("env-2"), k("env-3")];
    const first = await applyProjection(watched, keys);
    expect(first).toEqual({
      put: ["EXA_API_KEY", "EXA_API_KEY_1", "EXA_API_KEY_2", "EXA_API_KEY_3", "NUM_EXA"],
      removed: [],
    });
    expect(env.values.NUM_EXA).toBe("3");
    expect(await projectionDiff(env, keys)).toEqual([]);

    writes.length = 0;
    expect(await applyProjection(watched, keys)).toEqual({ put: [], removed: [] });
    expect(writes).toEqual([]);

    // env-3 is revoked: _3 is stale and NUM drops to 2.
    const after = [...keys.slice(0, 3), k("env-3", { status: "revoked" })];
    expect(await applyProjection(watched, after)).toEqual({
      put: ["NUM_EXA"],
      removed: ["EXA_API_KEY_3"],
    });
    expect(env.values.NUM_EXA).toBe("2");
    expect(env.values.EXA_API_KEY_3).toBeUndefined();

    // Down to one key: every numbered name and NUM go.
    const one = [
      keys[0] as ApiKey,
      k("env-1", { status: "revoked" }),
      k("env-2", { status: "revoked" }),
    ];
    expect(await applyProjection(watched, one)).toEqual({
      put: [],
      removed: ["EXA_API_KEY_1", "EXA_API_KEY_2", "NUM_EXA"],
    });
    // Names of other vendors and plain settings are never touched.
    expect(env.values.KEEP).toBe("1");
    expect(env.values.OTHER_API_KEY).toBe(sk("o"));
    expect(removes).toContain("NUM_EXA");
  });

  it("a vendor named with no keys left is cleared", async () => {
    const env = memoryEnvStore({
      EXA_API_KEY: sk("a"),
      EXA_API_KEY_1: sk("b"),
      NUM_EXA: "1",
      COHERE_API_KEY: sk("c"),
    });
    // Not named, not in the keys: left alone.
    expect(await applyProjection(env, [])).toEqual({ put: [], removed: [] });
    expect(await applyProjection(env, [], { vendors: ["exa"] })).toEqual({
      put: [],
      removed: ["EXA_API_KEY", "EXA_API_KEY_1", "NUM_EXA"],
    });
    expect(Object.keys(env.values)).toEqual(["COHERE_API_KEY"]);
    await expect(applyProjection(env, [], { vendors: ["Bad_Name"] })).rejects.toThrow(
      /vendor name/,
    );
  });

  it("vendors limits what a call touches", async () => {
    const env = memoryEnvStore();
    const keys = [parse(mk("exa", "a")), parse(mk("cohere", "a"))];
    expect((await applyProjection(env, keys, { vendors: ["cohere"] })).put).toEqual([
      "COHERE_API_KEY",
    ]);
    expect(Object.keys(env.values)).toEqual(["COHERE_API_KEY"]);
  });

  it("diff names ids, never values, and compares the count as a number", async () => {
    const a = parse(mk("exa", "env-0", { purposes: ["default"] }));
    const b = parse(mk("exa", "env-1"));
    const env = memoryEnvStore({
      EXA_API_KEY: sk("z"),
      EXA_API_KEY_2: sk("y"),
      NUM_EXA: "5",
    });
    const diff = await projectionDiff(env, [a, b]);
    expect(diff).toEqual([
      { name: "EXA_API_KEY", want: keyId(a.secret), have: keyId(sk("z")) },
      { name: "EXA_API_KEY_1", want: keyId(b.secret), have: null },
      { name: "EXA_API_KEY_2", want: null, have: keyId(sk("y")) },
      { name: "NUM_EXA", want: "1", have: "5" },
    ]);
    expect(JSON.stringify(diff)).not.toContain("sk-test");
    // A count that is not a number is shown as an id.
    const odd = await projectionDiff(memoryEnvStore({ NUM_EXA: sk("n") }), []);
    expect(odd).toEqual([]);
    const odd2 = await projectionDiff(memoryEnvStore({ NUM_EXA: sk("n") }), [], {
      vendors: ["exa"],
    });
    expect(odd2).toEqual([{ name: "NUM_EXA", want: null, have: keyId(sk("n")) }]);
  });
});

describe("no silent replace in the vault", () => {
  it("a new secret at a held address is refused unless it names the key it replaced", async () => {
    const store = memoryKeys([mk("cloudflare", "pages", { secret: sk("a") })]);
    await expect(store.put(mk("cloudflare", "pages", { secret: sk("b") }))).rejects.toThrow(
      /cloudflare@pages already holds another secret .*nothing was written/,
    );
    expect((await store.get("cloudflare@pages"))?.secret).toBe(sk("a"));
    // Another field of the same key is no replace.
    await store.put(mk("cloudflare", "pages", { secret: sk("a"), purposes: ["deploy"] }));
    // A rotation names the old id.
    await store.put(
      mk("cloudflare", "pages", {
        secret: sk("b"),
        purposes: ["deploy"],
        previous: [{ id: keyId(sk("a")), revokedAt: T1 }],
      }),
    );
    expect((await store.get("cloudflare@pages"))?.secret).toBe(sk("b"));
    // A second key of the vendor takes its own label.
    await store.put(mk("cloudflare", "dns", { secret: sk("c") }));
    expect((await store.list()).map((k) => k.address)).toEqual([
      "cloudflare@dns",
      "cloudflare@pages",
    ]);
  });

  it("an env name belongs to one key of an owner, and is never a ring name", async () => {
    const store = memoryKeys([
      mk("cloudflare", "pages", { secret: sk("a"), env: ["CLOUDFLARE_API_TOKEN"] }),
    ]);
    await expect(
      store.put(mk("cloudflare", "dns", { secret: sk("b"), env: ["CLOUDFLARE_API_TOKEN"] })),
    ).rejects.toThrow(/cloudflare@pages already fills CLOUDFLARE_API_TOKEN/);
    await expect(
      store.put(mk("cloudflare", "dns", { secret: sk("b"), env: ["CLOUDFLARE_API_KEY"] })),
    ).rejects.toThrow(/CLOUDFLARE_API_KEY is a ring name/);
    expect(() => apiKeySchema.parse(mk("cloudflare", "dns", { env: ["lower"] }))).toThrow();
    await store.put(mk("cloudflare", "dns", { secret: sk("b"), env: ["CLOUDFLARE_DNS_TOKEN"] }));
    await store.put(
      mk("cloudflare", "old", {
        secret: sk("c"),
        status: "revoked",
        revokedAt: T1,
        env: ["CLOUDFLARE_API_TOKEN"],
      }),
    );
  });

  it("the projection fills env names, replaces a rotated value, and refuses a value the key never had", async () => {
    const pages = apiKeySchema.parse(
      mk("cloudflare", "pages", { secret: sk("a"), env: ["CLOUDFLARE_API_TOKEN"] }),
    );
    const env = memoryEnvStore({ KEEP: "1" });
    // Its own name and no purpose: no ring name.
    expect(await applyProjection(env, [pages])).toEqual({
      put: ["CLOUDFLARE_API_TOKEN"],
      removed: [],
    });
    expect(env.values).toEqual({ KEEP: "1", CLOUDFLARE_API_TOKEN: sk("a") });

    const rotated = apiKeySchema.parse({
      ...pages,
      secret: sk("b"),
      previous: [{ id: keyId(sk("a")), revokedAt: T1 }],
    });
    await applyProjection(env, [rotated]);
    expect(env.values.CLOUDFLARE_API_TOKEN).toBe(sk("b"));

    // A value set by hand under the name: nothing is written, not even the ring name
    // (the purpose puts this key in the ring).
    env.values.CLOUDFLARE_API_TOKEN = "set-by-hand";
    const next = apiKeySchema.parse({
      ...rotated,
      secret: sk("c"),
      purposes: ["default"],
      previous: [...rotated.previous, { id: keyId(sk("b")), revokedAt: T2 }],
    });
    const err = await applyProjection(env, [next]).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(WouldReplace);
    expect(err).toMatchObject({ key: "CLOUDFLARE_API_TOKEN", heldLength: 11 });
    expect(env.values).toEqual({ KEEP: "1", CLOUDFLARE_API_TOKEN: "set-by-hand" });
    await applyProjection(env, [next], { replace: true });
    expect(env.values.CLOUDFLARE_API_TOKEN).toBe(sk("c"));
    expect(env.values.CLOUDFLARE_API_KEY).toBe(sk("c"));

    // A key that drops the env name leaves the name as it is.
    const bare = apiKeySchema.parse({ ...next, env: [] });
    expect(await applyProjection(env, [bare])).toEqual({ put: [], removed: [] });
    expect(env.values.CLOUDFLARE_API_TOKEN).toBe(sk("c"));
  });

  it("a key with its own env name and no purpose is in no ring", async () => {
    const pages = mk("cloudflare", "pages", { secret: sk("a"), env: ["CLOUDFLARE_PAGES_TOKEN"] });
    const tunnel = mk("cloudflare", "tunnel", {
      secret: sk("b"),
      env: ["CLOUDFLARE_TUNNEL_TOKEN"],
      madeAt: T1,
    });
    // Scoped tokens only: their own names, no pool.
    const scoped = [pages, tunnel].map((k) => apiKeySchema.parse(k));
    expect(projectKeys(scoped).get("cloudflare")).toEqual([
      { name: "CLOUDFLARE_PAGES_TOKEN", value: sk("a") },
      { name: "CLOUDFLARE_TUNNEL_TOKEN", value: sk("b") },
    ]);
    const store = memoryKeys(scoped);
    expect(await keysFor(store, { owner: "wren", vendor: "cloudflare" })).toEqual([]);

    // A purpose puts a named key in the ring; a key with no env name is in it as before.
    const main = mk("cloudflare", "main", {
      secret: sk("c"),
      env: ["CLOUDFLARE_MAIN_TOKEN"],
      purposes: ["default"],
      madeAt: T2,
    });
    const plain = mk("cloudflare", "plain", { secret: sk("d"), madeAt: T2 });
    await store.put(main);
    await store.put(plain);
    const ring = await keysFor(store, { owner: "wren", vendor: "cloudflare" });
    expect(ring.map((k) => k.account)).toEqual(["main", "plain"]);
    const all = [...scoped, apiKeySchema.parse(main), apiKeySchema.parse(plain)];
    expect(
      projectKeys(all)
        .get("cloudflare")
        ?.map((e) => e.name),
    ).toEqual([
      "CLOUDFLARE_API_KEY",
      "CLOUDFLARE_API_KEY_1",
      "NUM_CLOUDFLARE",
      "CLOUDFLARE_MAIN_TOKEN",
      "CLOUDFLARE_PAGES_TOKEN",
      "CLOUDFLARE_TUNNEL_TOKEN",
    ]);

    // Ring names an older version wrote for a scoped token are cleared.
    const env = memoryEnvStore({
      CLOUDFLARE_API_KEY: sk("a"),
      CLOUDFLARE_API_KEY_1: sk("b"),
      NUM_CLOUDFLARE: "1",
      CLOUDFLARE_PAGES_TOKEN: sk("a"),
      CLOUDFLARE_TUNNEL_TOKEN: sk("b"),
    });
    expect(await applyProjection(env, scoped)).toEqual({
      put: [],
      removed: ["CLOUDFLARE_API_KEY", "CLOUDFLARE_API_KEY_1", "NUM_CLOUDFLARE"],
    });
    expect(Object.keys(env.values).sort()).toEqual([
      "CLOUDFLARE_PAGES_TOKEN",
      "CLOUDFLARE_TUNNEL_TOKEN",
    ]);
  });
});

describe("keysFromEnv", () => {
  const e = (name: string, value: string): EnvEntry => ({ name, value });
  const o = { owner: "wren", madeAt: T0 };

  it("a ring projected back is the ring it came from", async () => {
    const entries = [
      e("PATH", "/bin"),
      e("EXA_API_KEY", sk("a")),
      e("EXA_API_KEY_1", sk("b")),
      e("EXA_API_KEY_2", sk("c")),
      e("NUM_EXA", "2"),
      e("COHERE_API_KEY", sk("d")),
      e("GOOGLE_MAPS_API_KEY", sk("e")),
      e("GOOGLE_MAPS_API_KEY_1", sk("f")),
      e("NUM_GOOGLE_MAPS", "1"),
    ];
    const { keys, skipped } = keysFromEnv(entries, o);
    expect(skipped).toEqual([]);
    expect(keys.map((k) => `${k.site}@${k.account}`)).toEqual([
      "cohere@env-0",
      "exa@env-0",
      "exa@env-1",
      "exa@env-2",
      "google-maps@env-0",
      "google-maps@env-1",
    ]);
    expect(keys.filter((k) => k.purposes?.includes("default")).length).toBe(3);
    const projected = projectKeys(keys.map(parse));
    const flat = [...projected.values()].flat();
    expect(flat.sort((x, y) => x.name.localeCompare(y.name))).toEqual(
      entries.filter((x) => x.name !== "PATH").sort((x, y) => x.name.localeCompare(y.name)),
    );
    // Through a store: nothing differs.
    const store = memoryKeys();
    for (const k of keys) await store.put(k);
    const env = memoryEnvStore(Object.fromEntries(entries.map((x) => [x.name, x.value])));
    const all = await Promise.all((await store.list()).map((i) => store.get(i.address)));
    expect(
      await projectionDiff(
        env,
        all.filter((k): k is ApiKey => k !== null),
      ),
    ).toEqual([]);
  });

  it("skips a numbered name past NUM, and every numbered name when NUM is missing", () => {
    const { keys, skipped } = keysFromEnv(
      [
        e("EXA_API_KEY", sk("a")),
        e("EXA_API_KEY_1", sk("b")),
        e("EXA_API_KEY_2", sk("c")),
        e("NUM_EXA", "1"),
        e("COHERE_API_KEY_1", sk("d")),
      ],
      o,
    );
    expect(keys.map((k) => `${k.site}@${k.account}`)).toEqual(["exa@env-0", "exa@env-1"]);
    expect(skipped).toEqual([
      { name: "COHERE_API_KEY_1", why: "past NUM_COHERE" },
      { name: "EXA_API_KEY_2", why: "past NUM_EXA" },
    ]);
  });

  it("keeps a value once, at the lower slot, and the diff shows what would move", async () => {
    const { keys, skipped } = keysFromEnv(
      [
        e("EXA_API_KEY", sk("a")),
        e("EXA_API_KEY_1", sk("b")),
        e("EXA_API_KEY_2", sk("b")),
        e("EXA_API_KEY_3", sk("c")),
        e("NUM_EXA", "3"),
        e("COHERE_API_KEY", sk("a")),
      ],
      o,
    );
    expect(skipped).toEqual([{ name: "EXA_API_KEY_2", why: "same key as EXA_API_KEY_1" }]);
    // The same value under another vendor is its own key.
    expect(keys.map((k) => `${k.site}@${k.account}`)).toEqual([
      "cohere@env-0",
      "exa@env-0",
      "exa@env-1",
      "exa@env-3",
    ]);
    const env = memoryEnvStore({
      EXA_API_KEY: sk("a"),
      EXA_API_KEY_1: sk("b"),
      EXA_API_KEY_2: sk("b"),
      EXA_API_KEY_3: sk("c"),
      NUM_EXA: "3",
    });
    const diff = await projectionDiff(env, keys.filter((k) => k.site === "exa").map(parse));
    expect(diff.map((d) => d.name)).toEqual(["EXA_API_KEY_2", "EXA_API_KEY_3", "NUM_EXA"]);
  });

  it("skips what it cannot make a key of, by name", () => {
    const { keys, skipped } = keysFromEnv(
      [
        e("X_API_KEY_0", sk("a")),
        e("EXA_API_KEY", "   "),
        e(`${"A".repeat(41)}_API_KEY`, sk("b")),
        e("NOT_A_KEY", sk("c")),
      ],
      o,
    );
    expect(keys).toEqual([]);
    expect(skipped.map((s) => s.name).sort()).toEqual([
      `${"A".repeat(41)}_API_KEY`,
      "EXA_API_KEY",
      "X_API_KEY_0",
    ]);
    expect(JSON.stringify(skipped)).not.toContain("sk-test");
  });

  it("sets owner, madeAt, live status and the default purpose", () => {
    const { keys } = keysFromEnv(
      [e("EXA_API_KEY", `${sk("a")}\n`), e("EXA_API_KEY_1", sk("b")), e("NUM_EXA", "1")],
      { owner: "do_acme", madeAt: T1 },
    );
    expect(keys.map(parse)).toMatchObject([
      { owner: "do_acme", madeAt: T1, status: "live", purposes: ["default"], secret: sk("a") },
      { owner: "do_acme", madeAt: T1, status: "live", purposes: [] },
    ]);
  });
});

describe("audit", () => {
  const use = (over: Partial<SecretUse> = {}): SecretUse => ({
    at: T0,
    credential: "exa@env-1",
    field: "secret",
    site: "exa",
    url: "https://api.exa.ai/search",
    by: "reach",
    allowed: true,
    ...over,
  });

  it("old rows and key rows verify together", async () => {
    const path = join(await mkdtemp(join(tmpdir(), "keys-audit-")), "audit.jsonl");
    const audit = fileAudit(path);
    await audit.record({
      at: T0,
      credential: "github",
      field: "password",
      site: "github",
      url: "https://github.com/login",
      by: "login",
      allowed: true,
    });
    await audit.record(use({ owner: "wren", keyId: keyId(sk("a")), reason: "search" }));
    await audit.record(use({ at: T1 }));
    expect(await verifyChain(path)).toEqual({ rows: 3, unchained: 0, ok: true, brokenAt: null });
    const rows = await audit.recent(3);
    expect(rows[0]).not.toHaveProperty("keyId");
    expect(rows[1]).toMatchObject({ owner: "wren", keyId: keyId(sk("a")), reason: "search" });
  });

  it("keyUses counts allowed uses per key and keeps the latest time", () => {
    const a = keyId(sk("a"));
    const b = keyId(sk("b"));
    const uses = keyUses([
      use({ keyId: a, at: T1 }),
      use({ keyId: a, at: T2 }),
      use({ keyId: a, at: T0 }),
      use({ keyId: a, at: "2026-12-01T00:00:00.000Z", allowed: false }),
      use({ keyId: b, at: T0 }),
      use({ credential: "github", field: "password" }),
    ]);
    expect(uses.size).toBe(2);
    expect(uses.get(a)).toEqual({ uses: 3, lastUsedAt: T2 });
    expect(uses.get(b)).toEqual({ uses: 1, lastUsedAt: T0 });
    expect(keyUses([]).size).toBe(0);
  });
});
