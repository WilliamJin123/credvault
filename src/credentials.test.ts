import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  credentialEnv,
  credentialSchema,
  envCredentials,
  fileCredentials,
  layeredCredentials,
  memoryCredentials,
  pullCredentials,
  pushCredentials,
  syncedCredentials,
  versionsFile,
} from "./credentials.js";
import { memoryEnvStore } from "./env-store.js";

const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("credentials", () => {
  it("file store writes 0600, round-trips, and lists names only", async () => {
    const dir = mkdtempSync(join(tmpdir(), "credvault-"));
    const store = fileCredentials(join(dir, "c.json"));
    await store.put("cloudflare", { username: "u", password: "p", totpSecret: RFC_SECRET });
    expect(statSync(join(dir, "c.json")).mode & 0o777).toBe(0o600);
    expect(await store.list()).toEqual(["cloudflare"]);
    expect((await store.get("cloudflare"))?.totpSecret).toBe(RFC_SECRET);
    expect(await store.get("nope")).toBeNull();
  });
  it("env store reads CRED_* and is read-only", async () => {
    const env = {
      CRED_GOOGLE_ADMIN_USERNAME: "a@b.co",
      CRED_GOOGLE_ADMIN_PASSWORD: "pw",
    };
    const store = envCredentials(env);
    expect(await store.list()).toEqual(["google-admin"]);
    expect((await store.get("google-admin"))?.username).toBe("a@b.co");
    await expect(store.put("x", { username: "u", password: "p" })).rejects.toThrow(/read-only/);
  });
  it("every field round-trips through env, lists as JSON", async () => {
    const cred = {
      username: "u",
      password: "p",
      previousPassword: "old",
      totpSecret: RFC_SECRET,
      recoveryCodes: ["r1"],
      codesInbox: "c@x.co",
      passkeys: [
        { rpId: "x", credentialId: "k", privateKey: "d", signCount: 3, isResidentCredential: true },
      ],
      via: "google",
      url: "https://x.co/login",
      madeAt: "2026-09-22T00:00:00.000Z",
    };
    const env = Object.fromEntries(credentialEnv("x", cred).map((e) => [e.name, e.value]));
    expect(await envCredentials(env).get("x")).toEqual(cred);
    await expect(envCredentials({ ...env, CRED_X_PASSKEYS: "{" }).get("x")).rejects.toThrow(
      /CRED_X_PASSKEYS is not JSON/,
    );
  });
  it("a credential round-trips through env entries, via-only included", async () => {
    const entries = credentialEnv("my-site", {
      username: "w@wren.co",
      via: "google",
      codesInbox: "codes@wren.co",
      recoveryCodes: [],
      passkeys: [],
    });
    expect(entries.map((e) => e.name)).toEqual([
      "CRED_MY_SITE_USERNAME",
      "CRED_MY_SITE_VIA",
      "CRED_MY_SITE_CODES_INBOX",
    ]);
    const env = Object.fromEntries(entries.map((e) => [e.name, e.value]));
    const back = await envCredentials(env).get("my-site");
    expect(back?.via).toBe("google");
    expect(back?.codesInbox).toBe("codes@wren.co");
    expect(back?.password).toBeUndefined();
  });
  it("an account keeps its own mark in the env name and comes back as itself", async () => {
    const entries = credentialEnv("google@ops", {
      username: "o@x.co",
      password: "p",
      recoveryCodes: [],
      passkeys: [],
    });
    expect(entries[0]?.name).toBe("CRED_GOOGLE__OPS_USERNAME");
    const env = Object.fromEntries(entries.map((e) => [e.name, e.value]));
    expect(await envCredentials(env).list()).toEqual(["google@ops"]);
    expect((await envCredentials(env).get("google@ops"))?.username).toBe("o@x.co");
  });
  it("an account named by its address comes back with its dots, not dashes", async () => {
    const site = "google@will@wren-automation.com";
    const entries = credentialEnv(site, {
      username: "w",
      password: "p",
      recoveryCodes: [],
      passkeys: [],
    });
    expect(entries[0]?.name).toBe("CRED_GOOGLE__WILL__WREN_AUTOMATION___COM_USERNAME");
    const env = Object.fromEntries(entries.map((e) => [e.name, e.value]));
    expect(await envCredentials(env).list()).toEqual([site]);
  });
  it("push sends every field but a canary's; pull keeps what is here unless told, and never drops passkeys", async () => {
    const key = (id: string) => ({
      rpId: "a",
      credentialId: id,
      privateKey: "d",
      signCount: 0,
      isResidentCredential: true,
    });
    const local = memoryCredentials({
      a: {
        username: "a",
        password: "1",
        totpSecret: "JBSWY3DPEHPK3PXP",
        recoveryCodes: ["r1", "r2"],
        passkeys: [key("shared")],
      },
      "b@two": { username: "b", via: "google", roles: ["main"], details: { memberNumber: "42" } },
      stripe: { username: "bait", password: "x", canary: true },
    });
    const kv = new Map<string, string>();
    const store = {
      all: async () => [...kv].map(([name, value]) => ({ name, value })),
      put: async (name: string, value: string) => void kv.set(name, value),
      list: async () => [...kv.keys()].map((name) => ({ name })),
      remove: async (name: string) => kv.delete(name),
    };
    const pushed = await pushCredentials(local, store);
    expect(pushed.map((p) => p.site)).toEqual(["a", "b@two"]);
    expect([...kv.keys()]).toEqual([
      "CRED_A_USERNAME",
      "CRED_A_PASSWORD",
      "CRED_A_TOTP_SECRET",
      "CRED_A_RECOVERY_CODES",
      "CRED_A_PASSKEYS",
      "CRED_B__TWO_USERNAME",
      "CRED_B__TWO_VIA",
      "CRED_B__TWO_ROLES",
      "CRED_B__TWO_DETAILS",
    ]);
    const other = memoryCredentials({
      a: { username: "old", password: "old", passkeys: [key("here")] },
    });
    const first = await pullCredentials(store, other);
    expect(first).toEqual({ written: ["b@two"], kept: ["a"] });
    expect((await other.get("b@two"))?.roles).toEqual(["main"]);
    expect((await other.get("b@two"))?.details).toEqual({ memberNumber: "42" });
    expect((await other.get("a"))?.password).toBe("old");
    const second = await pullCredentials(store, other, ["a"], { overwrite: true });
    expect(second).toEqual({ written: ["a"], kept: [] });
    const a = await other.get("a");
    expect(a?.password).toBe("1");
    expect(a?.recoveryCodes).toEqual(["r1", "r2"]);
    expect(a?.passkeys.map((p) => p.credentialId)).toEqual(["shared", "here"]);
    await expect(pullCredentials(store, other, ["nope"])).rejects.toThrow(/push it first/);
    // Codes used up here: the next push clears them there too.
    await local.put("a", { ...(await local.get("a")), username: "a", recoveryCodes: [] });
    await pushCredentials(local, store, ["a"]);
    expect(kv.has("CRED_A_RECOVERY_CODES")).toBe(false);
    expect(kv.has("CRED_A_PASSKEYS")).toBe(true);
  });
  it("remove forgets a site here, there, and in every layer; history is not touched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cv-rm-"));
    const file = fileCredentials(join(dir, "c.json"));
    const shared = memoryEnvStore();
    const s = syncedCredentials(file, shared, { prefix: "APP_CRED_" });
    await s.put("google@a@x.com", { username: "a@x.com", password: "p" });
    await s.put("keep", { username: "k", password: "p" });
    const both = layeredCredentials([s, envCredentials({})], s);
    expect(await both.remove?.("google@a@x.com")).toBe(true);
    expect(await both.list()).toEqual(["keep"]);
    expect(Object.keys(shared.values).some((k) => k.includes("__A__X___COM"))).toBe(false);
    expect(await both.get("google@a@x.com")).toBeNull();
    expect(await both.remove?.("google@a@x.com")).toBe(false);
  });
  it("synced: writes land here then there; reads prefer there, refresh here, and fall back", async () => {
    const shared = memoryEnvStore();
    const local = memoryCredentials({ trap: { username: "bait", password: "x", canary: true } });
    let t = 0;
    const errors: string[] = [];
    const s = syncedCredentials(local, shared, {
      prefix: "APP_CRED_",
      now: () => t,
      onSharedError: (site, _e, during) => errors.push(`${site}:${during}`),
    });
    await s.put("x", { username: "u", password: "p", recoveryCodes: ["c"] });
    expect(shared.values.APP_CRED_X_PASSWORD).toBe("p");
    expect(shared.values.APP_CRED_X_RECOVERY_CODES).toBe('["c"]');
    // Changed elsewhere: seen after the reuse window, and this copy follows.
    expect((await s.get("x"))?.password).toBe("p");
    shared.values.APP_CRED_X_PASSWORD = "new";
    expect((await s.get("x"))?.password).toBe("p");
    t = 60_001;
    expect((await s.get("x"))?.password).toBe("new");
    expect((await local.get("x"))?.password).toBe("new");
    // Made on another machine: listed and read here with no pull.
    shared.values.APP_CRED_Y_USERNAME = "y";
    shared.values.APP_CRED_Y_VIA = "google";
    expect(await s.list()).toEqual(["trap", "x", "y"]);
    expect((await s.get("y"))?.via).toBe("google");
    // Canaries never travel, and are read only here.
    expect(Object.keys(shared.values).some((k) => k.includes("TRAP"))).toBe(false);
    expect((await s.get("trap"))?.canary).toBe(true);
    // Shared store down: reads fall back, writes are reported, nothing is lost.
    const down = {
      ...shared,
      getMany: () => new Promise<Record<string, string>>(() => {}),
      put: async () => Promise.reject(new Error("offline")),
    };
    const off = syncedCredentials(local, down, {
      prefix: "APP_CRED_",
      timeoutMs: 5,
      onSharedError: (site, _e, d) => errors.push(`${site}:${d}`),
    });
    expect((await off.get("x"))?.password).toBe("new");
    await off.put("z", { username: "u", password: "p" });
    expect((await local.get("z"))?.password).toBe("p");
    expect(errors).toEqual(["x:read", "z:write"]);
    await expect(
      syncedCredentials(local, down).put("w", { username: "u", password: "p" }),
    ).rejects.toThrow(/offline/);
  });
  it("synced: a site is read from the shared store once per version, here or in another process", async () => {
    const shared = memoryEnvStore();
    let n = 0;
    const read: string[] = [];
    // A store that keeps change times, as SSM does.
    const timed = {
      ...shared,
      list: async () => (await shared.list()).map((e) => ({ ...e, updatedAt: `t${n}` })),
      getMany: async (names: string[]) => {
        read.push(names[0] ?? "");
        return shared.getMany(names);
      },
      put: async (name: string, value: string) => {
        n++;
        await shared.put(name, value);
      },
    };
    const dir = mkdtempSync(join(tmpdir(), "cv-ver-"));
    const versions = versionsFile(join(dir, "versions.json"));
    const local = memoryCredentials();
    const a = syncedCredentials(local, timed, { prefix: "APP_CRED_", versions });
    await a.put("x", { username: "u", password: "p" });
    for (let i = 0; i < 5; i++) expect((await a.get("x"))?.password).toBe("p");
    // Another process on this machine: same copy, same version, no read.
    const b = syncedCredentials(local, timed, { prefix: "APP_CRED_", versions });
    expect((await b.get("x"))?.password).toBe("p");
    expect(read).toEqual([]);
    // Changed elsewhere: read once, then served from here again.
    shared.values.APP_CRED_X_PASSWORD = "new";
    n++;
    expect((await b.get("x"))?.password).toBe("new");
    expect((await b.get("x"))?.password).toBe("new");
    expect((await a.get("x"))?.password).toBe("new");
    expect(read).toEqual(["APP_CRED_X_USERNAME"]);
    // Nothing there: no read at all.
    expect(await a.get("none")).toBeNull();
    expect(read).toHaveLength(1);
  });
  it("layered: first hit wins, writes go to the first store", async () => {
    const a = memoryCredentials({ s: { username: "a", password: "1" } });
    const b = memoryCredentials({
      s: { username: "b", password: "2" },
      t: { username: "t", password: "3" },
    });
    const l = layeredCredentials([a, b], a);
    expect((await l.get("s"))?.username).toBe("a");
    expect((await l.get("t"))?.username).toBe("t");
    await l.put("n", { username: "n", password: "4" });
    expect(await a.list()).toContain("n");
  });
});

describe("credential schema", () => {
  it("takes a via credential without a password, and nothing without either", async () => {
    const store = memoryCredentials();
    await store.put("s", { username: "u", via: "google", url: "https://s.test/login" });
    expect((await store.get("s"))?.password).toBeUndefined();
    await expect(store.put("t", { username: "u" })).rejects.toThrow(/password or a via/);
  });
  it("normalizes a spaced seed and rejects a 6-digit code", async () => {
    const store = memoryCredentials();
    await store.put("s", { username: "u", password: "p", totpSecret: "jbsw y3dp-ehpk 3pxp" });
    expect((await store.get("s"))?.totpSecret).toBe("JBSWY3DPEHPK3PXP");
    await expect(
      store.put("s", { username: "u", password: "p", totpSecret: "123456" }),
    ).rejects.toThrow(/base32 seed/);
  });
});

describe("sealed credential file", () => {
  it("writes ciphertext, reads it back, and upgrades a plain file on the next write", async () => {
    const { aesGcmCipher, isSealed } = await import("./cipher.js");
    const { readFileSync, writeFileSync } = await import("node:fs");
    const dir = mkdtempSync(join(tmpdir(), "credvault-sealed-"));
    const file = join(dir, "c.json");
    const key = Buffer.alloc(32, 7);
    writeFileSync(
      file,
      JSON.stringify({ sites: { old: { username: "o", password: "p", recoveryCodes: [] } } }),
    );
    const store = fileCredentials(file, aesGcmCipher(key));
    expect((await store.get("old"))?.username).toBe("o");
    await store.put("new", { username: "n", password: "q" });
    const raw = readFileSync(file, "utf8");
    expect(isSealed(raw)).toBe(true);
    expect(raw).not.toContain("password");
    expect((await store.get("old"))?.username).toBe("o");
    expect((await store.get("new"))?.password).toBe("q");
    await expect(
      fileCredentials(file, aesGcmCipher(Buffer.alloc(32, 8))).get("new"),
    ).rejects.toThrow();
  });

  it("read as plain text, it names the setting instead of a parse error", async () => {
    const { aesGcmCipher } = await import("./cipher.js");
    const dir = mkdtempSync(join(tmpdir(), "credvault-sealed-"));
    const file = join(dir, "c.json");
    await fileCredentials(file, aesGcmCipher(Buffer.alloc(32, 7))).put("s", {
      username: "u",
      password: "p",
    });
    await expect(fileCredentials(file).get("s")).rejects.toThrow(/opened with no cipher key/);
  });
});

describe("credentials under an app's own prefix", () => {
  it("names env entries with the prefix and reads only its own back", async () => {
    const o = { prefix: "MYAPP_CRED_" };
    const entries = credentialEnv(
      "s",
      { username: "u", password: "p", recoveryCodes: [], passkeys: [] },
      o,
    );
    expect(entries.map((e) => e.name)).toEqual(["MYAPP_CRED_S_USERNAME", "MYAPP_CRED_S_PASSWORD"]);
    const env = {
      ...Object.fromEntries(entries.map((e) => [e.name, e.value])),
      CRED_OTHER_USERNAME: "x",
      CRED_OTHER_PASSWORD: "y",
    };
    expect(await envCredentials(env, o).list()).toEqual(["s"]);
    expect(await envCredentials(env).list()).toEqual(["other"]);
  });
});

describe("a file sealed before a rename", () => {
  it.each(["autobrowse-sealed-v1", "credkeep-sealed-v1"])(
    "opens under %s and reseals under the new magic",
    async (old) => {
      const { aesGcmCipher, isSealed } = await import("./cipher.js");
      const { readFileSync, writeFileSync } = await import("node:fs");
      const file = join(mkdtempSync(join(tmpdir(), "credvault-legacy-")), "c.json");
      const cipher = aesGcmCipher(Buffer.alloc(32, 3));
      const plain = JSON.stringify({ sites: { a: { username: "a", password: "p" } } });
      const legacy = cipher.seal(plain).replace("credvault-sealed-v1", old);
      writeFileSync(file, legacy);
      expect(isSealed(legacy)).toBe(true);
      const store = fileCredentials(file, cipher);
      expect((await store.get("a"))?.password).toBe("p");
      await store.put("b", { username: "b", password: "q" });
      expect(readFileSync(file, "utf8")).toContain("credvault-sealed-v1");
    },
  );
});

describe("details", () => {
  it("holds camelCase names, never a login field's", () => {
    const base = { username: "u", password: "p" };
    expect(credentialSchema.parse({ ...base, details: { deliveryPostal: "M5T" } }).details).toEqual(
      {
        deliveryPostal: "M5T",
      },
    );
    for (const bad of [
      { password: "x" },
      { "member-number": "1" },
      { Member: "1" },
      { warehouse: "" },
    ])
      expect(() => credentialSchema.parse({ ...base, details: bad })).toThrow();
  });
});
