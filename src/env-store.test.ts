import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DeleteParameterCommand,
  DescribeParametersCommand,
  GetParametersCommand,
  PutParameterCommand,
  type SSMClient,
} from "@aws-sdk/client-ssm";
import { describe, expect, it } from "vitest";
import {
  envFileStore,
  expiring,
  memoryEnvStore,
  memoryUnshared,
  type PutOptions,
  parseDotenv,
  REMOVED,
  ssmEnvStore,
  syncedEnvStore,
  toDotenv,
  toExports,
  unsharedFile,
  upsertDotenv,
  WouldReplace,
} from "./env-store.js";

describe("dotenv helpers", () => {
  it("parses as a shell would, inlines a JSON file a value names, and renders back", () => {
    const text = `# comment
export A=1
B="two words" # trailing
C='x'
SA=/tmp/sa.json
bad-name=1
EMPTY=
`;
    const entries = parseDotenv(text, (p) => (p === "/tmp/sa.json" ? '{"k":1}' : null));
    expect(entries).toEqual([
      { name: "A", value: "1" },
      { name: "B", value: "two words" },
      { name: "C", value: "x" },
      { name: "SA", value: '{"k":1}' },
    ]);
    expect(toExports([{ name: "P", value: "it's" }])).toBe("export P='it'\\''s'\n");
    expect(toDotenv([{ name: "A", value: "1" }])).toBe("A=1\n");
    expect(toDotenv([{ name: "SA", value: "{\n}" }], (n) => `/x/${n.toLowerCase()}.json`)).toBe(
      "SA=/x/sa.json\n",
    );
    expect(() => toDotenv([{ name: "SA", value: "{\n}" }])).toThrow(/spans lines/);
    expect(
      upsertDotenv("A=old\nKEEP=1\n", [
        { name: "A", value: "new" },
        { name: "Z", value: "9" },
      ]),
    ).toBe("A=new\nKEEP=1\nZ=9\n");
  });
});

describe("expiry", () => {
  it("is kept with the value, cleared by a put without one, and listed soonest first", async () => {
    const store = memoryEnvStore();
    await store.put("NPM_TOKEN", "t", { expiresAt: "2026-12-21T00:00:00Z" });
    await store.put("LINKEDIN_TOKEN", "l", { expiresAt: "2026-10-15T00:00:00.000Z" });
    await store.put("STATIC_KEY", "k");
    const listed = await store.list();
    expect(listed.map((e) => [e.name, e.expiresAt])).toEqual([
      ["LINKEDIN_TOKEN", "2026-10-15T00:00:00.000Z"],
      ["NPM_TOKEN", "2026-12-21T00:00:00.000Z"],
      ["STATIC_KEY", null],
    ]);
    const now = Date.parse("2026-09-22T00:00:00Z");
    const day = 86_400_000;
    expect(expiring(listed, 14 * day, now)).toEqual([]);
    expect(expiring(listed, 30 * day, now).map((e) => e.name)).toEqual(["LINKEDIN_TOKEN"]);
    expect(expiring(listed, 100 * day, now).map((e) => e.name)).toEqual([
      "LINKEDIN_TOKEN",
      "NPM_TOKEN",
    ]);
    await store.put("NPM_TOKEN", "t2", { replace: true });
    expect((await store.list()).find((e) => e.name === "NPM_TOKEN")?.expiresAt).toBeNull();
  });
});

describe("no silent replace", () => {
  const refused = async (run: Promise<unknown>) =>
    run.then(
      () => null,
      (e: unknown) => e,
    );

  it("a put on a name that holds another value writes nothing until it says replace", async () => {
    const file = join(mkdtempSync(join(tmpdir(), "credvault-")), ".env");
    writeFileSync(file, "TOKEN=live-token-1\n");
    const stores = {
      memory: memoryEnvStore({ TOKEN: "live-token-1" }),
      file: envFileStore(file, {}),
    };
    for (const [kind, store] of Object.entries(stores)) {
      const err = await refused(store.put("TOKEN", "other-2"));
      expect(err, kind).toBeInstanceOf(WouldReplace);
      expect(err, kind).toMatchObject({ key: "TOKEN", heldLength: 12 });
      expect(String(err), kind).not.toContain("live-token-1");
      expect(await store.get("TOKEN"), kind).toBe("live-token-1");
      // The same value is no replace: a new expiry goes through.
      await store.put("TOKEN", "live-token-1", { expiresAt: "2026-12-21T00:00:00Z" });
      await store.put("TOKEN", "other-2", { replace: true });
      expect(await store.get("TOKEN"), kind).toBe("other-2");
      await store.put("NEW_NAME", "n");
    }
  });

  it("a synced put asks both sides before it writes either", async () => {
    const local = memoryEnvStore({ HERE: "a" });
    const shared = memoryEnvStore({ THERE: "b" });
    const store = syncedEnvStore(local, shared);
    expect(await refused(store.put("HERE", "x"))).toMatchObject({ where: "this machine" });
    expect(await refused(store.put("THERE", "x"))).toMatchObject({ where: "the shared store" });
    expect(local.values).toEqual({ HERE: "a" });
    expect(shared.values).toEqual({ THERE: "b" });
    await store.put("THERE", "x", { replace: true });
    expect([local.values.THERE, shared.values.THERE]).toEqual(["x", "x"]);

    // A value put while the shared store was away never replaces what the store got meanwhile.
    let up = false;
    const flaky = {
      ...shared,
      get: (n: string) => (up ? shared.get(n) : Promise.reject(new Error("offline"))),
      put: (n: string, v: string, o?: PutOptions) =>
        up ? shared.put(n, v, o) : Promise.reject(new Error("offline")),
    };
    const unshared = memoryUnshared();
    const away = syncedEnvStore(local, flaky, { unshared });
    await expect(away.put("MINTED", "mine")).rejects.toThrow(/kept on this machine only/);
    await expect(away.put("FREE", "f")).rejects.toThrow(/kept on this machine only/);
    shared.values.MINTED = "theirs";
    up = true;
    expect(await refused(away.share())).toMatchObject({ key: "MINTED" });
    expect(shared.values).toMatchObject({ MINTED: "theirs", FREE: "f" });
    expect(unshared.names()).toEqual(["MINTED"]);
    expect(await away.share({ replace: true })).toEqual(["MINTED"]);
    expect(shared.values.MINTED).toBe("mine");
  });
});

describe("ssm store", () => {
  /** SSM as a map, speaking the four commands the store sends; `decrypted` counts values read (KMS decrypts). */
  const fakeSsm = () => {
    const params = new Map<string, { value: string; description: string; version: number }>();
    const sent: string[] = [];
    const decrypted: string[] = [];
    const send = async (cmd: unknown) => {
      sent.push((cmd as object).constructor.name);
      const input = (cmd as { input: Record<string, unknown> }).input;
      if (cmd instanceof PutParameterCommand) {
        const name = input.Name as string;
        params.set(name, {
          value: input.Value as string,
          description: input.Description as string,
          version: (params.get(name)?.version ?? 0) + 1,
        });
        return {};
      }
      if (cmd instanceof DescribeParametersCommand)
        return {
          Parameters: [...params].map(([Name, p]) => ({
            Name,
            Description: p.description,
            Version: p.version,
            LastModifiedDate: new Date(Date.UTC(2026, 8, 26, 0, 0, p.version)),
          })),
        };
      if (cmd instanceof GetParametersCommand)
        return {
          Parameters: (input.Names as string[]).flatMap((Name) => {
            const p = params.get(Name);
            if (!p) return [];
            decrypted.push(Name.split("/").pop() ?? "");
            return [{ Name, Value: p.value }];
          }),
        };
      if (cmd instanceof DeleteParameterCommand) {
        params.delete(input.Name as string);
        return {};
      }
      throw new Error("unexpected command");
    };
    return { ssm: { send } as unknown as SSMClient, params, sent, decrypted };
  };

  it("refuses a replace, and a remove keeps the last value under removed/", async () => {
    const f = fakeSsm();
    const store = ssmEnvStore(f.ssm, "/app/config");
    await store.put("TOKEN", "live-token-1");
    await expect(store.put("TOKEN", "other-2")).rejects.toBeInstanceOf(WouldReplace);
    expect(f.params.get("/app/config/TOKEN")?.value).toBe("live-token-1");
    await store.put("TOKEN", "live-token-1", { expiresAt: "2026-12-21T00:00:00Z" });
    await store.put("TOKEN", "other-2", { replace: true });
    expect(f.params.get("/app/config/TOKEN")?.value).toBe("other-2");

    expect(await store.remove("TOKEN")).toBe(true);
    expect(f.params.has("/app/config/TOKEN")).toBe(false);
    expect(f.params.get(`/app/config/${REMOVED}/TOKEN`)).toMatchObject({ value: "other-2" });
    expect(f.params.get(`/app/config/${REMOVED}/TOKEN`)?.description).toMatch(/^removed 20/);
    expect(await store.remove("TOKEN")).toBe(false);
    // The name is free again.
    await store.put("TOKEN", "third-3");
  });

  it("lists names and expiry without decrypting, and reads values only on all/get", async () => {
    const f = fakeSsm();
    const store = ssmEnvStore(f.ssm, "/app/config");
    await store.put("TOKEN", "secret", { expiresAt: "2026-12-21T00:00:00Z" });
    await store.put("KEY", "k");
    expect(f.params.get("/app/config/TOKEN")?.description).toBe("expires 2026-12-21T00:00:00.000Z");
    expect(f.params.get("/app/config/KEY")?.description).toBe("no expiry");
    f.sent.length = 0;
    const listed = await store.list();
    expect(listed.map((e) => [e.name, e.expiresAt])).toEqual([
      ["KEY", null],
      ["TOKEN", "2026-12-21T00:00:00.000Z"],
    ]);
    expect(JSON.stringify(listed)).not.toContain("secret");
    expect(f.sent).toEqual(["DescribeParametersCommand"]);
    expect(await store.all()).toEqual([
      { name: "KEY", value: "k" },
      { name: "TOKEN", value: "secret" },
    ]);
    expect(await store.get("TOKEN")).toBe("secret");
    await expect(store.put("bad-name", "x")).rejects.toThrow(/bad name/);
  });

  it("reads each version of a value once: later reads of it decrypt nothing", async () => {
    const f = fakeSsm();
    const store = ssmEnvStore(f.ssm, "/app/config");
    await store.put("A", "1");
    await store.put("B", "2");
    expect(await store.get("A")).toBe("1");
    expect(await store.getMany(["A", "B", "NONE"])).toEqual({ A: "1", B: "2" });
    expect(await store.all()).toEqual([
      { name: "A", value: "1" },
      { name: "B", value: "2" },
    ]);
    expect(await store.get("A")).toBe("1");
    expect(f.decrypted).toEqual(["A", "B"]);
    // Changed from elsewhere (another machine): seen once the listing is, read once.
    const other = ssmEnvStore(f.ssm, "/app/config");
    await other.put("A", "new", { replace: true });
    expect((await store.all()).find((e) => e.name === "A")?.value).toBe("new");
    expect(await store.get("A")).toBe("new");
    expect(f.decrypted).toEqual(["A", "B", "A"]);
    // A write here is not read back from a stale copy.
    await store.put("B", "3", { replace: true });
    expect(await store.get("B")).toBe("3");
  });

  it("lists once for back-to-back readers, fresh again after a write", async () => {
    const f = fakeSsm();
    const store = ssmEnvStore(f.ssm, "/app/config");
    await store.put("A", "1");
    f.sent.length = 0;
    await Promise.all([store.list(), store.list()]);
    await store.list();
    expect(f.sent).toEqual(["DescribeParametersCommand"]);
    await store.put("B", "2");
    expect((await store.list()).map((e) => e.name)).toEqual(["A", "B"]);
    expect(f.sent.filter((c) => c === "DescribeParametersCommand")).toHaveLength(2);
  });
});

describe("env file store", () => {
  it("keeps other lines, writes 0600, and records expiry as a comment above the line", async () => {
    const file = join(mkdtempSync(join(tmpdir(), "credvault-")), ".env");
    writeFileSync(file, "# mine\nKEEP=1\nTOKEN=old\n");
    const env: NodeJS.ProcessEnv = {};
    const store = envFileStore(file, env);
    await store.put("TOKEN", "new", { expiresAt: "2026-12-21T00:00:00Z", replace: true });
    expect(readFileSync(file, "utf8")).toBe(
      "# mine\nKEEP=1\n# TOKEN expires 2026-12-21T00:00:00.000Z\nTOKEN=new\n",
    );
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(env.TOKEN).toBe("new");
    expect(await store.list()).toEqual([
      { name: "KEEP", updatedAt: null, expiresAt: null },
      { name: "TOKEN", updatedAt: null, expiresAt: "2026-12-21T00:00:00.000Z" },
    ]);
    // A put with no expiry clears the old one, as SSM's does.
    await store.put("TOKEN", "newer", { replace: true });
    expect(readFileSync(file, "utf8")).toBe("# mine\nKEEP=1\nTOKEN=newer\n");
    expect(await store.get("TOKEN")).toBe("newer");
    expect(await store.remove("TOKEN")).toBe(true);
    expect(await store.remove("TOKEN")).toBe(false);
    expect(await store.all()).toEqual([{ name: "KEEP", value: "1" }]);
    await expect(store.put("T", "a\nb")).rejects.toThrow(/spans lines/);
  });
});

describe("synced env store", () => {
  it("a mint lands on both, reads prefer the local copy, and a refused shared write is loud", async () => {
    const local = memoryEnvStore({ ONLY_HERE: "l" });
    const shared = memoryEnvStore({ ONLY_THERE: "s", BOTH: "old" });
    const store = syncedEnvStore(local, shared);
    await store.put("BOTH", "new", { expiresAt: "2026-11-21T00:00:00.000Z", replace: true });
    expect(shared.values.BOTH).toBe("new");
    expect(await store.get("ONLY_THERE")).toBe("s");
    expect(await store.getMany(["ONLY_HERE", "ONLY_THERE", "NONE"])).toEqual({
      ONLY_HERE: "l",
      ONLY_THERE: "s",
    });
    expect((await store.list()).map((e) => [e.name, e.expiresAt])).toEqual([
      ["BOTH", "2026-11-21T00:00:00.000Z"],
      ["ONLY_HERE", null],
      ["ONLY_THERE", null],
    ]);
    const down = { ...shared, put: async () => Promise.reject(new Error("offline")) };
    await expect(syncedEnvStore(local, down).put("MINTED", "t")).rejects.toThrow(
      /MINTED kept on this machine only/,
    );
    expect(local.values.MINTED).toBe("t");

    // The refused name is remembered: the next put that reaches the store sends it too.
    const unshared = memoryUnshared();
    let up = false;
    const flaky = {
      ...shared,
      put: (n: string, v: string, o?: PutOptions) =>
        up ? shared.put(n, v, o) : Promise.reject(new Error("offline")),
    };
    const synced = syncedEnvStore(local, flaky, { unshared });
    await local.put("MINTED", "t", { expiresAt: "2026-12-01T00:00:00.000Z" });
    await expect(
      synced.put("MINTED", "t", { expiresAt: "2026-12-01T00:00:00.000Z" }),
    ).rejects.toThrow();
    expect(unshared.names()).toEqual(["MINTED"]);
    up = true;
    await synced.put("OTHER", "o");
    expect(shared.values.MINTED).toBe("t");
    expect(shared.values.OTHER).toBe("o");
    expect(unshared.names()).toEqual([]);
    up = false;
    await expect(synced.put("LATER", "x")).rejects.toThrow();
    up = true;
    expect(await synced.share()).toEqual(["LATER"]);
    expect(await synced.share()).toEqual([]);
    expect(await store.remove("BOTH")).toBe(true);
    expect(shared.values.BOTH).toBeUndefined();
  });
});

describe("unshared file", () => {
  it("keeps names across instances, never values", () => {
    const dir = mkdtempSync(join(tmpdir(), "unshared-"));
    const path = join(dir, "unshared.json");
    unsharedFile(path).add("A");
    unsharedFile(path).add("B");
    unsharedFile(path).add("A");
    expect(unsharedFile(path).names()).toEqual(["A", "B"]);
    unsharedFile(path).drop("A");
    expect(readFileSync(path, "utf8")).toBe('["B"]\n');
    writeFileSync(path, "not json");
    expect(unsharedFile(path).names()).toEqual([]);
  });
});
