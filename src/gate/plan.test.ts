import { describe, expect, it } from "vitest";
import { allowHostsRegex, gateConfigSchema, layer, planGate, SENTINEL, sentinel } from "./plan.js";
import { auditLine } from "./run.js";

const KEY = Buffer.alloc(32, 7);
const config = gateConfigSchema.parse({
  dir: "/tmp/x",
  mitmdump: "mitmdump",
  audit: "/tmp/x/audit.jsonl",
  sources: ["a"],
  hosts: { RESTATE_AUTH_TOKEN: ["restate.example.com"] },
  roles: {
    weaver: {
      port: 4772,
      upstream: "http://127.0.0.1:4762",
      keys: ["EXA_API_KEY*", "RESTATE_AUTH_TOKEN"],
      plain: ["NUM_*"],
    },
    desk: { port: 4773, upstream: "http://127.0.0.1:4763", keys: ["EXA_API_KEY"] },
  },
});
const values = new Map([
  ["EXA_API_KEY", "real-exa-0"],
  ["EXA_API_KEY_1", "real-exa-1"],
  ["NUM_EXA", "1"],
  ["RESTATE_AUTH_TOKEN", "real-restate"],
  ["OTHER_SECRET", "never-copied"],
]);

describe("sentinel", () => {
  it("is stable, 32 characters, and differs by role and name", () => {
    const s = sentinel(KEY, "weaver", "EXA_API_KEY");
    expect(s).toHaveLength(32);
    expect(s).toMatch(new RegExp(`^${SENTINEL.source}$`));
    expect(sentinel(KEY, "weaver", "EXA_API_KEY")).toBe(s);
    expect(sentinel(KEY, "desk", "EXA_API_KEY")).not.toBe(s);
    expect(sentinel(KEY, "weaver", "EXA_API_KEY_1")).not.toBe(s);
    expect(sentinel(Buffer.alloc(32, 8), "weaver", "EXA_API_KEY")).not.toBe(s);
  });
});

describe("planGate", () => {
  const plan = planGate(config, values, KEY);

  it("writes sentinels for keys, plain values for plain names, nothing else", () => {
    const weaver = new Map(plan.files.get("weaver")?.map((e) => [e.name, e.value]));
    expect([...weaver.keys()]).toEqual([
      "EXA_API_KEY",
      "EXA_API_KEY_1",
      "NUM_EXA",
      "RESTATE_AUTH_TOKEN",
    ]);
    expect(weaver.get("EXA_API_KEY")).toBe(sentinel(KEY, "weaver", "EXA_API_KEY"));
    expect(weaver.get("NUM_EXA")).toBe("1");
    const text = JSON.stringify([...plan.files]);
    for (const real of ["real-exa-0", "real-exa-1", "real-restate", "never-copied"])
      expect(text).not.toContain(real);
  });

  it("maps each sentinel to its role, value and hosts", () => {
    const k = plan.keys.get(sentinel(KEY, "weaver", "RESTATE_AUTH_TOKEN"));
    expect(k).toMatchObject({
      role: "weaver",
      value: "real-restate",
      hosts: ["restate.example.com"],
      site: "restate.example.com",
    });
    expect(plan.keys.get(sentinel(KEY, "desk", "EXA_API_KEY"))).toMatchObject({
      role: "desk",
      hosts: ["api.exa.ai"],
      site: "exa",
    });
    expect(plan.hosts).toEqual(["api.exa.ai", "restate.example.com"]);
  });

  it("refuses a key with no hosts, a key listed as plain, and a shared port", () => {
    const bad = (roles: object, hosts = {}) =>
      planGate(gateConfigSchema.parse({ ...config, hosts, roles }), values, KEY);
    expect(() =>
      bad({ w: { port: 4772, upstream: "http://127.0.0.1:1", keys: ["OTHER_SECRET"] } }),
    ).toThrow(/OTHER_SECRET has no hosts/);
    expect(() =>
      bad({ w: { port: 4772, upstream: "http://127.0.0.1:1", plain: ["EXA_API_KEY"] } }),
    ).toThrow(/is a key/);
    expect(() =>
      bad({
        a: { port: 4772, upstream: "http://127.0.0.1:1" },
        b: { port: 4772, upstream: "http://127.0.0.1:1" },
      }),
    ).toThrow(/taken/);
  });

  it("audits a use with the key id and no value", () => {
    const line = auditLine(
      {
        t: "use",
        role: "weaver",
        key_role: "weaver",
        name: "EXA_API_KEY",
        host: "api.exa.ai",
        path: "/search",
      },
      plan,
    );
    expect(line).toMatchObject({
      credential: "EXA_API_KEY",
      site: "exa",
      url: "https://api.exa.ai/search",
      by: "gate:weaver",
      allowed: true,
    });
    expect(line.keyId).toMatch(/^[0-9a-f]{12}$/);
    expect(JSON.stringify(line)).not.toContain("real-exa");
  });
});

describe("layer", () => {
  it("lets an earlier source win a name", () => {
    const m = layer([
      [{ name: "A", value: "1" }],
      [
        { name: "A", value: "2" },
        { name: "B", value: "3" },
      ],
    ]);
    expect(Object.fromEntries(m)).toEqual({ A: "1", B: "3" });
  });
});

describe("allowHostsRegex", () => {
  it("matches the hosts with or without a port, and nothing else", () => {
    const re = new RegExp(allowHostsRegex(["api.exa.ai", "*.example.com"]));
    expect(re.test("api.exa.ai:443")).toBe(true);
    expect(re.test("api.exa.ai")).toBe(true);
    expect(re.test("a.b.example.com:443")).toBe(true);
    expect(re.test("api.exa.ai.evil.com:443")).toBe(false);
    expect(re.test("apiXexa.ai")).toBe(false);
  });
});
