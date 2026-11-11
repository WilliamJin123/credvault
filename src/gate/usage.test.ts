import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { RelayUse } from "./relay.js";
import { GB, readUses, siteOf, usageLog, usageSummary } from "./usage.js";

const use = (at: string, host: string, bytes: number, status = "200"): RelayUse => ({
  at,
  host,
  session: host,
  up: bytes / 4,
  down: (bytes * 3) / 4,
  ms: 10,
  status,
});
const flush = () => new Promise((r) => setTimeout(r, 20));

describe("relay usage", () => {
  it("appends each use, mode 0600, and alerts once per step a day passes", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "usage-")), "relay-usage.jsonl");
    const alerts: string[] = [];
    const log = usageLog(path, {
      alertGb: 0.5,
      pricePerGb: 1,
      alert: (l) => alerts.push(l),
      now: () => new Date("2026-11-11T10:00:00Z"),
    });
    log(use("2026-11-11T10:00:00Z", "a.googlevideo.com:443", 0.3 * GB));
    log(use("2026-11-11T10:01:00Z", "b.googlevideo.com:443", 0.3 * GB));
    log(use("2026-11-11T10:02:00Z", "c.googlevideo.com:443", 0.1 * GB));
    log(use("2026-11-12T00:01:00Z", "www.youtube.com:443", 0.2 * GB));
    await flush();
    expect(alerts).toEqual(["ALERT read relay: 0.60 GB today (~$0.60), past 0.50 GB"]);
    expect(readUses(path)).toHaveLength(4);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("counts today's bytes from the file on restart", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "usage-")), "relay-usage.jsonl");
    const now = () => new Date("2026-11-11T12:00:00Z");
    const first = usageLog(path, { alertGb: 1, pricePerGb: 1, alert: () => {}, now });
    first(use("2026-11-11T11:00:00Z", "x.com:443", 0.9 * GB));
    await flush();
    const alerts: string[] = [];
    const second = usageLog(path, { alertGb: 1, pricePerGb: 1, alert: (l) => alerts.push(l), now });
    second(use("2026-11-11T12:00:00Z", "x.com:443", 0.2 * GB));
    expect(alerts).toHaveLength(1);
    expect(readFileSync(path, "utf8").trim().split("\n")).toHaveLength(1);
  });

  it("skips a torn last line", () => {
    const dir = mkdtempSync(join(tmpdir(), "usage-"));
    const path = join(dir, "u.jsonl");
    writeFileSync(path, `${JSON.stringify(use("2026-11-11T00:00:00Z", "a.com:443", 10))}\n{"at":`);
    expect(readUses(path)).toHaveLength(1);
  });

  it("sums by day and by site in the window, at the price", () => {
    const uses = [
      use("2026-11-09T09:00:00Z", "old.com:443", GB),
      use("2026-11-10T09:00:00Z", "rr1---sn-a.googlevideo.com:443", 0.4 * GB),
      use("2026-11-11T09:00:00Z", "rr2---sn-b.googlevideo.com:443", 0.2 * GB),
      use("2026-11-11T09:01:00Z", "www.youtube.com:443", 0.1 * GB, "502"),
    ];
    const s = usageSummary(uses, { pricePerGb: 2, days: 2, now: new Date("2026-11-11T20:00:00Z") });
    expect(s.since).toBe("2026-11-10");
    expect(s.total).toMatchObject({ gb: 0.7, usd: 1.4, tunnels: 3, failed: 1, reads: 3 });
    expect(s.days.map((d) => [d.day, d.gb])).toEqual([
      ["2026-11-11", 0.3],
      ["2026-11-10", 0.4],
    ]);
    expect(s.sites.map((x) => [x.site, x.gb])).toEqual([
      ["googlevideo.com", 0.6],
      ["youtube.com", 0.1],
    ]);
    expect(siteOf("www.youtube.com")).toBe("youtube.com");
  });
});
