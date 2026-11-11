/**
 * The read relay's spend: one JSON line per tunnel (`RelayUse`) in `<dir>/relay-usage.jsonl`, an
 * alert each time a UTC day's bytes pass another `alertGb`, and the summary `gate usage` prints.
 * GB here is 10^9 bytes: it reads a little over a vendor's 2^30, never under.
 */
import { createWriteStream, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { RelayUse } from "./relay.js";

export const GB = 1e9;
export const usagePath = (dir: string) => join(dir, "relay-usage.jsonl");

export function readUses(path: string): RelayUse[] {
  if (!existsSync(path)) return [];
  const out: RelayUse[] = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line) continue;
    try {
      out.push(JSON.parse(line) as RelayUse);
    } catch {
      // a torn last line after a crash
    }
  }
  return out;
}

const dayOf = (iso: string) => iso.slice(0, 10);
const bytes = (u: RelayUse) => u.up + u.down;

/** Appends each use; `alert` once per `alertGb` step a day crosses (counted from the file on start). */
export function usageLog(
  path: string,
  o: { alertGb: number; pricePerGb: number; alert: (line: string) => void; now?: () => Date },
): (u: RelayUse) => void {
  const now = o.now ?? (() => new Date());
  let day = dayOf(now().toISOString());
  let total = readUses(path)
    .filter((u) => dayOf(u.at) === day)
    .reduce((n, u) => n + bytes(u), 0);
  const step = (n: number) => Math.floor(n / (o.alertGb * GB));
  let seen = step(total);
  const file = createWriteStream(path, { flags: "a", mode: 0o600 });
  return (u) => {
    file.write(`${JSON.stringify(u)}\n`);
    const d = dayOf(u.at);
    if (d !== day) {
      day = d;
      total = 0;
      seen = 0;
    }
    total += bytes(u);
    if (step(total) > seen) {
      seen = step(total);
      const gb = total / GB;
      o.alert(
        `ALERT read relay: ${gb.toFixed(2)} GB today (~$${(gb * o.pricePerGb).toFixed(2)}), past ${(seen * o.alertGb).toFixed(2)} GB`,
      );
    }
  };
}

/** `rr3---sn-x.googlevideo.com:443` → `googlevideo.com`. */
export const siteOf = (host: string) => host.replace(/:\d+$/, "").split(".").slice(-2).join(".");

interface Tally {
  gb: number;
  usd: number;
  tunnels: number;
  failed: number;
}

function tally(us: RelayUse[], price: number): Tally {
  const gb = us.reduce((n, u) => n + bytes(u), 0) / GB;
  return {
    gb: Number(gb.toFixed(4)),
    usd: Number((gb * price).toFixed(4)),
    tunnels: us.length,
    failed: us.filter((u) => u.status !== "200").length,
  };
}

/** Per day (newest first), per site (costliest first, top 15), and the window's total. */
export function usageSummary(
  uses: RelayUse[],
  o: { pricePerGb: number; days: number; now?: Date },
): {
  pricePerGb: number;
  since: string;
  total: Tally & { reads: number };
  days: (Tally & { day: string; reads: number })[];
  sites: (Tally & { site: string })[];
} {
  const since = new Date((o.now ?? new Date()).getTime() - (o.days - 1) * 86_400_000)
    .toISOString()
    .slice(0, 10);
  const win = uses.filter((u) => dayOf(u.at) >= since);
  const group = <K extends string>(key: (u: RelayUse) => K) => {
    const m = new Map<K, RelayUse[]>();
    for (const u of win) m.set(key(u), [...(m.get(key(u)) ?? []), u]);
    return m;
  };
  const reads = (us: RelayUse[]) => new Set(us.map((u) => u.session).filter(Boolean)).size;
  return {
    pricePerGb: o.pricePerGb,
    since,
    total: { ...tally(win, o.pricePerGb), reads: reads(win) },
    days: [...group((u) => dayOf(u.at))]
      .sort(([a], [b]) => (a < b ? 1 : -1))
      .map(([day, us]) => ({ day, ...tally(us, o.pricePerGb), reads: reads(us) })),
    sites: [...group((u) => siteOf(u.host))]
      .map(([site, us]) => ({ site, ...tally(us, o.pricePerGb) }))
      .sort((a, b) => b.gb - a.gb)
      .slice(0, 15),
  };
}
