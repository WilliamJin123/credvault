#!/usr/bin/env node
/**
 * `credvault gate --config <file>`: runs the key gate until stopped.
 * `credvault gate usage --config <file> [--days N]`: the read relay's spend, JSON.
 */
import { gate, loadGateConfig } from "./gate/run.js";
import { readUses, usagePath, usageSummary } from "./gate/usage.js";

const USAGE = "usage: credvault gate [usage] --config <file> [--days N]";

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd !== "gate") {
    console.error(USAGE);
    return 2;
  }
  const i = rest.indexOf("--config");
  const path = i >= 0 ? rest[i + 1] : undefined;
  if (!path) {
    console.error(USAGE);
    return 2;
  }
  const config = await loadGateConfig(path);
  if (rest[0] === "usage") {
    const d = rest.indexOf("--days");
    const days = d >= 0 ? Number(rest[d + 1]) : 7;
    if (!config.relay || !(days >= 1)) {
      console.error(config.relay ? USAGE : "credvault gate: no relay in this config");
      return 2;
    }
    const uses = readUses(usagePath(config.dir));
    console.log(
      JSON.stringify(usageSummary(uses, { pricePerGb: config.relay.pricePerGb, days }), null, 2),
    );
    return 0;
  }
  const g = await gate(config);
  const roles = [...g.plan.files.keys()].join(", ");
  console.error(
    `credvault gate: up; roles ${roles}; ${g.plan.keys.size} keys on ${g.plan.hosts.length} hosts`,
  );
  for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => g.stop());
  return g.done;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(`credvault gate: ${(err as Error).message}`);
    process.exit(1);
  },
);
