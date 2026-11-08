#!/usr/bin/env node
/** `credvault gate --config <file>`: runs the key gate until stopped. */
import { gate, loadGateConfig } from "./gate/run.js";

const USAGE = "usage: credvault gate --config <file>";

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
  const g = await gate(await loadGateConfig(path));
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
