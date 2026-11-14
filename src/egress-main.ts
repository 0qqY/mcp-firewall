import { createEgressProxy, EGRESS_PORT, parseEgressRule, type EgressEvent } from './egress.js';

/**
 * Entry point of the egress proxy container: `node /fw/egress-main.js`, allowlist in MCP_FW_EGRESS (rule strings
 * separated by commas). Writes one JSON line per decision to stdout for the firewall's audit log, `{"ready":3128}` once it
 * listens, and exits when stdin closes (the firewall went away), so the container never outlives it.
 */

function main(): void {
  const out = (v: unknown) => process.stdout.write(`${JSON.stringify(v)}\n`);
  let rules;
  try {
    rules = (process.env.MCP_FW_EGRESS ?? '').split(',').filter(Boolean).map(parseEgressRule);
  } catch (err) {
    process.stderr.write(`egress proxy: bad allowlist: ${(err as Error).message}\n`);
    process.exit(2);
  }
  const server = createEgressProxy({ rules, log: (e: EgressEvent) => out(e) });
  server.on('error', (err) => {
    process.stderr.write(`egress proxy: ${err.message}\n`);
    process.exit(1);
  });
  server.listen(EGRESS_PORT, '0.0.0.0', () => out({ ready: EGRESS_PORT }));
  process.stdin.resume();
  process.stdin.on('end', () => process.exit(0));
  process.stdin.on('close', () => process.exit(0));
}

main();
