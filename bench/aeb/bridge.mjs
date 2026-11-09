// Stdio-to-TCP bridge (the documented way to satisfy the Agent Egress Bench "runner-owned upstream" contract for a
// stdio-only backend): passes the line-delimited JSON-RPC stream in both directions between the firewall's child
// process pipes and the runner's loopback listener.
import net from 'node:net';

const [host, port] = String(process.argv[2] ?? '').split(':');
const socket = net.connect(Number(port), host);
process.stdin.pipe(socket);
socket.pipe(process.stdout);
socket.on('close', () => process.exit(0));
socket.on('error', () => process.exit(1));
process.stdin.on('end', () => socket.end());
