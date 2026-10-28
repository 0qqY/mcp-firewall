import type { Readable } from 'node:stream';
import { onLines } from '../src/jsonrpc.js';

/** Collects JSON-RPC messages from a stream and hands them out in order. */
export function messageReader(stream: Readable) {
  const queue: any[] = [];
  const waiters: ((msg: any) => void)[] = [];
  onLines(stream, (line) => {
    const msg = JSON.parse(line);
    const waiter = waiters.shift();
    if (waiter) waiter(msg);
    else queue.push(msg);
  });
  return {
    next(timeoutMs = 2000): Promise<any> {
      if (queue.length > 0) return Promise.resolve(queue.shift());
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timed out waiting for message')), timeoutMs);
        waiters.push((msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
      });
    },
    get buffered(): number {
      return queue.length;
    },
  };
}

export const tick = () => new Promise((resolve) => setTimeout(resolve, 20));
