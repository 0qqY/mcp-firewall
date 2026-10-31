import type { Readable, Writable } from 'node:stream';

export type JsonRpcId = string | number | null;
export type JsonObject = Record<string, unknown>;

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: JsonRpcId;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
}

/** JSON-RPC error code used for messages the firewall refuses. */
export const FIREWALL_ERROR_CODE = -32001;

/** Lines longer than this are dropped instead of buffered (memory exhaustion guard). */
export const MAX_LINE_LENGTH = 32 * 1024 * 1024;

export const isObject = (v: unknown): v is JsonObject =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

export const isRequest = (m: JsonRpcMessage): m is JsonRpcMessage & { method: string; id: JsonRpcId } =>
  typeof m.method === 'string' && m.id !== undefined;

export const isNotification = (m: JsonRpcMessage): m is JsonRpcMessage & { method: string } =>
  typeof m.method === 'string' && m.id === undefined;

export const isResponse = (m: JsonRpcMessage): boolean => m.method === undefined && m.id !== undefined;

export const idKey = (id: JsonRpcId | undefined): string => JSON.stringify(id ?? null);

/**
 * Parses one stdio line. Batches are returned as their elements; anything that is not
 * a JSON object (or an array of them) yields undefined.
 */
export function parseMessage(line: string): JsonRpcMessage[] | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return undefined;
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  return items.length > 0 && items.every(isObject) ? (items as JsonRpcMessage[]) : undefined;
}

export function send(stream: Writable, msg: JsonRpcMessage): void {
  stream.write(`${JSON.stringify(msg)}\n`);
}

/** MCP stdio framing: one JSON-RPC message per newline-terminated line. */
export function onLines(stream: Readable, onLine: (line: string) => void, onOversized?: () => void): void {
  let buffer = '';
  let discarding = false;
  stream.setEncoding('utf8');
  stream.on('data', (chunk: string) => {
    buffer += chunk;
    let newline: number;
    while ((newline = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, newline).replace(/\r$/, '');
      buffer = buffer.slice(newline + 1);
      if (discarding) {
        discarding = false;
        continue;
      }
      if (line.trim()) onLine(line);
    }
    if (buffer.length > MAX_LINE_LENGTH) {
      buffer = '';
      if (!discarding) onOversized?.();
      discarding = true;
    }
  });
  stream.on('end', () => {
    if (!discarding && buffer.trim()) onLine(buffer);
  });
}

export function errorResponse(id: JsonRpcId | undefined, reason: string): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: id ?? null,
    error: { code: FIREWALL_ERROR_CODE, message: `Blocked by Tuuf MCP Firewall: ${reason}` },
  };
}

/** A tools/call refusal is returned as a tool error so the model sees why the call failed. */
export function toolErrorResponse(id: JsonRpcId | undefined, reason: string): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: id ?? null,
    result: { content: [{ type: 'text', text: `[Tuuf MCP Firewall] Blocked: ${reason}` }], isError: true },
  };
}
