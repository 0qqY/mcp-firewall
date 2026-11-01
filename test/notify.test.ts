import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describe, DesktopNotifier } from '../src/notify.js';
import { compilePolicy } from '../src/policy.js';
import type { SiemRecord } from '../src/siem.js';

const rec = (verdict: SiemRecord['verdict'], reason: string, tool = 'read_text_file'): SiemRecord =>
  ({ ts: '2026-11-01T12:00:00Z', server: 'filesystem', verdict, tool, reason });

test('describe turns firewall reasons into short Turkish text', () => {
  const d = describe(rec('block', 'ML classifier flagged possible prompt injection (score 0.998)'));
  assert.equal(d.title, 'Tuuf MCP Firewall engelledi');
  assert.equal(d.body, 'filesystem · read_text_file: olası prompt enjeksiyonu');
  assert.match(describe(rec('redact', 'sensitive data in result: aws_access_key')).body, /hassas veri/);
  assert.match(describe(rec('block', 'something new')).body, /something new$/);
});

test('the first block shows at once, a burst becomes one summary, other verdicts stay quiet', async () => {
  const shown: [string, string][] = [];
  let now = 1_000;
  const n = new DesktopNotifier({ enabled: true, on: ['block'], quietSeconds: 30 }, (t, b) => shown.push([t, b]), () => now);
  n.send(rec('warn', 'ML classifier flagged possible prompt injection (score 0.95)'));
  assert.equal(shown.length, 0);
  n.send(rec('block', 'ML classifier flagged possible prompt injection (score 0.99)'));
  assert.equal(shown.length, 1);
  assert.match(shown[0][1], /Ayrıntı: http:\/\/127\.0\.0\.1:4747/);
  now += 1_000;
  n.send(rec('block', 'ML classifier flagged possible prompt injection (score 0.99)', 'a'));
  n.send(rec('block', 'tool definition changed since it was pinned (possible rug pull)', 'b'));
  assert.equal(shown.length, 1);
  await n.flush();
  assert.equal(shown.length, 2);
  assert.equal(shown[1][0], 'Tuuf MCP Firewall: 2 yeni olay');
  assert.match(shown[1][1], /Sonuncusu filesystem · b: araç tanımı onaydan sonra değişti/);
  n.close();
});

test('audit.notify is off by default and checks its verdicts', () => {
  assert.deepEqual(compilePolicy({}, '.').audit.notify, { enabled: false, on: ['block'], quietSeconds: 30 });
  assert.deepEqual(compilePolicy({ audit: { notify: { enabled: true, on: ['block', 'redact'] } } }, '.').audit.notify.on, ['block', 'redact']);
  assert.throws(() => compilePolicy({ audit: { notify: { on: ['allow'] } } }, '.'), /audit.notify.on/);
});
