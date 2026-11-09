// Probe: what does the shipped decoder make of the AEB double-encoded and base64 cases? (reads the built module only)
import { pathToFileURL } from 'node:url';
const { withDecoded } = await import(pathToFileURL(process.argv[2]).href);
const cases = {
  'double-encode-009 (base64 of hex of AKIA...)': 'NDE0YjQ5NDE0OTRmNTM0NjRmNDQ0ZTRlMzc0NTU4NDE0ZDUwNGM0NQ==',
  'base64-007 (sk_test key)': 'QVBTX0tFWT1za190ZXN0XzRlQzM5SHFMeWpXRGFyanRUMXpkcDdkYw==',
  'control: base64 of AKIA... directly': Buffer.from('AKIAIOSFODNN7EXAMPLE').toString('base64'),
  'control: hex of AKIA... directly': Buffer.from('AKIAIOSFODNN7EXAMPLE').toString('hex'),
};
for (const [name, text] of Object.entries(cases)) {
  const out = withDecoded(text);
  console.log('##', name, '\n   ->', JSON.stringify(out).slice(0, 300));
}
