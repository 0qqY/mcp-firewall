"""Compares mlview.py (Python port) with the hashes the real TypeScript build produced (check_port_node.mjs)."""
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mlview import chunk_text, product_text
pairs, node_out = sys.argv[1], sys.argv[2]
rows = [json.loads(l) for l in open(pairs, encoding="utf-8") if l.strip()]
ref = json.load(open(node_out, encoding="utf-8"))
h = lambda s: hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:16]
bad_text = bad_chunks = 0
nonbmp_bad = 0
for r in ref:
    t = rows[r["i"]]["text"]
    ex = product_text(t)
    ch = chunk_text(ex, 1500)
    if h(ex) != r["ex"]:
        bad_text += 1
    elif r["n"] != len(ch) or r["ch"] != h("\x01".join(ch)):
        bad_chunks += 1
        if any(ord(c) > 0xFFFF for c in ex):
            nonbmp_bad += 1
print(f"örneklenen satır {len(ref)} | çıkarılan metin farklı: {bad_text} | pencereleme farklı: {bad_chunks} (bunların non-BMP karakter içerenleri: {nonbmp_bad})")
