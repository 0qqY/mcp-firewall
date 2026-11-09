"""Combines the per-profile results.jsonl files of the AEB runner into the tables used in the report.

Only reads files.  usage: python -I aggregate.py <out dir holding one folder per profile> <pipelock_subset.json> > tables.md
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

OUT = Path(sys.argv[1])
SUBSET = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")) if len(sys.argv) > 2 else {"in_profile": []}
PROFILES = [p for p in ("defaults", "installed", "example-ml", "example-ml-block", "tuned") if (OUT / p / "results.jsonl").exists()]
data = {p: [json.loads(l) for l in (OUT / p / "results.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()] for p in PROFILES}
by_id = {p: {r["case_id"]: r for r in rows} for p, rows in data.items()}
ids = sorted({i for p in PROFILES for i in by_id[p]})
ref = next(iter(by_id.values()))


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "-"


def stats(rows):
    blk = [r for r in rows if r["expected"] == "block"]
    alw = [r for r in rows if r["expected"] != "block"]
    return {
        "n": len(rows),
        "blk": len(blk), "det": sum(r["score"] == "pass" for r in blk), "mod": sum(r["actual"] == "modified" for r in blk),
        "miss": sum(r["actual"] == "allow" for r in blk), "lenient": sum(r["lenient"] == "pass" for r in blk),
        "alw": len(alw), "ok": sum(r["score"] == "pass" for r in alw), "fp": sum(r["actual"] == "block" for r in alw),
        "alt": sum(r["actual"] == "modified" for r in alw), "err": sum(r["score"] == "error" for r in rows),
    }


print("## 1. Profil özeti (87 MCP vakası)\n")
print("| profil | engel beklenen | engelledi (katı) | maskeleyip/değiştirip iletti | kaçırdı | gevşek ölçü* | izin beklenen | izin verdi | yanlış engel | zararsızı değiştirdi | hata |")
print("|---|---|---|---|---|---|---|---|---|---|---|")
for p in PROFILES:
    s = stats(data[p])
    print(f"| {p} | {s['blk']} | {s['det']} ({pct(s['det'], s['blk'])}) | {s['mod']} | {s['miss']} | {s['lenient']} ({pct(s['lenient'], s['blk'])}) | {s['alw']} | {s['ok']} ({pct(s['ok'], s['alw'])}) | {s['fp']} | {s['alt']} | {s['err']} |")
print("\n*gevşek ölçü: engelleme + maskeleyerek/silerek iletme (tehdit içeriği değiştirilmiş) sayılır.\n")

print("## 2. Taşıma bazında (katı engelleme / yanlış engel)\n")
print("| profil | stdio engel | stdio izin | HTTP (gateway) engel | HTTP izin |")
print("|---|---|---|---|---|")
for p in PROFILES:
    cells = []
    for tr in ("mcp_stdio", "mcp_http"):
        s = stats([r for r in data[p] if r["transport"] == tr])
        cells += [f"{s['det']}/{s['blk']} ({pct(s['det'], s['blk'])})", f"{s['ok']}/{s['alw']} ({pct(s['ok'], s['alw'])})"]
    print(f"| {p} | " + " | ".join(cells) + " |")

print("\n## 3. Kategori bazında (katı engelleme; yanlış engel)\n")
cats = sorted({r["category"] for r in ref.values()})
print("| kategori | n | " + " | ".join(PROFILES) + " |")
print("|---|---|" + "---|" * len(PROFILES))
for c in cats:
    cells = []
    n = 0
    for p in PROFILES:
        rs = [r for r in data[p] if r["category"] == c]
        n = len(rs)
        s = stats(rs)
        parts = []
        if s["blk"]:
            parts.append(f"{s['det']}/{s['blk']} engel" + (f", {s['mod']} maske" if s["mod"] else ""))
        if s["alw"]:
            parts.append(f"{s['ok']}/{s['alw']} izin" + (f" ({s['fp']} yanlış)" if s["fp"] else ""))
        cells.append("; ".join(parts))
    print(f"| {c} | {n} | " + " | ".join(cells) + " |")

print("\n## 4. Engelleri kim yaptı? (katı engelleyen vakalarda gerekçe ailesi)\n")


COLS = ["ML sınıflandırıcı", "desen + ML", "tanım/instructions deseni", "DLP / kod çözücü", "yol kısıtı (paths)", "argüman regex kuralı", "veri akışı (taint)", "diğer"]


def family(r):
    """Which mechanism the audit note / client-visible reason names (patterns and ML can both be named in one note)."""
    text = " ".join([r.get("detail") or ""] + (r.get("audit") or []))
    has_ml = "ML classifier" in text
    has_pat = bool(re.search(r"suspicious pattern|possible tool poisoning|instructions removed|hidden unicode", text, re.I))
    if "denied by path" in text:
        return "yol kısıtı (paths)"
    if "deny pattern" in text:
        return "argüman regex kuralı"
    if "data flow" in text:
        return "veri akışı (taint)"
    if "sensitive data" in text:
        return "DLP / kod çözücü"
    if has_ml and has_pat:
        return "desen + ML"
    if has_ml:
        return "ML sınıflandırıcı"
    if has_pat:
        return "tanım/instructions deseni"
    return "diğer"


print("| profil | " + " | ".join(COLS) + " |")
print("|---|" + "---|" * len(COLS))
for p in PROFILES:
    c = Counter(family(r) for r in data[p] if r["actual"] == "block")
    print(f"| {p} | " + " | ".join(str(c.get(k, 0)) for k in COLS) + " |")

print("\n## 5. Pipelock'un kendi yayımladığı profille örtüşen vakalar\n")
inp = set(SUBSET.get("in_profile", []))
print("(Pipelock 3.1.0, korpus v2.0.0, satıcı beyanı: örtüşen 39 engel-beklenen vakanın 39'u 'blocked: yes', 10 izin-beklenen vakada yanlış alarm yok.)\n")
print("| profil | örtüşen engel-beklenen: engelledi (katı) | gevşek | örtüşen izin-beklenen: yanlış engel |")
print("|---|---|---|---|")
for p in PROFILES:
    rs = [r for r in data[p] if r["case_id"] in inp]
    s = stats(rs)
    print(f"| {p} | {s['det']}/{s['blk']} | {s['lenient']}/{s['blk']} | {s['fp']}/{s['alw']} |")

print("\n## 6. Vaka bazında matris (B=engelledi, A=izin verdi, M=değiştirip iletti, E=hata; ✓ beklenene uydu, ✗ uymadı)\n")
print("| vaka | kategori | taşıma | beklenen | " + " | ".join(PROFILES) + " |")
print("|---|---|---|---|" + "---|" * len(PROFILES))
for i in ids:
    r0 = ref.get(i) or next(by_id[p][i] for p in PROFILES if i in by_id[p])
    cells = []
    for p in PROFILES:
        r = by_id[p].get(i)
        if not r:
            cells.append("-")
            continue
        letter = {"block": "B", "allow": "A", "modified": "M", "error": "E"}[r["actual"]]
        cells.append(letter + ("✓" if r["score"] == "pass" else "✗"))
    print(f"| {i} | {r0['category']} | {r0['transport'][4:]} | {r0['expected']} | " + " | ".join(cells) + " |")
