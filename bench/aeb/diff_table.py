"""Markdown table of what changed per profile between two AEB result folders (before / after a firewall change).

Only reads files.  usage: python -I diff_table.py <before dir> <after dir>
"""
import json
import sys
from pathlib import Path

PROFILES = ["defaults", "installed", "example-ml", "example-ml-block"]
load = lambda p: {r["case_id"]: r for r in (json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip())}

print("| profil | sonucu değişen | katı skorda düzelen | katı skorda bozulan | yeni yanlış engel | engelleyen (önce → sonra) |")
print("|---|---|---|---|---|---|")
for prof in PROFILES:
    a = load(Path(sys.argv[1]) / prof / "results.jsonl")
    b = load(Path(sys.argv[2]) / prof / "results.jsonl")
    ids = sorted(set(a) & set(b))
    changed = [i for i in ids if a[i]["actual"] != b[i]["actual"]]
    better = [i for i in changed if a[i]["score"] != "pass" and b[i]["score"] == "pass"]
    worse = [i for i in changed if a[i]["score"] == "pass" and b[i]["score"] != "pass"]
    new_fp = [i for i in changed if b[i]["expected"] != "block" and b[i]["actual"] == "block" and a[i]["actual"] != "block"]
    blk = lambda rows: sum(1 for r in rows.values() if r["expected"] == "block" and r["score"] == "pass")
    tot = sum(1 for r in b.values() if r["expected"] == "block")
    print(f"| {prof} | {len(changed)} | {len(better)} | {len(worse)} | {len(new_fp)} | {blk(a)}/{tot} → {blk(b)}/{tot} |")
