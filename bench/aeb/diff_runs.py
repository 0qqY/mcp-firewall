"""Case-by-case comparison of two AEB runs of the same profile (before / after a firewall change).

Only reads files.  usage: python -I diff_runs.py <before results.jsonl> <after results.jsonl>
"""
import json
import sys

load = lambda p: {r["case_id"]: r for r in (json.loads(l) for l in open(p, encoding="utf-8") if l.strip())}
before, after = load(sys.argv[1]), load(sys.argv[2])
improved = regressed = changed = 0
for cid in sorted(set(before) & set(after)):
    a, b = before[cid], after[cid]
    if a["actual"] == b["actual"]:
        continue
    changed += 1
    kind = "="
    if a["score"] != "pass" and b["score"] == "pass":
        improved += 1
        kind = "+"
    elif a["score"] == "pass" and b["score"] != "pass":
        regressed += 1
        kind = "!"
    print(f'{kind} {cid:52} {a["actual"]:8} -> {b["actual"]:8} (beklenen {a["expected"]}) {str(b.get("detail") or "")[:70]}')
print(f"\nsonuç değişen: {changed} | katı skorda düzelen: {improved} | katı skorda bozulan: {regressed} | ortak vaka: {len(set(before) & set(after))}")
