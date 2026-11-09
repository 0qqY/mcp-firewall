import json, sys
rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8")]
only = sys.argv[2] if len(sys.argv) > 2 else "fail"   # fail | all
for r in sorted(rows, key=lambda r: (r["category"], r["case_id"])):
    if only == "fail" and r["score"] == "pass":
        continue
    note = (r.get("detail") or "")[:70]
    aud = "; ".join(r.get("audit") or [])[:90]
    print(f'{r["score"].upper():5} {r["case_id"]:50} {r["transport"][4:]:5} {r["expected"]}->{r["actual"]:8} {note} | {aud}')
print(len([r for r in rows if r["score"] != "pass"]), "hatalı /", len(rows))
