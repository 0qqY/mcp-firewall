import json, sys
from collections import Counter
from pathlib import Path
repo = Path(sys.argv[1])
prof = json.loads((repo / "profiles" / "pipelock.json").read_text(encoding="utf-8"))
per = {r["case_id"]: r for r in prof["per_case"]}
print("profil:", prof["tool"], prof["tool_version"], "korpus", prof["corpus_version"], "| per_case:", len(per))
mcp = {}
for p in sorted((repo / "cases").rglob("*.json")):
    if p.name in ("before.json", "after.json", "expected.json"): continue
    try: c = json.loads(p.read_text(encoding="utf-8"))
    except Exception: continue
    it = c.get("input_type") or ""
    if it.startswith("mcp_") or c.get("category") in ("mcp_input", "mcp_tool", "mcp_chain"):
        mcp[c["id"]] = c
inprof = {i: c for i, c in mcp.items() if i in per}
print("MCP vakası:", len(mcp), "| profilde bulunan:", len(inprof), "| profilde olmayan:", len(mcp) - len(inprof))
blk = [i for i, c in inprof.items() if c["expected_verdict"] == "block"]
alw = [i for i, c in inprof.items() if c["expected_verdict"] != "block"]
print("engel beklenen (profilde):", len(blk), Counter(per[i]["blocked"] for i in blk))
print("izin beklenen (profilde): ", len(alw), "false_positive alanı:", Counter(per[i]["false_positive"] for i in alw))
by_cat = {}
for i in blk:
    by_cat.setdefault(mcp[i]["category"], Counter())[per[i]["blocked"]] += 1
for k, v in sorted(by_cat.items()): print("  ", k, dict(v))
json.dump({"in_profile": sorted(inprof), "missing": sorted(set(mcp) - set(inprof))}, open(sys.argv[2], "w"))
