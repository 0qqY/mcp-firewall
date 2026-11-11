"""Several models side by side on an external row file (score.mjs / score_torch.py result files).

  python -I -X utf8 bench/heldout/compare_external.py --rows <rows.jsonl> [--by cls] [--md out.md] <result.json> ...

Each model is judged at its own threshold (the `threshold` stored in its result file). Rows with label 1 give recall, rows with
label 0 the share that was flagged (false positives when the set is labelled benign, "flagged" when it is unlabelled).
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--rows", type=Path, required=True)
ap.add_argument("--by", default="cls")
ap.add_argument("--md", type=Path)
ap.add_argument("results", type=Path, nargs="+")
args = ap.parse_args()

rows = [json.loads(l) for l in open(args.rows, encoding="utf-8") if l.strip()]
groups = defaultdict(list)
for r in rows:
    groups[(r.get(args.by) or "-", r["label"])].append(r["id"])
keys = sorted(groups)


def pct(ids: list[str], score: dict, thr: float) -> str:
    n = sum(score[i] >= thr for i in ids)
    return f"{100 * n / len(ids):.1f}% ({n}/{len(ids)})"


head = ["model", "eşik"] + [f"{k} {'recall' if label else 'işaretlenen'}" for k, label in keys] + ["tümü: recall", "tümü: işaretlenen benign"]
lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
for path in args.results:
    res = json.load(open(path, encoding="utf-8"))
    score = {r["id"]: r["score"] for r in res["results"]}
    thr = res["threshold"]
    pos = [r["id"] for r in rows if r["label"] == 1]
    neg = [r["id"] for r in rows if r["label"] == 0]
    cells = [res["model"], str(thr)] + [pct(groups[k], score, thr) for k in keys]
    cells += [pct(pos, score, thr) if pos else "-", pct(neg, score, thr) if neg else "-"]
    lines.append("| " + " | ".join(cells) + " |")
text = "\n".join(lines) + "\n"
print(text)
if args.md:
    args.md.write_text(text, encoding="utf-8")
