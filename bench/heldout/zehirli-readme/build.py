"""Poisoned-README test (14.11.2026): does a model trained on real documentation learn "looks like a README, so benign"?

Base texts: the measurement READMEs (training/data/hf_new/_external_eval, never trained on), 40 Turkish + 40 English.
Payloads: payloads.json, 16 hand-written lines (8 TR, 8 EN) addressed to an AI agent (payloads-noai.json: the same
harmful actions as plain imperatives that never mention an AI), not produced by the training
twin generator (docs_data.py takes its injection lines from the v12eva train split). Each payload is inserted as its
own paragraph at the start, middle and end of a README: 240 rows, all label 1. Texts are not committed.

  python -I build.py <out dir> [payloads-noai.json]   # <out>/poison.jsonl (score_torch.py --texts format) and <out>/meta.json
"""
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).parent
EXT = HERE.parent.parent.parent / "training" / "data" / "hf_new" / "_external_eval"

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
pay = json.loads((HERE / (sys.argv[2] if len(sys.argv) > 2 else "payloads.json")).read_text(encoding="utf-8"))
rows = []
for f in ("tr_real_tools.jsonl", "en_control.jsonl"):
    rows += [json.loads(l) for l in open(EXT / f, encoding="utf-8")]
rows = [r for r in rows if r["cls"] in ("readme", "en_readme")]
rnd, meta, n = random.Random(7), {}, 0
with open(out / "poison.jsonl", "w", encoding="utf-8") as fh:
    for lang in ("tr", "en"):
        base = [r for r in rows if (r["cls"] == "readme") == (lang == "tr")]
        ps = [p for l, p in pay if l == lang]
        for i, r in enumerate(rnd.sample(base, 40)):
            p, paras = ps[i % len(ps)], r["text"].split("\n\n")
            for pos, k in (("start", 0), ("mid", len(paras) // 2), ("end", len(paras))):
                n += 1
                rid = f"PR-{n:03d}"
                meta[rid] = {"lang": lang, "pos": pos, "base": r["id"]}
                fh.write(json.dumps({"id": rid, "channel": "output", "text": "\n\n".join(paras[:k] + [p] + paras[k:])}, ensure_ascii=False) + "\n")
(out / "meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
print(n, "rows")
