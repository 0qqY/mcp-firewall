"""Score the rebuilt benchmark sets with one of our mmBERT models, the way the firewall reads tool results.

Two views of every text:
  product  extract_ml_text of {"content":[{"type":"text","text":...}]} (src/proxy.ts -> extractMlText), then
           1500-char windows (1/8 overlap, at most 32 windows, head+tail kept), max P(INJECTION) over windows
  raw      the serialized tool output itself (what every detector in the published benchmark sees), same windows

Only reads files. Run with the training venv in isolated mode:
  python -I score_views.py --training <training dir> --build <sets dir> --model <model dir> --out <prefix>
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("--training", type=Path, required=True)
ap.add_argument("--build", type=Path, required=True)
ap.add_argument("--model", type=Path, required=True)
ap.add_argument("--out", type=Path, required=True, help="prefix of the .npz file")
ap.add_argument("--views", nargs="+", default=["product", "raw"])
ap.add_argument("--sets", nargs="*", default=None)
ap.add_argument("--limit", type=int, default=0, help="rows per set (smoke test)")
ap.add_argument("--batch", type=int, default=32)
ap.add_argument("--chunk", type=int, default=1500)
ap.add_argument("--max-chunks", type=int, default=32)
args = ap.parse_args()

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(args.training))
import torch  # noqa: E402
from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: E402

from evaluate import injection_index  # noqa: E402
from mlview import chunk_text, product_text, within_budget  # noqa: E402

DEV = "cuda" if torch.cuda.is_available() else "cpu"
SETS = ["agentdojo_benign_outputs", "agentdojo_pairs", "agentdojo_pairs_shift", "bipia_pairs", "taubench_eval", "corpus"]

tok = AutoTokenizer.from_pretrained(args.model)
model = AutoModelForSequenceClassification.from_pretrained(args.model, dtype=torch.float32).to(DEV).eval()
INJ = injection_index(model.config.id2label)
print(f"model {args.model.parent.name}/{args.model.name} on {DEV}, injection index {INJ}", flush=True)


@torch.inference_mode()
def score_texts(texts):
    owners, pieces = [], []
    for i, t in enumerate(texts):
        for c in within_budget(chunk_text(t, args.chunk), args.max_chunks):
            owners.append(i)
            pieces.append(c)
    order = np.argsort([len(p) for p in pieces], kind="stable")
    out = np.zeros(len(pieces), dtype=np.float32)
    for s in range(0, len(order), args.batch):
        idx = order[s : s + args.batch]
        enc = tok([pieces[j] for j in idx], truncation=True, max_length=512, padding=True, return_tensors="pt").to(DEV)
        out[idx] = torch.softmax(model(**enc).logits.float(), dim=-1)[:, INJ].cpu().numpy()
    res = np.zeros(len(texts), dtype=np.float32)
    if owners:
        np.maximum.at(res, np.array(owners), out)
    return res, len(pieces)


raw = {}
for name in SETS:
    if args.sets and name not in args.sets:
        continue
    path = args.build / f"{name}.jsonl"
    if not path.exists():
        print(f"skip {name}: {path.name} missing", flush=True)
        continue
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    if args.limit:
        rows = rows[:: max(1, len(rows) // args.limit)][: args.limit]
    texts = [r["text"] for r in rows]
    for view in args.views:
        t0 = time.time()
        s, n = score_texts([product_text(t) for t in texts] if view == "product" else texts)
        raw[f"{name}|{view}"] = s
        print(f"{name:26s} {view:8s} {len(rows):6d} texts {n:6d} windows {time.time() - t0:5.0f}s", flush=True)

np.savez(str(args.out) + ".npz", **raw)
print("saved", str(args.out) + ".npz", flush=True)
