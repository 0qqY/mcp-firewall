"""ProtectAI deberta-v3-base-prompt-injection-v2 (the baseline in models/protectai-deberta-v3-pi-v2) on CPU through
onnxruntime, scored the way the benchmark scores it: the raw text, truncated to 512 tokens, P(INJECTION) from a softmax.

Only reads files. usage:
  python -I score_onnx_protectai.py --model-dir <dir> --pairs <bipia_pairs.jsonl> --out <prefix> [--test-attacks-only]
Rows kept with --test-attacks-only: benign rows and injected rows whose attack comes from BIPIA's test split
(the benchmark's main BIPIA analysis); the saved arrays are indexed by position in the full file.
"""

import argparse
import json
import os
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

ap = argparse.ArgumentParser()
ap.add_argument("--model-dir", type=Path, required=True)
ap.add_argument("--pairs", type=Path, required=True)
ap.add_argument("--out", type=Path, required=True)
ap.add_argument("--test-attacks-only", action="store_true")
ap.add_argument("--limit", type=int, default=0)
ap.add_argument("--batch", type=int, default=8)
ap.add_argument("--threads", type=int, default=0, help="onnxruntime intra-op threads (0 = all cores)")
args = ap.parse_args()

rows = [json.loads(line) for line in open(args.pairs, encoding="utf-8") if line.strip()]
idx = [i for i, r in enumerate(rows) if not args.test_attacks_only or r["label"] == 0 or r.get("attack_split") == "test"]
if args.limit:
    idx = idx[:: max(1, len(idx) // args.limit)][: args.limit]

tok = AutoTokenizer.from_pretrained(args.model_dir)
opts = ort.SessionOptions()
opts.intra_op_num_threads = args.threads or os.cpu_count() or 4
sess = ort.InferenceSession(str(args.model_dir / "onnx" / "model.onnx"), opts, providers=["CPUExecutionProvider"])
names = {i.name for i in sess.get_inputs()}
cfg = json.loads((args.model_dir / "config.json").read_text(encoding="utf-8"))
inj = [int(k) for k, v in cfg["id2label"].items() if "inj" in v.lower()][0]
print(f"{len(idx)} rows, {opts.intra_op_num_threads} threads, injection index {inj}, inputs {sorted(names)}", flush=True)

order = sorted(idx, key=lambda i: len(rows[i]["text"]))
probs = np.full(len(rows), np.nan, dtype=np.float32)
t0 = time.time()
for s in range(0, len(order), args.batch):
    part = order[s : s + args.batch]
    enc = tok([rows[i]["text"] for i in part], truncation=True, max_length=512, padding=True, return_tensors="np")
    feed = {k: enc[k].astype(np.int64) for k in ("input_ids", "attention_mask") if k in names}
    logits = sess.run(None, feed)[0].astype(np.float64)
    e = np.exp(logits - logits.max(axis=-1, keepdims=True))
    probs[part] = (e / e.sum(axis=-1, keepdims=True))[:, inj]
    if (s // args.batch) % 40 == 0:
        print(f"  {s + len(part)}/{len(order)}  {time.time() - t0:.0f}s", flush=True)

np.savez(str(args.out) + ".npz", probs=probs, idx=np.array(idx))
print("saved", str(args.out) + ".npz", f"{time.time() - t0:.0f}s", flush=True)
