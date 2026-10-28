"""Scores several saved models (any architecture) on the same eval sets, side by side, like combine.py does
for soups. Rows are scored as the firewall does: 1500-character windows, max score, threshold 0.9.

  python compare.py runs/mcp-pi-v9/best runs/mcp-pi-v12-soup/best runs/mcp-pi-mmbert/best
  python compare.py ... --chunk-chars 6000   # longer windows for long-context models
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from combine import SETS, metrics
from evaluate import score


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("models", type=Path, nargs="+")
    ap.add_argument("--threshold", type=float, default=0.9)
    ap.add_argument("--chunk-chars", type=int, default=1500)
    ap.add_argument("--max-len", type=int, default=512)
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    data = {k: [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()] for k, p in SETS.items() if p.exists()}
    scores = {}
    for path in args.models:
        name = path.parent.name if path.name == "best" else path.name
        tok = AutoTokenizer.from_pretrained(path)
        model = AutoModelForSequenceClassification.from_pretrained(path, dtype=torch.float32).to(device).eval()
        scores[name] = {k: score(model, tok, [r["text"] for r in rows], 16, args.max_len, device, args.chunk_chars) for k, rows in data.items()}
        del model
        torch.cuda.empty_cache()

    for k, rows in data.items():
        y = np.array([r["label"] for r in rows])
        print(f"\n== {k}: ALL recall/fpr, then recall per attack source / fpr per benign source")
        for name, s in scores.items():
            p = s[k] >= args.threshold
            overall = f"{p[y == 1].mean():.3f}/{p[y == 0].mean():.3f}" if y.any() and not y.all() else ""
            print(f"  {name:<18} ALL {overall}", metrics(rows, s[k], args.threshold))


if __name__ == "__main__":
    main()
