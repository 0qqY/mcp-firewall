"""Prints the INJECTION probability of every row in a JSONL file, worst mistakes first (red-team triage)."""

import argparse
import json

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from evaluate import score


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--threshold", type=float, default=0.9)
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, dtype=torch.float32).to(device).eval()
    rows = [json.loads(l) for l in open(args.data, encoding="utf-8") if l.strip()]
    scores = score(model, tokenizer, [r["text"] for r in rows], 16, 512, device)

    # Errors first, ordered by how wrong they are.
    def wrongness(i: int) -> float:
        return (1 - scores[i]) if rows[i]["label"] == 1 else scores[i]

    for i in sorted(range(len(rows)), key=wrongness, reverse=True):
        r, s = rows[i], float(scores[i])
        verdict = "MISS" if r["label"] == 1 and s < args.threshold else "FP  " if r["label"] == 0 and s >= args.threshold else "ok  "
        print(f"{verdict} label={r['label']} score={s:.3f} [{r['source']}] {r['text'][:110]!r}")


if __name__ == "__main__":
    main()
