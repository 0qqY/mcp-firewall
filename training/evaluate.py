"""Evaluates any Hugging Face classifier (hub id or local dir) on data/test.jsonl, overall and per source.

Use it to compare the baseline with your own model on MCP-specific data, e.g.
  python evaluate.py --model protectai/deberta-v3-base-prompt-injection-v2
  python evaluate.py --model runs/mcp-pi/best
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from metrics import binary_metrics

POSITIVE_LABELS = {"INJECTION", "LABEL_1", "JAILBREAK", "UNSAFE", "MALICIOUS"}


def injection_index(id2label: dict) -> int:
    for idx, label in id2label.items():
        if str(label).upper() in POSITIVE_LABELS:
            return int(idx)
    return 1


def chunk_text(text: str, size: int) -> list[str]:
    """Same windows as src/ml/classifier.ts chunkText: size chars, 1/8 overlap."""
    if len(text) <= size:
        return [text]
    step = size - size // 8
    chunks, start = [], 0
    while True:
        chunks.append(text[start : start + size])
        if start + size >= len(text):
            return chunks
        start += step


@torch.no_grad()
def score(model, tokenizer, texts: list[str], batch: int, max_len: int, device: str, chunk_chars: int = 0,
          prefixes: list[str] | None = None) -> np.ndarray:
    """INJECTION probability per text. With chunk_chars, scores every window and keeps the max, like the firewall.
    prefixes (one per text, e.g. a channels.py tag + newline) go in front of every window, as the firewall does."""
    idx = injection_index(model.config.id2label)
    owners, pieces = [], []
    for i, t in enumerate(texts):
        for c in chunk_text(t, chunk_chars) if chunk_chars else [t]:
            owners.append(i)
            pieces.append(prefixes[i] + c if prefixes else c)
    out = []
    for i in range(0, len(pieces), batch):
        enc = tokenizer(pieces[i : i + batch], truncation=True, max_length=max_len, padding=True, return_tensors="pt").to(device)
        logits = model(**enc).logits.float()
        out.append(torch.softmax(logits, dim=-1)[:, idx].cpu().numpy())
    flat = np.concatenate(out)
    result = np.zeros(len(texts), dtype=flat.dtype)
    np.maximum.at(result, np.array(owners), flat)
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--revision", default=None, help="pin a hub commit for reproducible comparisons")
    ap.add_argument("--data", type=Path, default=Path(__file__).parent / "data" / "test.jsonl")
    ap.add_argument("--thresholds", type=float, nargs="+", default=[0.5, 0.9])
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--chunk-chars", type=int, default=0, help="score like the firewall: windows of N chars, max score (ml.chunkChars default 1500)")
    ap.add_argument("--json", type=Path, help="write the report as JSON")
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(args.model, revision=args.revision)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, revision=args.revision, dtype=torch.float32).to(device).eval()

    rows = [json.loads(l) for l in open(args.data, encoding="utf-8") if l.strip()]
    labels = np.array([r["label"] for r in rows])
    scores = score(model, tokenizer, [r["text"] for r in rows], args.batch, args.max_len, device, args.chunk_chars)

    groups = defaultdict(list)
    for i, r in enumerate(rows):
        groups[r["source"]].append(i)
    groups = {"ALL": list(range(len(rows))), **dict(sorted(groups.items()))}

    report = {}
    print(f"model: {args.model}  rows: {len(rows)}  device: {device}")
    for t in args.thresholds:
        print(f"\nthreshold {t}")
        print(f"{'source':<20}{'n':>6}{'prec':>8}{'recall':>8}{'f1':>8}{'fpr':>8}{'auroc':>8}")
        for name, idx in groups.items():
            m = binary_metrics(labels[idx], scores[idx], t)
            report[f"{name}@{t}"] = m
            print(f"{name:<20}{len(idx):>6}{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}{m['fpr']:>8.3f}{m['auroc']:>8.3f}")
    if args.json:
        args.json.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
