"""Combines two fine-tuned checkpoints: weight averaging ("model soup") and score ensembles.

Both checkpoints start from the same base model, so their weights can be interpolated into one model
with no extra inference cost. Score ensembles (mean / min of the two probabilities) need two models at
runtime and are reported for comparison.

To avoid tuning on the numbers we report, the independent eval set is split by row index: even rows
pick the combination, odd rows report it.

  python combine.py --a runs/mcp-pi-v4/best --b runs/mcp-pi-v6/best --alphas 0.3 0.5 0.7
  python combine.py --a ... --b ... --save-alpha 0.5 --out runs/mcp-pi-v7/best
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from evaluate import score

HERE = Path(__file__).parent
SETS = {"independent": HERE / "data" / "eval_independent.jsonl", "turkish": HERE / "data" / "eval_turkish.jsonl",
        "test": HERE / "data" / "test.jsonl", "probes_v2": HERE / "probes_v2.jsonl",
        "obfuscated": HERE / "data" / "eval_obfuscated.jsonl", "multilingual": HERE / "data" / "eval_multilingual.jsonl"}


def load(path: Path) -> torch.nn.Module:
    return AutoModelForSequenceClassification.from_pretrained(path, dtype=torch.float32)


def soup(a: torch.nn.Module, b: torch.nn.Module, alpha: float) -> torch.nn.Module:
    """(1 - alpha) * a + alpha * b, parameter by parameter (buffers such as position ids are copied)."""
    sb = b.state_dict()
    mixed = {k: (1 - alpha) * v + alpha * sb[k] if v.is_floating_point() else v for k, v in a.state_dict().items()}
    out = load_like(a)
    out.load_state_dict(mixed)
    return out


def load_like(model: torch.nn.Module) -> torch.nn.Module:
    return AutoModelForSequenceClassification.from_config(model.config).to(torch.float32)


def metrics(rows: list[dict], s: np.ndarray, thr: float) -> dict[str, str]:
    out = {}
    for src in sorted({r["source"] for r in rows}):
        idx = [i for i, r in enumerate(rows) if r["source"] == src]
        y = np.array([rows[i]["label"] for i in idx])
        p = s[idx] >= thr
        out[src] = f"{(p[y == 1]).mean():.3f}" if y.all() else f"fpr {(p[y == 0]).mean():.3f}" if not y.any() else f"{(p[y == 1]).mean():.3f}/{(p[y == 0]).mean():.3f}"
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--a", type=Path, required=True)
    ap.add_argument("--b", type=Path, required=True)
    ap.add_argument("--alphas", type=float, nargs="*", default=[0.3, 0.5, 0.7])
    ap.add_argument("--threshold", type=float, default=0.9)
    ap.add_argument("--save-alpha", type=float, help="write the soup with this alpha to --out and exit")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.a)
    a, b = load(args.a), load(args.b)
    if args.save_alpha is not None:
        m = soup(a, b, args.save_alpha)
        m.save_pretrained(args.out)
        tok.save_pretrained(args.out)
        print(f"saved soup alpha={args.save_alpha} to {args.out}")
        return

    device = "cuda" if torch.cuda.is_available() else "cpu"
    data = {k: [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()] for k, p in SETS.items()}
    models = {"A": a, "B": b} | {f"soup{al}": soup(a, b, al) for al in args.alphas}
    scores = {}
    for name, m in models.items():
        m.to(device).eval()
        scores[name] = {k: score(m, tok, [r["text"] for r in rows], 16, 512, device, 1500) for k, rows in data.items()}
        m.to("cpu")
        torch.cuda.empty_cache()
    scores["mean(A,B)"] = {k: (scores["A"][k] + scores["B"][k]) / 2 for k in data}
    scores["min(A,B)"] = {k: np.minimum(scores["A"][k], scores["B"][k]) for k in data}

    ind = data["independent"]
    halves = {"tune (even)": slice(0, None, 2), "report (odd)": slice(1, None, 2)}
    for half, sl in halves.items():
        rows = ind[sl]
        print(f"\n== independent, {half}: recall per attack source / fpr per benign source")
        for name, s in scores.items():
            print(f"  {name:<10}", metrics(rows, s["independent"][sl], args.threshold))
    print("\n== turkish benchmark")
    for name, s in scores.items():
        y = np.array([r["label"] for r in data["turkish"]])
        p = s["turkish"] >= args.threshold
        print(f"  {name:<10} ALL {p[y == 1].mean():.3f}/{p[y == 0].mean():.3f}", metrics(data["turkish"], s["turkish"], args.threshold))
    for k in ("test", "probes_v2"):
        print(f"\n== {k} ALL recall/fpr and per-source")
        for name, s in scores.items():
            y = np.array([r["label"] for r in data[k]])
            p = s[k] >= args.threshold
            print(f"  {name:<10} ALL {p[y == 1].mean():.3f}/{p[y == 0].mean():.3f}", {src: v for src, v in metrics(data[k], s[k], args.threshold).items() if src.startswith(("probe2", "oasst", "fineweb", "mcptox", "deepset"))})
    print("\n== obfuscated: recall on attacks / fpr on benign, per transform")
    for name, s in scores.items():
        print(f"  {name:<10}", metrics(data["obfuscated"], s["obfuscated"], args.threshold))
    print("\n== multilingual (machine-translated): recall on attacks / fpr on benign, per language and pool")
    for name, s in scores.items():
        print(f"  {name:<10}", metrics(data["multilingual"], s["multilingual"], args.threshold))


if __name__ == "__main__":
    main()
