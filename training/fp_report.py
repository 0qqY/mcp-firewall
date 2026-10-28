"""False-positive triage: scores the benign rows of a source and groups them by simple, explainable traits.

Traits are heuristics for reading the errors, not labels: they show which kinds of benign text the model
over-flags (e.g. persona/role-play prompts vs plain questions vs long system prompts).
"""

import argparse
import json
import random
import re
from collections import defaultdict

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from evaluate import score

TRAITS = {
    "persona": re.compile(r"\b(you are|act as|pretend|roleplay|role-play|imagine you|from now on|you will be)\b", re.I),
    "rules": re.compile(r"\b(you must|always|never|do not|don't|rules?:|instructions?:)\b", re.I),
    "addresses_ai": re.compile(r"\b(chatgpt|gpt|ai|assistant|language model|llm|bot)\b", re.I),
    "question": re.compile(r"^[^.\n]{0,200}\?\s*$"),
}


def traits(text: str) -> list[str]:
    found = [name for name, rx in TRAITS.items() if rx.search(text)]
    found.append("long" if len(text) > 1500 else "short" if len(text) < 200 else "medium")
    return found


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--threshold", type=float, default=0.9)
    ap.add_argument("--samples", type=int, default=12)
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, dtype=torch.float32).to(device).eval()
    rows = [json.loads(l) for l in open(args.data, encoding="utf-8") if l.strip()]
    rows = [r for r in rows if r["source"] == args.source and r["label"] == 0]
    s = score(model, tok, [r["text"] for r in rows], 16, 512, device, 1500)
    flagged = s >= args.threshold

    by_trait = defaultdict(lambda: [0, 0])
    for r, f in zip(rows, flagged):
        for t in traits(r["text"]):
            by_trait[t][0] += 1
            by_trait[t][1] += int(f)
    print(f"{args.source}: {len(rows)} benign rows, {flagged.sum()} flagged ({flagged.mean():.1%})")
    print(f"{'trait':<14}{'n':>6}{'flagged':>9}{'rate':>8}")
    for t, (n, k) in sorted(by_trait.items(), key=lambda kv: -kv[1][0]):
        print(f"{t:<14}{n:>6}{k:>9}{k / n:>8.1%}")
    none = [i for i, r in enumerate(rows) if not set(traits(r["text"])) & {"persona", "rules", "addresses_ai"}]
    print(f"no persona/rules/AI words: {len(none)} rows, {flagged[none].mean() if none else 0:.1%} flagged")

    rng = random.Random(0)
    fp_idx = [i for i in range(len(rows)) if flagged[i]]
    print("\nsample flagged (truncated):")
    for i in rng.sample(fp_idx, min(args.samples, len(fp_idx))):
        print(f"  {s[i]:.3f} {traits(rows[i]['text'])} {rows[i]['text'][:150]!r}")
    print("\nsample passed (truncated):")
    ok_idx = [i for i in range(len(rows)) if not flagged[i]]
    for i in rng.sample(ok_idx, min(6, len(ok_idx))):
        print(f"  {s[i]:.3f} {traits(rows[i]['text'])} {rows[i]['text'][:150]!r}")
    print("\nscore histogram:", np.histogram(s, bins=[0, .1, .5, .9, .99, 1.0001])[0].tolist())


if __name__ == "__main__":
    main()
