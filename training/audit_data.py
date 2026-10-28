"""Shortcut audit of a training split: does length, imperative tone or text diversity alone predict the label?

A healthy set has benign rows across every length and style, and many distinct benign texts. If long
texts are mostly injections, or long benign texts come from a handful of templates, the model can learn
"long / unfamiliar = injection" instead of the actual intent.
"""

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

IMPERATIVE = re.compile(r"^\s*(please\s+)?(write|create|act|generate|give|make|list|tell|explain|translate|summari[sz]e|you are|you will|i want you)\b", re.I | re.M)


def bucket(n: int) -> str:
    return "<200" if n < 200 else "200-600" if n < 600 else "600-1500" if n < 1500 else ">=1500"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(__file__).parent / "data" / "train.jsonl")
    args = ap.parse_args()
    rows = [json.loads(l) for l in open(args.data, encoding="utf-8") if l.strip()]

    print(f"{args.data.name}: {len(rows)} rows")
    print("\nlength bucket      n   %INJ   distinct benign texts")
    groups = defaultdict(list)
    for r in rows:
        groups[bucket(len(r["text"]))].append(r)
    for b in ("<200", "200-600", "600-1500", ">=1500"):
        g = groups[b]
        inj = sum(r["label"] for r in g)
        distinct = len({r["text"] for r in g if r["label"] == 0})
        print(f"{b:<14}{len(g):>6}{inj / max(1, len(g)):>7.0%}{distinct:>10}")

    imp = [r for r in rows if IMPERATIVE.search(r["text"])]
    print(f"\nimperative/LLM-directed opening: {len(imp)} rows, {sum(r['label'] for r in imp) / max(1, len(imp)):.0%} INJ, "
          f"{len({r['text'] for r in imp if r['label'] == 0})} distinct benign")

    print("\nbenign rows >= 600 chars by source (distinct / total):")
    long_benign = Counter()
    long_distinct = defaultdict(set)
    for r in rows:
        if r["label"] == 0 and len(r["text"]) >= 600:
            long_benign[r["source"]] += 1
            long_distinct[r["source"]].add(r["text"])
    for s, n in long_benign.most_common():
        print(f"  {s:<22}{len(long_distinct[s]):>6} / {n}")
    print("\ninjection rows >= 600 chars by source:")
    print(" ", dict(Counter(r["source"] for r in rows if r["label"] == 1 and len(r["text"]) >= 600).most_common()))


if __name__ == "__main__":
    main()
