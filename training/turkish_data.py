"""Turkish prompt-injection data, plus an independent Turkish benchmark for evaluation only.

Before this, Turkish appeared in training only as benign text (FineWeb-2) and as carriers for English
attacks, so the model had never seen an attack phrased in Turkish.

Training (train/validation splits only; their test splits are inside the benchmark below):
  * beratcmn/turkish-prompt-injections (Apache-2.0 @ c40c38f): Turkish translation of deepset/prompt-injections.
  * 3nesdeniz/turkish-prompt-injection-1k (CC BY 4.0 @ 1cbd115): synthetic attacks in four families and
    benign requests that mention security topics.
  * 3nesdeniz/turkish-conversation-prompt-injection (CC BY 4.0 @ 29d7593): daily requests, attacks and
    "boundary" negatives paired with each attack. Jensy1234/turkish-conversation-prompt-injection is an
    exact copy and is not used.

Evaluation only (never trained on):
  * halilneed/turkish-prompt-injection-benchmark (@ bf31d06; rows carry their own licences: CC0, CC BY 4.0,
    Apache-2.0): the test splits of the three sets above, all of fevziegeyurtsevenler/turkish-prompt-injection,
    invisible-Unicode attacks, and 2,875 benign Turkish banking, personal-data and task texts that
    measure false alarms.
"""

import random

from datasets import load_dataset

BERAT = ("beratcmn/turkish-prompt-injections", "c40c38f8ca632052fbfec19e90fab31fce33eda1")
ONE_K = ("3nesdeniz/turkish-prompt-injection-1k", "1cbd1152d9732f40148fbd5bb7cf0f58ddfe84c6")
CONV = ("3nesdeniz/turkish-conversation-prompt-injection", "29d7593984f563c4ad56876aa800b9ffd948a2fb")
BENCH = ("halilneed/turkish-prompt-injection-benchmark", "bf31d065f96a82a8d615863b8ae8da532651f7f2")


def load_all(seed: int = 17) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    out = {"train": [], "val": [], "test": []}
    berat = load_dataset(BERAT[0], revision=BERAT[1], split="train")
    for row in berat:
        split = "val" if rng.random() < 0.1 else "train"
        out[split].append({"text": row["text"], "label": int(row["label"]), "source": "tr_berat"})
    for (name, rev), source in ((ONE_K, "tr_1k"), (CONV, "tr_conv")):
        ds = load_dataset(name, revision=rev)
        for hf_split, split in (("train", "train"), ("validation", "val")):
            out[split] += [{"text": r["text"], "label": int(r["label"]), "source": source} for r in ds[hf_split]]
    return out


def attacks() -> dict[str, list[str]]:
    """Turkish attack texts by split, for embedding into Turkish web carriers."""
    return {split: [r["text"] for r in rows if r["label"] == 1] for split, rows in load_all().items()}


def benchmark() -> list[dict]:
    ds = load_dataset(BENCH[0], revision=BENCH[1], split="test")
    return [{"text": r["text"], "label": int(r["label"]), "source": f"trb_{r['subset']}"} for r in ds]


if __name__ == "__main__":
    from collections import Counter

    for split, rows in load_all().items():
        print(split, len(rows), dict(Counter((r["source"], r["label"]) for r in rows)))
    print("benchmark", dict(Counter((r["source"], r["label"]) for r in benchmark())))
