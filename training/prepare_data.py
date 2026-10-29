"""Builds data/{train,val,test}.jsonl from public prompt-injection data (deepset, InjecAgent, AgentDojo,
BIPIA code attacks; see public_data.py), synthetic MCP data and optional labelled JSONL files
(for example reviewed firewall audit excerpts). Run fetch_public.ps1 first.

Every row: {"text": str, "label": 0 (SAFE) | 1 (INJECTION), "source": str}
"""

import argparse
import json
import random
from collections import Counter
from pathlib import Path

from datasets import load_dataset

from benign_corpus import load_all as load_benign_corpus
from benign_prompts import load_all as load_benign_prompts
from dev_corpus import load_all as load_dev_corpus
from jailbreak_data import load_all as load_jailbreak
from obfuscate import augment as obfuscate_augment
from public_data import load_all as load_public
from task_prompts import load_all as load_task_prompts
from turkish_data import load_all as load_turkish

DATA = Path(__file__).parent / "data"


def norm(text: str) -> str:
    return " ".join(text.lower().split())


VERBATIM_SOURCES = {"deepset", "jackhhao"}  # negatives taken verbatim from a dataset, not from our templates


def dedupe(splits: dict[str, list[dict]]) -> None:
    """Drops val/train attack rows (and verbatim dataset negatives) whose text also occurs in a held-out split.

    Public sets overlap (the same Gandalf or DAN prompt shows up in several), and a test attack seen in
    training would inflate scores. Benign carriers are shared across splits on purpose (every attack has a
    benign twin in the same carrier), so they are not deduplicated; intentional repeats in train are kept.
    """
    checked = lambda r: r["label"] == 1 or r["source"] in VERBATIM_SOURCES
    test = {norm(r["text"]) for r in splits["test"] if checked(r)}
    before = len(splits["val"])
    splits["val"] = [r for r in splits["val"] if not (checked(r) and norm(r["text"]) in test)]
    held = test | {norm(r["text"]) for r in splits["val"] if checked(r)}
    train_before = len(splits["train"])
    splits["train"] = [r for r in splits["train"] if not (checked(r) and norm(r["text"]) in held)]
    print(f"dedupe: removed {before - len(splits['val'])} val and {train_before - len(splits['train'])} train rows seen in held-out splits")


def read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def deepset() -> tuple[list[dict], list[dict]]:
    """deepset/prompt-injections (Apache-2.0): short direct injections in English and German."""
    ds = load_dataset("deepset/prompt-injections")
    convert = lambda split: [{"text": r["text"], "label": int(r["label"]), "source": "deepset"} for r in ds[split]]
    return convert("train"), convert("test")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--extra-train", type=Path, nargs="*", default=[], help="labelled JSONL files added to train")
    ap.add_argument("--extra-test", type=Path, nargs="*", default=[], help="labelled JSONL files added to test")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--public-weight", type=int, default=3, help="times public training rows are repeated")
    ap.add_argument("--mcptox-weight", type=int, default=1, help="times MCPTox training rows are repeated (3 regressed probes_v2)")
    ap.add_argument("--no-jailbreak", dest="jailbreak", action="store_false", help="leave out jailbreak_data.py sources")
    ap.add_argument("--no-benign-corpus", dest="benign_corpus", action="store_false", help="leave out benign_corpus.py sources")
    ap.add_argument("--no-benign-prompts", dest="benign_prompts", action="store_false", help="leave out benign_prompts.py sources")
    ap.add_argument("--no-turkish",dest="turkish", action="store_false", help="leave out turkish_data.py sources")
    ap.add_argument("--obfuscate-share", type=float, default=0.0, help="add obfuscated copies (obfuscate.py) of this share of train/val rows, both labels")
    ap.add_argument("--translated", action="store_true", help="add data/translated_{train,val}.jsonl (translate.py)")
    ap.add_argument("--task-prompts", action="store_true", help="add task_prompts.py sources (task instructions next to personal data)")
    ap.add_argument("--dev-corpus", action="store_true", help="add dev_corpus.py sources (security-engineering text about injection)")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    if not (DATA / "synth_train.jsonl").exists():
        raise SystemExit("run synth_mcp.py first")

    public_train, public_test = deepset()
    rng.shuffle(public_train)
    cut = len(public_train) // 10
    splits = {
        "train": public_train[cut:] + read_jsonl(DATA / "synth_train.jsonl"),
        "val": public_train[:cut] + read_jsonl(DATA / "synth_val.jsonl"),
        "test": public_test + read_jsonl(DATA / "synth_test.jsonl"),
    }
    for split, rows in load_public(args.seed).items():
        # Public attacks are mostly cue-free and far fewer than synthetic rows; repeat them in train only.
        if split != "train":
            splits[split] += rows
            continue
        for row in rows:
            splits[split] += [row] * (args.mcptox_weight if row["source"] == "mcptox" else args.public_weight)
    if args.jailbreak:
        for split, rows in load_jailbreak().items():
            splits[split] += rows
    if args.benign_corpus:
        for split, rows in load_benign_corpus().items():
            splits[split] += rows
    if args.benign_prompts:
        for split, rows in load_benign_prompts().items():
            splits[split] += rows
    if args.turkish:
        for split, rows in load_turkish().items():
            splits[split] += rows * (args.public_weight - 1 if split == "train" else 1)
    if args.task_prompts:
        for split, rows in load_task_prompts().items():
            splits[split] += rows
    if args.dev_corpus:
        for split, rows in load_dev_corpus().items():
            splits[split] += rows
    for path in args.extra_train:
        splits["train"] += read_jsonl(path)
    for path in args.extra_test:
        splits["test"] += read_jsonl(path)

    dedupe(splits)
    if args.obfuscate_share > 0:
        # After dedupe, so a copy never outlives the row it was made from; test stays plain (eval_obfuscated.jsonl covers it).
        for split in ("train", "val"):
            splits[split] += obfuscate_augment(splits[split], args.obfuscate_share, seed=args.seed + len(split))
    if args.translated:
        # Made from this run's own train/val rows (same seed), so no held-out row is translated into training.
        for split in ("train", "val"):
            splits[split] += read_jsonl(DATA / f"translated_{split}.jsonl")
    for name, rows in splits.items():
        rng.shuffle(rows)
        write_jsonl(DATA / f"{name}.jsonl", rows)
        counts = Counter((r["source"], r["label"]) for r in rows)
        summary = ", ".join(f"{src}/{'INJ' if lbl else 'SAFE'}={n}" for (src, lbl), n in sorted(counts.items()))
        print(f"{name}: {len(rows)} rows ({summary})")


if __name__ == "__main__":
    main()
