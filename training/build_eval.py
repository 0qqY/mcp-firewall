"""Builds data/eval_independent.jsonl: an evaluation set from sources never used for training.

  * Microsoft LLMail-Inject (MIT, microsoft/llmail-inject-challenge @ 1063bdf): emails written by
    hundreds of competitors to make an email agent call send_email, phase 2 (defences: Prompt Shield v2,
    TaskTracker, LLM judge).
      llmail_success   submissions that actually triggered the API (attack worked end to end)
      llmail_attack    other submissions the organisers' judge labelled as attack attempts
      llmail_fp        the 203 benign emails the organisers published for false-positive tests
    Submissions judged "Unclear" or "False" are left out: they are not reliable labels either way.
  * TrustAIRLab in-the-wild jailbreak prompts (MIT @ a10aab8), 2023-12-25 snapshot:
      itw_jailbreak    jailbreak prompts collected from Discord, Reddit, websites
      itw_regular      regular prompts from the same platforms
    jackhhao (used in training) derives from this collection, so rows seen in training are removed.

Every row whose normalised text occurs in data/train.jsonl or data/val.jsonl is dropped.

Also writes data/eval_turkish.jsonl from the Turkish benchmark described in turkish_data.py.
"""

import argparse
import json
import random
from collections import Counter
from pathlib import Path

from datasets import load_dataset

DATA = Path(__file__).parent / "data"
LLMAIL = DATA / "external" / "eval" / "llmail"
ITW = ("TrustAIRLab/in-the-wild-jailbreak-prompts", "a10aab8")


def norm(text: str) -> str:
    return " ".join(text.lower().split())


def build_turkish(seen: set[str]) -> None:
    """data/eval_turkish.jsonl from the Turkish benchmark (turkish_data.py), minus rows seen in training."""
    from turkish_data import benchmark

    rows = benchmark()
    kept = [r for r in rows if norm(r["text"]) not in seen]
    with open(DATA / "eval_turkish.jsonl", "w", encoding="utf-8") as f:
        for r in kept:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"eval_turkish.jsonl: {len(kept)} rows ({len(rows) - len(kept)} seen in training dropped)",
          dict(Counter((r["source"], r["label"]) for r in kept)))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--turkish-only", action="store_true", help="only (re)build eval_turkish.jsonl; keeps eval_independent.jsonl as is")
    args = ap.parse_args()
    rng = random.Random(2026)
    seen = set()
    for name in ("train.jsonl", "val.jsonl"):
        with open(DATA / name, encoding="utf-8") as f:
            seen |= {norm(json.loads(line)["text"]) for line in f if line.strip()}
    build_turkish(seen)
    if args.turkish_only:
        return

    subs = json.load(open(LLMAIL / "labelled_unique_submissions_phase2.json", encoding="utf-8"))
    success = [t for t, v in subs.items() if v["reason"] == "api_triggered"]
    attack = [t for t, v in subs.items() if str(v["attack_attempt"]) == "True" and v["reason"] != "api_triggered"]
    fp = json.load(open(LLMAIL / "emails_for_fp_tests.json", encoding="utf-8"))

    itw_jb = load_dataset(ITW[0], "jailbreak_2023_12_25", revision=ITW[1])["train"]["prompt"]
    itw_reg = load_dataset(ITW[0], "regular_2023_12_25", revision=ITW[1])["train"]["prompt"]

    rows = []
    for source, texts, label, n in (
        ("llmail_success", success, 1, 600),
        ("llmail_attack", attack, 1, 600),
        ("llmail_fp", fp, 0, None),
        ("itw_jailbreak", list(itw_jb), 1, None),
        ("itw_regular", list(itw_reg), 0, 1400),
    ):
        fresh = list(dict.fromkeys(t for t in texts if t and t.strip() and norm(t) not in seen))
        picked = rng.sample(fresh, n) if n and len(fresh) > n else fresh
        rows += [{"text": t, "label": label, "source": source} for t in picked]
        print(f"{source}: {len(texts)} available, {len(texts) - len(fresh)} dropped (seen/duplicate/empty), {len(picked)} used")

    with open(DATA / "eval_independent.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("eval_independent.jsonl:", len(rows), dict(Counter((r["source"], r["label"]) for r in rows)))


if __name__ == "__main__":
    main()
