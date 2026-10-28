"""Machine-translated training rows (Turkish first, a few other languages) and a multilingual eval set.

Turkish attacks in training came from three small datasets, so the model knows few Turkish ways of saying
"ignore the system message" or "list the access keys". Here English training rows of both labels (attacks
and their benign twins) are translated with Helsinki-NLP opus-mt models, so the model sees the same
attack/benign contrast in other languages without learning "Turkish = attack" or "Turkish = safe".

  python translate.py train    # data/translated_{train,val}.jsonl from data/{train,val}.jsonl
  python translate.py eval     # data/eval_multilingual.jsonl (LLMail and test rows; evaluation only)

Run `train` on the train/val files of a prepare_data.py run without --translated, then rerun prepare_data.py
with --translated (same seed, so the splits match). Only train and val rows are translated for training.
Models (pinned):
  tr  Helsinki-NLP/opus-mt-tc-big-en-tr (CC BY 4.0)
  de  Helsinki-NLP/opus-mt-en-de (CC BY 4.0)
  es, fr, ru  Helsinki-NLP/opus-mt-en-{es,fr,ru} (Apache-2.0)
"""

import argparse
import json
import random
import re
from pathlib import Path

import torch
from transformers import AutoTokenizer, MarianMTModel

DATA = Path(__file__).parent / "data"
MODELS = {
    "tr": ("Helsinki-NLP/opus-mt-tc-big-en-tr", "e539fc1"),
    "de": ("Helsinki-NLP/opus-mt-en-de", "6183067"),
    "es": ("Helsinki-NLP/opus-mt-en-es", "5bc4493"),
    "fr": ("Helsinki-NLP/opus-mt-en-fr", "dd7f654"),
    "ru": ("Helsinki-NLP/opus-mt-en-ru", "bb09c99"),
}
# Rows per label for train (val gets a tenth). Turkish is what the benchmark measures, so it gets the most.
TRAIN_PER_LABEL = {"tr": 3000, "de": 600, "es": 600, "fr": 600, "ru": 600}
MAX_CHARS = 1200  # longer rows are mostly web carriers; MT on them is slow and drifts
SKIP_SOURCE = re.compile(r"^(tr_|fineweb_tr|trb_)|_tr\b|\+")  # already Turkish, or an augmented copy
SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


def read(path: Path) -> list[dict]:
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def write(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def ascii_share(text: str) -> float:
    return sum(c.isascii() for c in text) / max(1, len(text))


class Translator:
    def __init__(self, lang: str, device: str):
        name, rev = MODELS[lang]
        self.tok = AutoTokenizer.from_pretrained(name, revision=rev)
        self.model = MarianMTModel.from_pretrained(name, revision=rev).to(device).eval()
        self.device = device

    @torch.no_grad()
    def sentences(self, items: list[str], batch: int = 32) -> list[str]:
        order = sorted(range(len(items)), key=lambda i: len(items[i]))  # similar lengths batch well
        done: dict[int, str] = {}
        for k in range(0, len(order), batch):
            idx = order[k:k + batch]
            enc = self.tok([items[i] for i in idx], return_tensors="pt", padding=True, truncation=True, max_length=256).to(self.device)
            gen = self.model.generate(**enc, num_beams=2, max_new_tokens=256)
            for i, text in zip(idx, self.tok.batch_decode(gen, skip_special_tokens=True)):
                done[i] = text
        return [done[i] for i in range(len(items))]

    def texts(self, texts: list[str]) -> list[str | None]:
        """Translates sentence by sentence (line breaks kept); None when the result looks broken."""
        pieces, owners = [], []
        for t, text in enumerate(texts):
            for line_no, line in enumerate(text.split("\n")):
                for part in SENTENCE.split(line):
                    if part.strip():
                        pieces.append(part.strip())
                        owners.append((t, line_no))
        translated = self.sentences(pieces)
        lines: dict[tuple[int, int], list[str]] = {}
        for owner, text in zip(owners, translated):
            lines.setdefault(owner, []).append(text)
        out: list[str | None] = []
        for t, text in enumerate(texts):
            n = len(text.split("\n"))
            result = "\n".join(" ".join(lines.get((t, i), [])) for i in range(n)).strip()
            ratio = len(result) / max(1, len(text.strip()))
            repeated = re.search(r"(\b\w+\b)(?:\W+\1\b){4,}", result)
            out.append(result if 0.4 <= ratio <= 2.5 and not repeated else None)
        return out


def sample(rows: list[dict], per_label: int, rng: random.Random) -> list[dict]:
    seen, pool = set(), {0: [], 1: []}
    for r in rows:
        key = " ".join(r["text"].lower().split())
        if key in seen or SKIP_SOURCE.search(r["source"]) or len(r["text"]) > MAX_CHARS or ascii_share(r["text"]) < 0.95:
            continue
        seen.add(key)
        pool[r["label"]].append(r)
    picked = []
    for label in (0, 1):
        rng.shuffle(pool[label])
        picked += pool[label][:per_label]
    return picked


def translate_rows(rows: list[dict], lang: str, translator: Translator) -> list[dict]:
    out = []
    for r, text in zip(rows, translator.texts([r["text"] for r in rows])):
        if text:
            out.append({"text": text, "label": r["label"], "source": f"{r['source']}+mt_{lang}"})
    return out


def build_train(device: str, seed: int) -> None:
    rng = random.Random(seed)
    splits = {"train": read(DATA / "train.jsonl"), "val": read(DATA / "val.jsonl")}
    out = {"train": [], "val": []}
    for lang, per_label in TRAIN_PER_LABEL.items():
        translator = Translator(lang, device)
        for split, rows in splits.items():
            picked = sample(rows, per_label if split == "train" else per_label // 10, rng)
            out[split] += translate_rows(picked, lang, translator)
            print(f"{lang} {split}: {len(picked)} picked")
        del translator
        torch.cuda.empty_cache()
    for split, rows in out.items():
        write(DATA / f"translated_{split}.jsonl", rows)
        print(f"translated_{split}: {len(rows)} rows")


def build_eval(device: str, seed: int) -> None:
    """Per language: LLMail successful attacks (never trained on in any language), test attacks and test benign rows."""
    rng = random.Random(seed)
    test = read(DATA / "test.jsonl")
    independent = read(DATA / "eval_independent.jsonl")
    pools = {
        "llmail": [r for r in independent if r["source"] == "llmail_success"],
        "test_attack": [r for r in test if r["label"] == 1 and not SKIP_SOURCE.search(r["source"])],
        "test_benign": [r for r in test if r["label"] == 0 and not SKIP_SOURCE.search(r["source"])],
    }
    pools = {k: [r for r in v if len(r["text"]) <= 3000 and ascii_share(r["text"]) >= 0.95] for k, v in pools.items()}
    picked = {k: rng.sample(v, min(200, len(v))) for k, v in pools.items()}
    rows = [{"text": r["text"], "label": r["label"], "source": f"en_{k}"} for k, v in picked.items() for r in v]
    for lang in MODELS:
        translator = Translator(lang, device)
        for k, v in picked.items():
            for r, text in zip(v, translator.texts([r["text"] for r in v])):
                if text:
                    rows.append({"text": text, "label": r["label"], "source": f"{lang}_{k}"})
        del translator
        torch.cuda.empty_cache()
        print(f"{lang} done")
    write(DATA / "eval_multilingual.jsonl", rows)
    print(f"eval_multilingual: {len(rows)} rows")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("what", choices=["train", "eval"])
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    (build_train if args.what == "train" else build_eval)(device, args.seed)
