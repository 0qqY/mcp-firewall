"""Benign prompts written *to* an AI (role assignments, system prompts, formatting rules), with matched
injected copies.

v9 flagged 61% of TrustAIRLab "regular" prompts. fp_report.py showed the flagged ones are mostly
"Act as a ...", "You are ...", "You must always ..." prompts: our training data had almost no benign text
that addresses the model, so "talks to the AI" had become a sign of injection. (About 18% of those
"regular" prompts contain jailbreak or override wording themselves; flagging those is not a mistake.)

Sources:
  * fka/awesome-chatgpt-prompts (CC0 @ 5917251): "I want you to act as ..." role prompts.
  * danielrosehill/System-Prompt-Library (CC BY 4.0 @ cf54baa): ~900 assistant system prompts (Markdown).
  * Naomibas/llm-system-prompts-benchmark (Apache-2.0 @ 840bd1b): 100 short behaviour rules.

Rows with jailbreak/override wording are dropped (they are not benign), and so is any prompt whose start
matches a row of eval_independent.jsonl or eval_turkish.jsonl, so the evaluation stays unseen.
Half the prompts also get an attack from benign_corpus.attack_pools() inserted, so "addresses the AI"
alone does not mean safe either. Splits by index: 80% train, 10% val, 10% test.
"""

import json
import random
import re
from pathlib import Path

from datasets import load_dataset

from benign_corpus import WINDOW, _insert, _split, _window, attack_pools
from public_data import EXT

AWESOME = ("fka/awesome-chatgpt-prompts", "59172513d81cf10e9ce5c7547bbebd004dbd8db0")
LIBRARY = ("danielrosehill/System-Prompt-Library", "cf54baa36abcbfa5e92e7b3fb5ee4ff6c97aca1d")
RULES = ("Naomibas/llm-system-prompts-benchmark", "840bd1b108151290783860eeff588bf03d85234b")
DATA = Path(__file__).parent / "data"

JAILBREAK = re.compile(
    r"ignore (all )?(the )?(previous|prior|above) (instructions|prompts?)|do anything now|\bDAN\b|developer mode|jailbr(oken|eak)"
    r"|no (restrictions|limits|filters|censorship)|exception to (the )?AI|ethical (protocols|guidelines)|unfiltered|uncensored|amoral"
    r"|without (any )?(moral|ethic)|never refuses?|not bound by|openai('s)? (content )?polic|nsfw|lewd|explicit",
    re.I,
)


def _norm(text: str) -> str:
    return " ".join(text.lower().split())


def _eval_prefixes() -> set[str]:
    out = set()
    for name in ("eval_independent.jsonl", "eval_turkish.jsonl"):
        path = DATA / name
        if path.exists():
            out |= {_norm(json.loads(l)["text"])[:80] for l in open(path, encoding="utf-8") if l.strip()}
    return out


def _library() -> list[str]:
    """Reads the Markdown prompts one by one (some file names contain '?', which Windows cannot cache)."""
    cache = EXT / "system_prompt_library.jsonl"
    if not cache.exists():
        from huggingface_hub import HfFileSystem

        fs = HfFileSystem()
        root = f"datasets/{LIBRARY[0]}@{LIBRARY[1]}/system-prompts/md"
        texts = []
        for path in sorted(fs.ls(root, detail=False)):
            with fs.open(path, "r", encoding="utf-8") as f:
                texts.append(f.read())
        cache.parent.mkdir(parents=True, exist_ok=True)
        with open(cache, "w", encoding="utf-8") as f:
            for t in texts:
                f.write(json.dumps({"text": t}, ensure_ascii=False) + "\n")
    return [json.loads(l)["text"] for l in open(cache, encoding="utf-8") if l.strip()]


def load_all(seed: int = 19, inject_share: float = 0.5) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    pools = attack_pools(seed)
    seen_eval = _eval_prefixes()
    sources = {
        "sp_awesome": list(load_dataset(AWESOME[0], revision=AWESOME[1], split="train")["prompt"]),
        "sp_library": _library(),
        "sp_rules": list(load_dataset(RULES[0], revision=RULES[1], split="train")["prompt"]),
    }
    out = {"train": [], "val": [], "test": []}
    for source, texts in sources.items():
        texts = [t for t in dict.fromkeys(texts) if t and t.strip() and not JAILBREAK.search(t) and _norm(t)[:80] not in seen_eval]
        for i, t in enumerate(texts):
            split, text = _split(i), _window(rng, t, WINDOW)
            out[split].append({"text": text, "label": 0, "source": source})
            if rng.random() < inject_share:
                out[split].append({"text": _insert(rng, text, rng.choice(pools[split])), "label": 1, "source": source})
    return out


if __name__ == "__main__":
    from collections import Counter

    for split, rows in load_all().items():
        print(split, len(rows), dict(Counter((r["source"], r["label"]) for r in rows)))
