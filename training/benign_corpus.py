"""Long, diverse, real benign text, with matched injected copies, to break the "long text = injection" shortcut.

Found by audit_data.py on v4's training split: texts over 200 characters were 79-86% injections and the
long benign ones came from about a hundred distinct texts, so v4 flagged 80% of independent benign prompts.

Sources (pinned revisions, streamed; only the first rows of one shard are read):
  * HuggingFaceFW/fineweb (ODC-BY @ 9bb295d), sample/10BT: English web pages, the closest stand-in for
    web-fetch and document tool results.
  * HuggingFaceFW/fineweb-2 (ODC-BY @ af9c133), tur_Latn: Turkish web pages.
  * OpenAssistant/oasst1 (Apache-2.0 @ fdf72ae): real requests people wrote to an assistant, and long
    assistant replies. Requests ("write a poem", "explain X") are benign content, not attacks.

Long documents are cut to one window of at most 1500 characters, the firewall's ml.chunkChars, so the
model sees the same text sizes it scores in production. Half of the web documents and assistant replies
get an attack from attack_pools() inserted inside the window (own line or mid-paragraph), so document
style alone does not mean "safe" either. Splits are by document index: 80% train, 10% val, 10% test.
"""

import json
import random

from datasets import load_dataset

from jailbreak_data import JACKHHAO, LAKERA
from public_data import EXT, attack_pool
from synth_mcp import PAYLOADS, families, payload
from turkish_data import attacks as tr_attacks

FINEWEB = ("HuggingFaceFW/fineweb", "9bb295ddab0e05d785b879661af7260fed5140fc", "sample/10BT/000_00000.parquet")
FINEWEB_TR = ("HuggingFaceFW/fineweb-2", "af9c13333eb981300149d5ca60a8e9d659b276b9", "data/tur_Latn/train/000_00000.parquet")
OASST = ("OpenAssistant/oasst1", "fdf72ae0827c1cda404aff25b6603abec9e3399b")
WINDOW = 1500


def _split(i: int) -> str:
    return "test" if i % 10 == 0 else "val" if i % 10 == 1 else "train"


def _window(rng: random.Random, text: str, size: int = WINDOW) -> str:
    if len(text) <= size:
        return text
    start = rng.randrange(0, len(text) - size)
    start = text.rfind(" ", 0, start) + 1  # begin on a word boundary
    return text[start : start + size]


def _insert(rng: random.Random, text: str, attack: str) -> str:
    """Puts the attack inside the host text; trims the host so the result is as long as the benign twin,
    so length carries no label signal.

    v5 only used own-line insertion at paragraph breaks and missed LLMail attacks woven into the prose of
    an email, so half the insertions now continue the surrounding sentence flow instead.
    """
    host = text[: max(150, len(text) - len(attack) - 2)]
    if rng.random() < 0.5:
        cuts = [i for i, ch in enumerate(host) if ch == "\n"] or [len(host)]
        at = rng.choice(cuts)
        return f"{host[:at].rstrip()}\n{attack}\n{host[at:].lstrip()}"
    cuts = [i + 1 for i, ch in enumerate(host) if ch in ".!?" and host[i + 1 : i + 2] == " "] or [len(host)]
    at = rng.choice(cuts)
    return f"{host[:at]} {attack} {host[at:].lstrip()}"


def attack_pools(seed: int) -> dict[str, list[str]]:
    """Attacks to embed, by split, drawn from every labelled source we already use (test stays held out):
    InjecAgent and AgentDojo goals (plain and in AgentDojo's own template), our synthetic payload families,
    BIPIA code attacks, Lakera, deepset, and short jackhhao jailbreaks."""
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack

    rng = random.Random(seed)
    pools = attack_pool()
    template = ImportantInstructionsAttack._JB_STRING
    for split in pools:
        pools[split] += [template.format(user="the user", model="the assistant", goal=g) for g in pools[split]]
        pools[split] += [payload(rng, i) for i in families(len(PAYLOADS), split) for _ in range(6)]
    for hf_split, split in (("train", "train"), ("validation", "val"), ("test", "test")):
        pools[split] += load_dataset(LAKERA[0], revision=LAKERA[1], split=hf_split)["text"]
    for name, split in (("train", "train"), ("test", "test")):
        with open(EXT / "bipia" / f"code_attack_{name}.json", encoding="utf-8") as f:
            pools[split] += [a for group in json.load(f).values() for a in group]
    # deepset's train split also feeds our val (prepare_data cuts it), so keep it out of val/test pools.
    deepset = load_dataset("deepset/prompt-injections")
    pools["train"] += [r["text"] for r in deepset["train"] if r["label"] == 1]
    pools["test"] += [r["text"] for r in deepset["test"] if r["label"] == 1]
    jb = load_dataset(JACKHHAO[0], revision=JACKHHAO[1])
    pools["train"] += [r["prompt"] for r in jb["train"] if r["type"] == "jailbreak" and len(r["prompt"]) < 600]
    pools["test"] += [r["prompt"] for r in jb["test"] if r["type"] == "jailbreak" and len(r["prompt"]) < 600]
    return pools


def _stream(name: str, rev: str, file: str, n: int, min_chars: int) -> list[str]:
    # Generic parquet builder on one pinned file: avoids the repo's per-language configs.
    ds = load_dataset("parquet", data_files=f"hf://datasets/{name}@{rev}/{file}", split="train", streaming=True)
    out = []
    for row in ds:
        if len(row["text"]) >= min_chars:
            out.append(row["text"])
            if len(out) >= n:
                break
    return out


def load_all(seed: int = 13, n_en: int = 5000, n_tr: int = 1200, n_prompts: int = 3000, n_replies: int = 1500, inject_share: float = 0.5) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    pools = attack_pools(seed)

    tr_pools = tr_attacks()
    tr_pools["test"] = pools["test"]  # the Turkish sets' test splits belong to eval_turkish.jsonl
    out = {"train": [], "val": [], "test": []}
    for source, docs in (("fineweb", _stream(*FINEWEB, n_en, 300)), ("fineweb_tr", _stream(*FINEWEB_TR, n_tr, 300))):
        for i, doc in enumerate(docs):
            # Varied window sizes so benign web text covers every length bucket, not just the chunk size.
            split, text = _split(i), _window(rng, doc, rng.randint(250, WINDOW))
            out[split].append({"text": text, "label": 0, "source": source})
            if rng.random() < inject_share:
                # Turkish pages mostly get Turkish attacks, the way a Turkish site would carry one.
                pool = tr_pools[split] if source == "fineweb_tr" and rng.random() < 0.7 else pools[split]
                out[split].append({"text": _insert(rng, text, rng.choice(pool)), "label": 1, "source": source})

    msgs = load_dataset(OASST[0], revision=OASST[1], split="train")
    prompts = list(dict.fromkeys(m["text"] for m in msgs if m["role"] == "prompter" and m["text"].strip()))
    replies = list(dict.fromkeys(m["text"] for m in msgs if m["role"] == "assistant" and len(m["text"]) >= 300))
    rng.shuffle(prompts)
    rng.shuffle(replies)
    for source, texts in (("oasst_prompt", prompts[:n_prompts]), ("oasst_reply", replies[:n_replies])):
        for i, t in enumerate(texts):
            split, text = _split(i), _window(rng, t)
            out[split].append({"text": text, "label": 0, "source": source})
            # Long assistant replies are document-like too; without injected twins they read as "always safe".
            if source == "oasst_reply" and rng.random() < inject_share:
                out[split].append({"text": _insert(rng, text, rng.choice(pools[split])), "label": 1, "source": source})
    return out


if __name__ == "__main__":
    from collections import Counter

    for split, rows in load_all().items():
        print(split, len(rows), dict(Counter((r["source"], r["label"]) for r in rows)))
