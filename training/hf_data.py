"""Training and evaluation rows from public Hugging Face datasets (permissive licences), 06.11.2026.

Downloaded with scratchpad hf_fetch.py into data/hf_new/<owner>__<name>/ (parquet exports, data files only):
  nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1 (CC BY 4.0)  injected tool output + the same record without the injection
  3nesdeniz/agentic-prompt-injection-5k, english-prompt-injection-3k (CC BY 4.0)  agentic/RAG/memory/approval injections and hard negatives
  wambosec/prompt-injections, prompt-injections-subtle (MIT)  natural benign prompts and social-engineering attacks
  dmilush/shieldlm-prompt-injection (MIT) subsets: trustailab in-the-wild jailbreaks, yanismiraoui multilingual attacks, alespalla benign chat
  neuralchemy/Prompt-injection-dataset (Apache-2.0) source "original" only
  fevziegeyurtsevenler/{turkish-prompt-injection, multilingual-prompt-injection, multilingual-jailbreak} (CC BY 4.0), mcp-tool-poisoning (Apache-2.0)

Evaluation stays separate: the sources' own test splits, two Nemotron domains (it_helpdesk, insurance) that never appear in
training, and the 25 MCP tool-poisoning pairs. Anything that matches an existing eval set (first 80 normalised characters)
is dropped. Sources that are evaluation-only in this project (xTRam1 safeguard, rogue-security, AltaySec, OnerAYTAS, halilneed,
zn, 3nesdeniz boundary pairs) are not used for training even where shieldlm repackages them.

  python hf_data.py build [--extra-eval FILE ...]   # data/hf_build/{train,val,holdout}.jsonl
  python hf_data.py translate                        # data/hf_build/{train,holdout}_tr.jsonl (Turkish machine translation)
"""

import argparse
import hashlib
import json
import random
import re
from pathlib import Path

import pandas as pd

DATA = Path(__file__).parent / "data"
RAW = DATA / "hf_new"
OUT = DATA / "hf_build"
NEMO_HOLDOUT = {"it_helpdesk", "insurance"}
FILE = {"eval": "holdout"}  # an "eval.jsonl" written here became unreadable on this machine (access denied), so the held-out split has another name


# Web-shell style code is not prompt-injection text, and Windows Defender blocks any file that holds it (Backdoor:PHP/Perhetshell),
# which made the held-out split unreadable, so such rows stay out of every split.
WEBSHELL = re.compile(r"<\?php|\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)|eval\s*\(|base64_decode\s*\(|passthru\s*\(|shell_exec\s*\(|assert\s*\(\s*\$", re.I)


def norm(text: str) -> str:
    return " ".join(text.lower().split())


def bucket(text: str, n: int = 10) -> int:
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16) % n


def parquet(name: str, cfg: str = "default") -> pd.DataFrame:
    frames = []
    for p in sorted((RAW / name / cfg).glob("*/0000.parquet")):
        frames.append(pd.read_parquet(p).assign(_split=p.parent.name))
    return pd.concat(frames, ignore_index=True)


def eval_prefixes(extra: list[Path]) -> set[str]:
    out = set()
    files = [*DATA.glob("eval_*.jsonl"), DATA / "test.jsonl", DATA / "val.jsonl", *extra]
    for p in files:
        if p.exists():
            for line in open(p, encoding="utf-8"):
                if line.strip():
                    out.add(norm(json.loads(line)["text"])[:80])
    return out


def find_field(node, needle: str):
    """Returns (dict, key) of the first string field that contains `needle`."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str) and needle in v:
                return node, k
            hit = find_field(v, needle)
            if hit:
                return hit
    elif isinstance(node, list):
        for v in node:
            hit = find_field(v, needle)
            if hit:
                return hit
    return None


def nemotron() -> tuple[list[dict], list[dict]]:
    """Tool-output pairs: the record that holds the injected field, with and without the injection."""
    d = parquet("nvidia__Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1")
    train, held = [], []
    for _, r in d.iterrows():
        env = json.loads(r["environment"]) if isinstance(r["environment"], str) else r["environment"]
        needle = r["injection"]["injection_text"]
        hit = find_field(env, needle) or find_field(env, needle.strip())
        if not hit:
            continue
        node, key = hit
        injected = json.dumps(node, ensure_ascii=False, separators=(",", ":"))
        clean_node = dict(node)
        clean_node[key] = re.sub(r"[ \t]{2,}", " ", node[key].replace(needle.strip(), " ").replace(needle, " ")).strip()
        clean = json.dumps(clean_node, ensure_ascii=False, separators=(",", ":"))
        if clean == injected:
            continue
        target = held if r["domain"] in NEMO_HOLDOUT else train
        target.append({"text": injected, "label": 1, "source": f"hf_nemo_{r['attack_category']}"})
        target.append({"text": clean, "label": 0, "source": "hf_nemo_clean"})
    return train, held


def three(name: str, tag: str) -> dict[str, list[dict]]:
    d = parquet(name)
    out = {"train": [], "val": [], "eval": []}
    for _, r in d.iterrows():
        split = {"train": "train", "validation": "val", "test": "eval"}[r["_split"]]
        out[split].append({"text": r["text"], "label": int(r["label"]), "source": f"{tag}_{'attack' if r['label'] else 'benign'}"})
    return out


def wambo(name: str, tag: str, train_cap: int, rng: random.Random) -> dict[str, list[dict]]:
    d = parquet(name)
    out = {"train": [], "val": [], "eval": []}
    for _, r in d.iterrows():
        row = {"text": r["prompt"], "label": int(r["label"]), "source": f"{tag}_{'attack' if r['label'] else 'benign'}"}
        if r["_split"] == "test":
            out["eval"].append(row)
        else:
            out["val" if bucket(r["prompt"]) == 0 else "train"].append(row)
    rng.shuffle(out["train"])
    out["train"] = out["train"][:train_cap]
    return out


def shield(rng: random.Random) -> dict[str, list[dict]]:
    d = parquet("dmilush__shieldlm-prompt-injection")
    out = {"train": [], "val": [], "eval": []}
    keep = {"trustailab/in-the-wild-jailbreak-prompts": ("hf_wild_jailbreak", 1000), "yanismiraoui/prompt-injections": ("hf_yanis_multi", 1000),
            "alespalla/chatbot-instruction-prompts": ("hf_chat_benign", 1500)}
    for src, (tag, cap) in keep.items():
        sub = d[d["source"] == src]
        rows = [{"text": r["text"], "label": int(r["label_binary"]), "source": tag, "_split": r["_split"]} for _, r in sub.iterrows() if len(r["text"]) < 6000]
        rng.shuffle(rows)
        for row in rows[:cap]:
            split = {"train": "train", "validation": "val", "test": "eval"}[row.pop("_split")]
            out[split].append(row)
    return out


PLACEHOLDERS = {"{SECRET}": ["sk-live-9f3a7c21b8d4e6", "AKIAIOSFODNN7EXAMPLE", "ghp_x8Qm2LrT0vN4aKd7", "hunter2-prod-token", "eyJhbGciOiJIUzI1NiJ9.e30"],
                "{URL}": ["attacker.example.net", "collect.evil.example", "198.51.100.23:8080", "hooks.badsite.example", "exfil.test/in"]}


def fill(text: str, rng: random.Random) -> str:
    for k, vals in PLACEHOLDERS.items():
        while k in text:
            text = text.replace(k, rng.choice(vals), 1)
    return text


def fevzi(rng: random.Random) -> dict[str, list[dict]]:
    out = {"train": [], "val": [], "eval": []}
    for name in ("turkish-prompt-injection", "multilingual-prompt-injection", "multilingual-jailbreak"):
        d = parquet(f"fevziegeyurtsevenler__{name}")
        for _, r in d.iterrows():
            text = fill(r["payload"], rng)
            b = bucket(text)
            split = "eval" if b == 0 else "val" if b == 1 else "train"
            out[split].append({"text": text, "label": 1, "source": f"hf_fevzi_{r['language']}"})
    return out


def mcp_pairs() -> list[dict]:
    d = parquet("fevziegeyurtsevenler__mcp-tool-poisoning")
    rows = []
    for _, r in d.iterrows():
        rows.append({"text": f"{r['tool_name']}\n{r['benign_description']}", "label": 0, "source": "hf_mcp25_benign"})
        rows.append({"text": f"{r['tool_name']}\n{r['poisoned_description']}", "label": 1, "source": "hf_mcp25_poisoned"})
    return rows


def neuralchemy_original() -> dict[str, list[dict]]:
    d = parquet("neuralchemy__Prompt-injection-dataset", "full")
    d = d[d["source"] == "original"]
    out = {"train": [], "val": [], "eval": []}
    for _, r in d.iterrows():
        split = {"train": "train", "validation": "val", "test": "eval"}[r["_split"]]
        out[split].append({"text": r["text"], "label": int(r["label"]), "source": "hf_nc_original"})
    return out


def build(extra: list[Path], seed: int) -> None:
    rng = random.Random(seed)
    seen_eval = eval_prefixes(extra)
    parts = []
    nemo_train, nemo_held = nemotron()
    parts.append({"train": nemo_train, "val": [], "eval": nemo_held})
    parts.append(three("3nesdeniz__agentic-prompt-injection-5k", "hf_agentic5k"))
    parts.append(three("3nesdeniz__english-prompt-injection-3k", "hf_eng3k"))
    parts.append(wambo("wambosec__prompt-injections", "hf_wambo", 3000, rng))
    parts.append(wambo("wambosec__prompt-injections-subtle", "hf_wambo_subtle", 700, rng))
    parts.append(shield(rng))
    parts.append(fevzi(rng))
    parts.append(neuralchemy_original())
    parts.append({"train": [], "val": [], "eval": mcp_pairs()})
    merged = {"train": [], "val": [], "eval": []}
    taken: set[str] = set()
    dropped = 0
    shells: dict[str, int] = {}
    # eval rows first, so a text that is in both an eval split and a train split stays out of training
    for split in ("eval", "val", "train"):
        for part in parts:
            for row in part[split]:
                key = norm(row["text"])
                if WEBSHELL.search(row["text"]):
                    shells[row["source"]] = shells.get(row["source"], 0) + 1
                    continue
                if key in taken or (split != "eval" and key[:80] in seen_eval):
                    dropped += 1
                    continue
                taken.add(key)
                merged[split].append(row)
    OUT.mkdir(exist_ok=True)
    for split, rows in merged.items():
        rng.shuffle(rows)
        with open(OUT / f"{FILE.get(split, split)}.jsonl", "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    from collections import Counter

    for split, rows in merged.items():
        c = Counter((r["source"], r["label"]) for r in rows)
        print(split, len(rows), "labels", dict(Counter(r["label"] for r in rows)))
        for (s, l), n in sorted(c.items()):
            print(f"   {s} label={l}: {n}")
    print("dropped (duplicate or in an existing eval set):", dropped)
    print("dropped as web-shell code:", shells)


def translate() -> None:
    import sys

    import torch

    sys.path.insert(0, str(Path(__file__).parent))
    from translate import Translator, translate_rows

    translator = Translator("tr", "cuda")
    for src, dst, sources in (("train", "train_tr", ("hf_agentic5k", "hf_eng3k")), ("holdout", "holdout_tr", ("hf_agentic5k", "hf_eng3k"))):
        rows = [json.loads(l) for l in open(OUT / f"{src}.jsonl", encoding="utf-8") if l.strip()]
        picked = [r for r in rows if r["source"].startswith(sources) and len(r["text"]) <= 900 and sum(c.isascii() for c in r["text"]) / len(r["text"]) > 0.95]
        done = translate_rows(picked, "tr", translator)
        with open(OUT / f"{dst}.jsonl", "w", encoding="utf-8") as f:
            for r in done:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"{dst}: {len(done)} of {len(picked)} translated")
    del translator
    torch.cuda.empty_cache()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["build", "translate"])
    ap.add_argument("--extra-eval", type=Path, nargs="*", default=[])
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    build(a.extra_eval, a.seed) if a.what == "build" else translate()
