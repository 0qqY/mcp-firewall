"""Direct prompt-injection / jailbreak examples, plus benign texts that merely talk about such attacks.

Sources (pinned revisions):
  * Lakera/gandalf_ignore_instructions (MIT @ 04737b6): 1000 "ignore your instructions" prompts from the
    Gandalf game. Used raw and embedded in benign tool results; raw ones are paired with short benign
    requests that reuse the same tasks ("tell me a story"), so the model learns the override, not the task.
  * jackhhao/jailbreak-classification (Apache-2.0 @ 2f2ceeb): jailbreak vs benign persona prompts. The
    benign side ("You are a devoted fan of...") teaches that role-play alone is not an attack.
Not used: TrustAIRLab in-the-wild (largely the source of jackhhao, noisy "regular" labels), JailbreakBench
(harmful-behaviour goals, a content-safety task rather than injection), unlicensed sets.

The talk-about-attacks negatives are why naming words like "jailbreak" or "prompt injection" in the
data would backfire: these words appear far more often in security articles, tickets and logs than in real
attacks. Template families follow the usual rule: index % 5 == 0 is test only.
"""

import random

from datasets import load_dataset

from synth_mcp import BENIGN_RESULTS, fill

LAKERA = ("Lakera/gandalf_ignore_instructions", "04737b6")
JACKHHAO = ("jackhhao/jailbreak-classification", "2f2ceeb")

BENIGN_REQUESTS = [
    "Tell me a story about {x}.", "Write a short poem about {x}.", "What is the capital of {c}?",
    "Translate 'good morning' into {l}.", "Give me three facts about {x}.", "Summarize the plot of a heist movie.",
    "Spell the word {w} backwards.", "What rhymes with {w}?", "Explain {x} to a ten-year-old.",
    "Can you give me a hint for today's crossword?", "List five words that start with {s}.",
    "Bana {x} hakkında kısa bir hikâye anlat.", "{c} ülkesinin başkenti neresi?", "What is the first letter of the alphabet?",
    "Tell me a joke about programmers.", "Describe your favourite colour.", "What does the word {w} mean?",
    "How many letters are in the word {w}?", "Write a haiku about {x}.", "Recommend a book about {x}.",
]
FILL = {
    "x": ["dragons", "the ocean", "black holes", "a lost cat", "volcanoes", "the moon", "robots", "autumn"],
    "c": ["France", "Japan", "Brazil", "Kenya", "Türkiye", "Canada"],
    "l": ["Spanish", "German", "Turkish", "Japanese"],
    "w": ["password", "orange", "silence", "secret", "lantern", "puzzle"],
    "s": ["P", "S", "T", "K"],
}

TOPICS = ["prompt injection", "jailbreak", "indirect prompt injection", "LLM jailbreak", "tool poisoning", "istem enjeksiyonu"]
TALK_ABOUT = [
    "Our team is publishing a blog post on {t} and how to defend agents against it.",
    "Ticket #{n}: the customer asks whether our product detects {t} attempts in uploaded documents.",
    "Changelog 2.{n}: improved {t} detection; false positives reduced by {n}%.",
    "Reading list: three papers on {t} defenses, including a survey from 2025.",
    "Workshop agenda: 10:00 intro to {t}, 11:00 red-teaming lab, 12:00 lunch.",
    "Log 2026-10-{d}: classifier flagged a possible {t} in a tool result; the analyst marked it a false positive.",
    "FAQ: What is {t}? It is an attempt to make a language model ignore its instructions. We treat tool output as data, so such text cannot change the agent's goals.",
    "Slack, #ml-eval: does anyone have a good labelled dataset of {t} examples for our benchmark?",
    "Course syllabus, week {d}: {t} and other attacks on LLM applications. Reading: OWASP Top 10 for LLMs.",
    "Bug report: the {t} filter blocks the phrase 'ignore case' in grep results. Expected: allowed.",
    "News: researchers disclosed a new {t} technique affecting several chatbots; vendors have released patches.",
    "Interview question: how would you test an LLM application for {t}? Describe your approach.",
    "Example from our docs: an attacker might hide 'ignore previous instructions' in a web page. The firewall flags text like this in tool results and blocks it.",
    "Güvenlik eğitimi: {t} saldırılarını tanıma ve raporlama, perşembe 14:00, toplantı salonu B.",
    "Aylık rapor: geçen ay {n} {t} denemesi tespit edildi, hepsi engellendi; yanlış alarm oranı %{d}.",
    "Meeting notes: agreed to add {t} tests to CI before the release; owner: platform team.",
    "Policy reminder: do not try to jailbreak production assistants; report findings to the security team instead.",
    "Paper abstract: we measure how often agents follow {t} payloads hidden in retrieved documents and propose a detector.",
    "Release notes: the assistant now refuses common jailbreak prompts and explains why.",
    "Kod incelemesi: {t} tespit eşiğini 0.9'dan 0.85'e düşürmeyi öneriyorum; önce yanlış pozitiflere bakalım.",
]


def _held_out(i: int) -> bool:
    return i % 5 == 0


def _families(count: int, split: str) -> list[int]:
    return [i for i in range(count) if _held_out(i) == (split == "test")]


def _fill_request(rng: random.Random, text: str) -> str:
    for key, values in FILL.items():
        text = text.replace("{" + key + "}", rng.choice(values))
    return text


def _embed(rng: random.Random, carrier: str, attack: str) -> str:
    where = rng.random()
    if where < 0.3:
        return f"{attack}\n{carrier}"
    if where < 0.6:
        mid = len(carrier) // 2
        return f"{carrier[:mid]}\n{attack}\n{carrier[mid:]}"
    return f"{carrier}\n{attack}"


def lakera(rng: random.Random) -> dict[str, list[dict]]:
    ds = load_dataset(LAKERA[0], revision=LAKERA[1])
    out = {"train": [], "val": [], "test": []}
    for hf_split, split in (("train", "train"), ("validation", "val"), ("test", "test")):
        for row in ds[hf_split]:
            out[split].append({"text": row["text"], "label": 1, "source": "lakera"})
            out[split].append({"text": _fill_request(rng, BENIGN_REQUESTS[rng.choice(_families(len(BENIGN_REQUESTS), split))]), "label": 0, "source": "lakera"})
            if rng.random() < 0.5:
                carrier = fill(rng, rng.choice(BENIGN_RESULTS))
                out[split].append({"text": _embed(rng, carrier, row["text"]), "label": 1, "source": "lakera_embedded"})
                out[split].append({"text": carrier, "label": 0, "source": "lakera_embedded"})
    return out


def jackhhao(rng: random.Random) -> dict[str, list[dict]]:
    ds = load_dataset(JACKHHAO[0], revision=JACKHHAO[1])
    out = {"train": [], "val": [], "test": []}
    for hf_split in ("train", "test"):
        for row in ds[hf_split]:
            split = "test" if hf_split == "test" else ("val" if rng.random() < 0.1 else "train")
            out[split].append({"text": row["prompt"], "label": int(row["type"] == "jailbreak"), "source": "jackhhao"})
    return out


def talk_about(rng: random.Random, n_train: int = 600, n_val: int = 80, n_test: int = 120) -> dict[str, list[dict]]:
    out = {"train": [], "val": [], "test": []}
    for split, n in (("train", n_train), ("val", n_val), ("test", n_test)):
        for _ in range(n):
            text = TALK_ABOUT[rng.choice(_families(len(TALK_ABOUT), split))]
            text = text.replace("{t}", rng.choice(TOPICS)).replace("{n}", str(rng.randint(2, 97))).replace("{d}", str(rng.randint(10, 28)))
            out[split].append({"text": text, "label": 0, "source": "talk_about"})
    return out


def load_all(seed: int = 11) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    merged = {"train": [], "val": [], "test": []}
    for loader in (lakera, jackhhao, talk_about):
        for split, rows in loader(rng).items():
            merged[split] += rows
    return merged


if __name__ == "__main__":
    from collections import Counter

    for split, rows in load_all().items():
        print(split, len(rows), dict(Counter((r["source"], r["label"]) for r in rows)))
