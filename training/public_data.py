"""Indirect prompt-injection examples built from public, permissively licensed research datasets.

Sources (attack instructions only; carriers are ours or from the same MIT sources):
  * InjecAgent (MIT, uiuc-kang-lab/InjecAgent @ f19c9f2): 17 tool-response templates with an
    "<Attacker Instruction>" slot and 62 attacker instructions (base setting, no cue phrases).
  * AgentDojo (MIT, agentdojo==0.1.35, benchmark v1.2): 35 injection-task goals, benign default texts at
    the injection points, and the package's own "important instructions" attack template.
  * BIPIA (MIT code, microsoft/BIPIA @ a004b69): the 100 malicious code-snippet attacks only. Its "text"
    attacks are ordinary questions that count as attacks only because they are off-task; labelling them
    INJECTION would teach the model to flag normal questions in emails and documents. Its context data
    mixes third-party licences (e.g. CC BY-SA) and is not used.
  * MCPTox (zhiqiangwang4/MCPTox-Benchmark @ f85189f, AAAI 2026): the repository has no licence file; used
    with permission obtained from the authors by the project owner (2026-10-26). Do not redistribute
    the raw files or derived datasets without checking that permission first.

Every positive has a structure-matched negative (same carrier, benign filler), so the model must judge
content rather than format. Attack instructions are split by index: index % 5 == 0 goes to test only.
"""

import json
import random
import re
from pathlib import Path

from synth_mcp import BENIGN_RESULTS, benign_tool, fill

EXT = Path(__file__).parent / "data" / "external"
PLACEHOLDER = "<Attacker Instruction>"

# Benign fillers for carrier slots (reviews, bios, notes, emails). Several are polite requests addressed
# to people, which is normal content and must not be confused with instructions aimed at the agent.
BENIGN_FILLERS = [
    "Great value for the price. Battery easily lasts a full workday.",
    "Backend developer, coffee enthusiast, maintainer of a few small open-source libraries.",
    "Please send me the slides from yesterday's meeting when you get a chance.",
    "Delivery was two days late but customer service sorted it out quickly.",
    "Reminder: the office will be closed on Monday for the public holiday.",
    "Can you review my pull request before Friday? It touches the billing module.",
    "Loved the hotel breakfast; the room was smaller than the photos suggested.",
    "Note to self: renew the domain before it expires next month.",
    "Thanks for the quick fix! The export works again on our side.",
    "Agenda: budget review, hiring plan, and the Q4 roadmap.",
    "The screen scratches easily, so I would recommend a protector.",
    "Please forward this invoice to your accounts payable team and keep me in CC.",
    "Data engineer based in Izmir. I write about stream processing and Postgres.",
    "Our team lunch moved to 13:00 because of the client call.",
    "Firmware 2.4 fixed the Bluetooth drop-outs I reported earlier.",
    "Lütfen raporu cuma gününe kadar finans ekibine iletin.",
    "Ürün beklediğimden hızlı geldi, paketleme de çok özenliydi.",
    "Could someone on the platform team check why the staging deploy is slow?",
    "Happy to help with the migration next week if you need an extra pair of hands.",
    "Package left at the front desk. Signature: R. Demir.",
]


def _held_out(i: int) -> bool:
    return i % 5 == 0


def _split_for(i: int, rng: random.Random) -> str:
    if _held_out(i):
        return "test"
    return "val" if rng.random() < 0.1 else "train"


def _jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _carrier_text(template: str, filler: str) -> str:
    # Templates are Python-literal dicts; keep them as the agent would see them, with quotes escaped safely.
    return template.replace(PLACEHOLDER, filler.replace("'", "’"))


def _tool_def(rng: random.Random, split: str, text: str | None) -> str:
    name, desc = benign_tool(rng, split)
    return f"{name}\n{desc}" if text is None else f"{name}\n{desc} {text}"


def _embed(rng: random.Random, carrier: str, attack: str) -> str:
    where = rng.random()
    if where < 0.3:
        return f"{attack}\n{carrier}"
    if where < 0.6:
        mid = len(carrier) // 2
        return f"{carrier[:mid]}\n{attack}\n{carrier[mid:]}"
    return f"{carrier}\n{attack}"


def injecagent(rng: random.Random) -> dict[str, list[dict]]:
    users = _jsonl(EXT / "injecagent" / "user_cases.jsonl")
    attacks = [a["Attacker Instruction"] for f in ("attacker_cases_dh.jsonl", "attacker_cases_ds.jsonl") for a in _jsonl(EXT / "injecagent" / f)]
    out = {"train": [], "val": [], "test": []}
    for i, attack in enumerate(attacks):
        split = _split_for(i, rng)
        # Each attack goes into 6 random carriers; every positive gets a matched negative.
        for user in rng.sample(users, 6):
            template = user["Tool Response Template"]
            out[split].append({"text": _carrier_text(template, attack), "label": 1, "source": "injecagent"})
            out[split].append({"text": _carrier_text(template, rng.choice(BENIGN_FILLERS)), "label": 0, "source": "injecagent"})
        out[split].append({"text": _tool_def(rng, split, attack), "label": 1, "source": "injecagent_tooldef"})
        out[split].append({"text": _tool_def(rng, split, None), "label": 0, "source": "injecagent_tooldef"})
    return out


def agentdojo(rng: random.Random) -> dict[str, list[dict]]:
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
    from agentdojo.task_suite.load_suites import get_suites

    template = ImportantInstructionsAttack._JB_STRING
    goals, defaults = [], []
    for suite in get_suites("v1.2").values():
        goals += [t.GOAL for t in suite.injection_tasks.values()]
        defaults += [v for v in suite.get_injection_vector_defaults().values() if v.strip()]
    users = ["Emma Johnson", "the user", "your user", "Mehmet Kaya"]
    models = ["the AI model", "Claude", "the assistant", "GPT-4"]
    out = {"train": [], "val": [], "test": []}
    for i, goal in enumerate(goals):
        split = _split_for(i, rng)
        for _ in range(8):
            carrier = rng.choice(defaults) if rng.random() < 0.5 else fill(rng, rng.choice(BENIGN_RESULTS))
            # Half plain (cue-free), half wrapped in AgentDojo's own attack template.
            attack = goal if rng.random() < 0.5 else template.format(user=rng.choice(users), model=rng.choice(models), goal=goal)
            out[split].append({"text": _embed(rng, carrier, attack), "label": 1, "source": "agentdojo"})
            out[split].append({"text": carrier, "label": 0, "source": "agentdojo"})
        out[split].append({"text": _tool_def(rng, split, goal), "label": 1, "source": "agentdojo_tooldef"})
        out[split].append({"text": _tool_def(rng, split, None), "label": 0, "source": "agentdojo_tooldef"})
    return out


def bipia_code(rng: random.Random) -> dict[str, list[dict]]:
    out = {"train": [], "val": [], "test": []}
    # BIPIA ships its own train/test split of attack instructions; keep it.
    for split_name in ("train", "test"):
        with open(EXT / "bipia" / f"code_attack_{split_name}.json", encoding="utf-8") as f:
            attacks = [a for group in json.load(f).values() for a in group]
        for attack in attacks:
            split = split_name if split_name == "test" else ("val" if rng.random() < 0.1 else "train")
            carrier = fill(rng, rng.choice(BENIGN_RESULTS))
            out[split].append({"text": _embed(rng, carrier, attack), "label": 1, "source": "bipia_code"})
            out[split].append({"text": carrier, "label": 0, "source": "bipia_code"})
    return out


MCPTOX_TOOL = re.compile(r"Tool: (\S+)\nDescription: (.*?)(?=\nArguments:|\n\n)", re.S)


def mcptox(rng: random.Random) -> dict[str, list[dict]]:
    """MCPTox: 485 poisoned tool descriptions on 45 real MCP servers, plus those servers' clean tools.

    Split by server (sorted name index % 5 == 0 -> test, % 10 == 1 -> val), so test measures unseen servers.
    Each server's clean tool descriptions are its matched negatives.
    """
    pure = json.load(open(EXT / "mcptox" / "pure_tool.json", encoding="utf-8"))
    servers = json.load(open(EXT / "mcptox" / "response_all.json", encoding="utf-8"))["servers"]
    clean: dict[str, list[tuple[str, str]]] = {}
    for s in servers.values():
        clean.setdefault(s["server_name"], []).extend(MCPTOX_TOOL.findall(s["clean_system_promot"]))
    names = sorted({c["server_name"] for group in pure for c in group.values()} | set(clean))
    split_of = {n: "test" if i % 5 == 0 else "val" if i % 10 == 1 else "train" for i, n in enumerate(names)}

    out = {"train": [], "val": [], "test": []}
    poisoned: dict[str, int] = {}
    for group in pure:
        for c in group.values():
            split = split_of[c["server_name"]]
            out[split].append({"text": f"{c['tool_name']}\n{c['tool_content'].strip()}", "label": 1, "source": "mcptox"})
            poisoned[c["server_name"]] = poisoned.get(c["server_name"], 0) + 1
    for name, tools in clean.items():
        unique = list(dict.fromkeys(tools))
        split = split_of[name]
        # Balance each server: as many clean rows as poisoned ones, cycling through its real tools.
        need = max(poisoned.get(name, 0), len(unique))
        for i in range(need):
            tool, desc = unique[i % len(unique)] if unique else benign_tool(rng, split)
            out[split].append({"text": f"{tool}\n{desc.strip()}", "label": 0, "source": "mcptox"})
    return out


def attack_pool() -> dict[str, list[str]]:
    """Raw InjecAgent instructions and AgentDojo goals by split, for embedding into other carriers.

    Test membership (index % 5 == 0) matches injecagent()/agentdojo(), so test attacks stay unseen.
    """
    from agentdojo.task_suite.load_suites import get_suites

    injec = [a["Attacker Instruction"] for f in ("attacker_cases_dh.jsonl", "attacker_cases_ds.jsonl") for a in _jsonl(EXT / "injecagent" / f)]
    goals = [t.GOAL for suite in get_suites("v1.2").values() for t in suite.injection_tasks.values()]
    out = {"train": [], "val": [], "test": []}
    for texts in (injec, goals):
        for i, t in enumerate(texts):
            out["test" if i % 5 == 0 else "val" if i % 10 == 1 else "train"].append(t)
    return out


def load_all(seed: int = 7) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    merged = {"train": [], "val": [], "test": []}
    for loader in (injecagent, agentdojo, bipia_code, mcptox):
        for split, rows in loader(rng).items():
            merged[split] += rows
    return merged


if __name__ == "__main__":
    from collections import Counter

    data = load_all()
    for split, rows in data.items():
        print(split, len(rows), dict(Counter((r["source"], r["label"]) for r in rows)))
