"""BIPIA matched set, built the way "Passing the Test You Trained On" (Liu 2026) describes it.

Our own port of the construction (benchmark repo: scripts/build_bipia.py, MIT). It only reads BIPIA's data files
(JSON / JSONL); no code from the BIPIA or benchmark repositories is executed.

  benign   every clean context (train + test) of the email, table and code tasks
  injected each clean context with K = 4 of BIPIA's own attack strings inserted at start / middle / end
           (text attacks for email and table, code attacks for code); the attack carries the split it came from

usage: python -I build_bipia_mine.py <BIPIA/benchmark dir> <out.jsonl>
Check: the paper reports 1,200 benign and 2,435 injected rows for the test-split attacks.
"""

import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

root, out = Path(sys.argv[1]), Path(sys.argv[2])
K = 4
rng = random.Random(0)


def insert(context: str, attack: str, pos: str) -> str:
    if pos == "start":
        return attack + "\n" + context
    if pos == "end":
        return context + "\n" + attack
    cuts = [m.end() for m in re.finditer(r"[.!?]\s", context)] or [len(context) // 2]
    c = rng.choice(cuts)
    return context[:c] + "\n" + attack + "\n" + context[c:]


def attacks(name: str):
    data = json.load(open(root / name, encoding="utf-8"))
    split = "test" if "test" in name else "train"
    return [(f"{category}|{split}", s) for category, lst in data.items() for s in lst]


TEXT = attacks("text_attack_test.json") + attacks("text_attack_train.json")
CODE = attacks("code_attack_test.json") + attacks("code_attack_train.json")

rows = []
for task in ("email", "table", "code"):
    for split in ("train", "test"):
        for line in open(root / task / f"{split}.jsonl", encoding="utf-8"):
            ex = json.loads(line)
            if task == "code":
                context = "\n".join(ex["context"])
                pool = CODE
            else:
                context = ex["context"]
                pool = TEXT
            base = dict(suite="bipia-" + task, task=f"{task}/{split}/{len(rows)}", function=task, step=0)
            rows.append(dict(base, attack="none", position="none", label=0, text=context))
            for category, s in rng.sample(pool, K):
                pos = rng.choice(["start", "middle", "end"])
                name, attack_split = category.split("|")
                rows.append(dict(base, attack="bipia:" + name, attack_split=attack_split, position=pos, label=1,
                                 text=insert(context, s, pos)))

with open(out, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")

benign = sum(r["label"] == 0 for r in rows)
inj_test = sum(r["label"] == 1 and r["attack_split"] == "test" for r in rows)
inj_train = sum(r["label"] == 1 and r["attack_split"] == "train" for r in rows)
print("benign", benign, "| injected (test-split attacks)", inj_test, "| injected (train-split attacks)", inj_train)
print("by suite", dict(Counter(r["suite"] for r in rows)))
print("paper check: benign 1200 and injected(test) 2435 ->", "MATCH" if (benign, inj_test) == (1200, 2435) else "DIFFERENT")
