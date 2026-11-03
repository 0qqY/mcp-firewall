"""Channel tags: the firewall tells the model where a text came from (src/ml/classifier.ts CHANNEL_TAGS).

The firewall never sees the user's own messages, only what servers send: tool definitions, tool results and
prompt templates. A definition or a template addresses the model by design ("Use this tool when ...",
"Act as a reviewer"); a tool result should not. Without a tag the model has to learn one boundary for all
three, and benign role prompts (v10) cost tool-result recall (LLMail 96% -> 60%). With a tag each channel
gets its own boundary.

Every row gets "<tag>\\n" in front: definition sources get [tool definition], benign_prompts.py rows (role and
system prompts with injected twins) get [prompt template], everything else [tool output] - the channel the
firewall scans most, and the one every untagged model was implicitly trained for.

The tag alone was not enough (soup04-ctx, 2026-11-02): role prompts as benign pulled the whole model towards
"text that addresses the model is fine", LLMail recall 99% -> 62%. --output-twins adds the same role prompts
tagged [tool output] with label 1, so only the tag tells the two apart and the model has to read it.

  python channels.py --data data/v12dev2 --out data/v12ctx
  python channels.py --data data/v12dev2 --out data/v12twin --output-twins 0.5
"""

import argparse
import json
import random
from collections import Counter
from pathlib import Path

TAGS = {"definition": "[tool definition]", "output": "[tool output]", "prompt": "[prompt template]"}
DEFINITION_SOURCES = {"synth_tool_def", "mcptox", "injecagent_tooldef", "agentdojo_tooldef"}
PROMPT_SOURCES = {"sp_awesome", "sp_library", "sp_rules"}


def channel(source: str | None) -> str:
    base = (source or "").split("+")[0]  # "synth_tool_def+mt_tr" is a translation of synth_tool_def
    if base in DEFINITION_SOURCES:
        return "definition"
    if base in PROMPT_SOURCES:
        return "prompt"
    return "output"  # also "twin_sp_*": a role prompt that turned up in a tool result


def tag(text: str, ch: str) -> str:
    return f"{TAGS[ch]}\n{text}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, required=True, help="folder with train/val/test.jsonl")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--no-prompts", dest="prompts", action="store_false", help="leave out benign_prompts.py rows")
    ap.add_argument("--output-twins", type=float, default=0.0, metavar="SHARE",
                    help="share of benign role prompts also added as [tool output] with label 1")
    ap.add_argument("--seed", type=int, default=23)
    args = ap.parse_args()

    extra = {"train": [], "val": [], "test": []}
    if args.prompts:
        from benign_prompts import load_all as load_benign_prompts

        extra = load_benign_prompts()
        rng = random.Random(args.seed)
        for split, rows in extra.items():
            rows += [{**r, "label": 1, "source": "twin_" + r["source"]} for r in rows
                     if r["label"] == 0 and rng.random() < args.output_twins]
    args.out.mkdir(parents=True, exist_ok=True)
    for split in ("train", "val", "test"):
        path = args.data / f"{split}.jsonl"
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()] if path.exists() else []
        rows += extra[split]
        with open(args.out / f"{split}.jsonl", "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps({**r, "text": tag(r["text"], channel(r.get("source")))}, ensure_ascii=False) + "\n")
        print(split, len(rows), dict(Counter((channel(r.get("source")), r["label"]) for r in rows)))


if __name__ == "__main__":
    main()
