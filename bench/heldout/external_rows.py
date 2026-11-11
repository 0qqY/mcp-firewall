"""Turns the downloaded external Hugging Face data into rows for bench/heldout/score.mjs (same schema as heldout-v1.jsonl).

Reads  training/data/hf_new/<owner>__<name>/   and writes  training/data/hf_new/_external_eval/*.jsonl  (git-ignored; each source keeps its
own license: mcp-research-alliance/mcp-ecosystem CC-BY-4.0, halilneed/turkish-prompt-injection-false-alarm-benchmark CC0-1.0,
treycsa/realistic-prompt-injections MIT). Nothing from the downloaded files is imported or executed, only parsed as JSON / parquet.

  python -X utf8 -I bench/heldout/external_rows.py [--tools 3000] [--seed 1]

Files written:
  tr_false_alarm.jsonl      2875 benign Turkish texts (business, banking, task instructions) as tool results
  tr_task_prompt.jsonl      the 1000 task instructions again, as prompt templates
  probes_wrapped.jsonl      17 injections / benign texts wrapped in realistic documents
  real_tools_sample.jsonl   random sample of real MCP tool definitions (unlabelled, assumed benign: every flag has to be reviewed by hand)
  real_tools_all.jsonl / real_prompts_all.jsonl / real_resources_all.jsonl   every de-duplicated record, for the regex scan only
"""
import json
import random
import sys
from pathlib import Path

import pyarrow.parquet as pq

HF = Path(__file__).resolve().parents[2] / "training" / "data" / "hf_new"
OUT = HF / "_external_eval"
args = sys.argv[1:]


def opt(name, default):
    return type(default)(args[args.index(f"--{name}") + 1]) if f"--{name}" in args else default


N_TOOLS, SEED = opt("tools", 3000), opt("seed", 1)
OUT.mkdir(exist_ok=True)


def write(name, rows):
    with open(OUT / name, "w", encoding="utf8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{name}: {len(rows)} rows")


def jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf8").splitlines() if line.strip()]


# --- Turkish false alarm benchmark: every text is benign ---------------------------------------------------------------------------
src = "halilneed/turkish-prompt-injection-false-alarm-benchmark"
tr = jsonl(HF / src.replace("/", "__") / "data" / "test.jsonl")
assert all(str(r["label"]) == "0" for r in tr), "the benchmark is meant to be all benign"
write("tr_false_alarm.jsonl", [dict(id=f"XR-{r['id']}", source=src, channel="output", kind="tool_result", cls=r["subset"], lang="tr", carrier=r["subset"], label=0, text=r["text"]) for r in tr])
write("tr_task_prompt.jsonl", [dict(id=f"XP-{r['id']}", source=src, channel="prompt", kind="prompt_template", cls=r["subset"], lang="tr", carrier=r["subset"], label=0, text=r["text"]) for r in tr if r["subset"] == "task_instruction"])

# --- realistic wrapped injections ----------------------------------------------------------------------------------------------------
src = "treycsa/realistic-prompt-injections"
probes = jsonl(HF / src.replace("/", "__") / "probes.jsonl")
write("probes_wrapped.jsonl", [dict(id=f"XW-{r['id']}", source=src, channel="output", kind="tool_result", cls=r["category"], lang="en", carrier="wrapped_document", label=1 if r["label"] == "injection" else 0, text=r["text"]) for r in probes])

# --- real MCP tool, prompt and resource definitions -------------------------------------------------------------------------------
src = "mcp-research-alliance/mcp-ecosystem"
base = HF / src.replace("/", "__") / "viewer"


def parse_json(value, default):
    if value in (None, "None", ""):
        return default
    try:
        parsed = json.loads(value)
    except Exception:  # noqa: BLE001
        return default
    return parsed if isinstance(parsed, type(default)) else default


tools_raw = pq.read_table(base / "mcp_tools.parquet", columns=["tool_name", "original_description", "input_json_schema"]).to_pylist()
seen, tool_defs, no_description = set(), [], 0
for r in tools_raw:
    name, desc = r["tool_name"] or "", r["original_description"] or ""
    if len(desc.strip()) < 15:
        no_description += 1
        continue
    if (name, desc) in seen:
        continue
    seen.add((name, desc))
    tool_defs.append({"name": name, "description": desc, "inputSchema": parse_json(r["input_json_schema"], {})})
lens = sorted(len(d["description"]) for d in tool_defs)
print(f"tools: {len(tools_raw)} records, {no_description} without a usable description, {len(tool_defs)} unique (name, description); "
      f"description length median {lens[len(lens) // 2]}, p95 {lens[int(len(lens) * 0.95)]}, max {lens[-1]}")


def row(prefix, i, cls, definition):
    return dict(id=f"{prefix}-{i:06d}", source=src, channel="definition", kind="definition", cls=cls, lang="xx", carrier="description", label=0, definition=definition)


all_tools = [row("XA", i, "real_tool", d) for i, d in enumerate(tool_defs)]
write("real_tools_all.jsonl", all_tools)
write("real_tools_sample.jsonl", random.Random(SEED).sample(all_tools, min(N_TOOLS, len(all_tools))))

prompts, seen = [], set()
for r in pq.read_table(base / "mcp_prompts.parquet", columns=["prompt_name", "description", "arguments_json"]).to_pylist():
    key = (r["prompt_name"], r["description"])
    if key in seen or len((r["description"] or "").strip()) < 15:
        continue
    seen.add(key)
    prompts.append(row("XQ", len(prompts), "real_prompt", {"name": r["prompt_name"] or "", "description": r["description"], "arguments": parse_json(r["arguments_json"], [])}))
write("real_prompts_all.jsonl", prompts)

resources, seen = [], set()
for r in pq.read_table(base / "mcp_resources.parquet", columns=["resource_name", "resource_uri_template", "description", "mime_type"]).to_pylist():
    key = (r["resource_name"], r["resource_uri_template"], r["description"])
    if key in seen or len((r["description"] or "").strip()) < 15:
        continue
    seen.add(key)
    resources.append(row("XS", len(resources), "real_resource", {"name": r["resource_name"] or "", "uri": r["resource_uri_template"] or "", "description": r["description"], "mimeType": r["mime_type"] or ""}))
write("real_resources_all.jsonl", resources)
