"""Converts the "evilsandangels" twin dataset (8000 rows: 4 attack categories x malicious + clean twin, pair_id splits)
into the train/val/test jsonl format of train.py / evaluate.py / score_dump.py.

  python -I evilsandangels_data.py "D:/Ai Attack Dataset (Evil and Clean twins)/dataset"

Writes
  data/eva/{train,val,test}.jsonl     the dataset alone (solo run: mcp-pi-mmbert-evilsandangels-solo)
  data/v12eva/{train,val,test}.jsonl  data/v12lab + the dataset (main run: mcp-pi-mmbert-evilsandangels)
train/val rows are {text, label, source}; test rows keep id, pair_id, category, subtype, lang for the error analysis.

rug_pull rows hold two pretty-printed manifests (median ~800 tokens, all over the 512-token limit, so the changed
current_manifest would be cut off). They are re-serialised as compact JSON (same keys, same order, same values;
only whitespace is dropped): max 428 tokens, so nothing is truncated.
"""

import argparse
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).parent


def convert(row: dict) -> dict:
    text = row["text"]
    if row["category"] == "rug_pull":
        text = json.dumps(json.loads(text), ensure_ascii=False, separators=(",", ":"))
    return {
        "text": text,
        "label": int(row["label_id"]),
        "source": f"eva_{row['category']}",
        "id": row["id"],
        "pair_id": row["pair_id"],
        "category": row["category"],
        "subtype": row["subtype"],
        "lang": row["lang"],
    }


def write(path: Path, rows: list[dict], keys: tuple[str, ...] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps({k: r[k] for k in keys} if keys else r, ensure_ascii=False) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dataset", type=Path, help="folder that holds 'evil + clean/all.jsonl'")
    ap.add_argument("--lab", type=Path, default=HERE / "data" / "v12lab")
    args = ap.parse_args()

    src = args.dataset / "evil + clean" / "all.jsonl"
    rows = [convert(json.loads(l)) for l in open(src, encoding="utf-8") if l.strip()]
    split_of = {json.loads(l)["id"]: json.loads(l)["split"] for l in open(src, encoding="utf-8") if l.strip()}
    parts = {s: [r for r in rows if split_of[r["id"]] == s] for s in ("train", "val", "test")}

    plain = ("text", "label", "source")
    write(HERE / "data" / "eva" / "train.jsonl", parts["train"], plain)
    write(HERE / "data" / "eva" / "val.jsonl", parts["val"], plain)
    write(HERE / "data" / "eva" / "test.jsonl", parts["test"])

    out = HERE / "data" / "v12eva"
    out.mkdir(parents=True, exist_ok=True)
    for name, extra in (("train", parts["train"]), ("val", parts["val"])):
        with open(args.lab / f"{name}.jsonl", encoding="utf-8") as f:
            base = [l for l in f if l.strip()]
        with open(out / f"{name}.jsonl", "w", encoding="utf-8", newline="\n") as f:
            f.writelines(l if l.endswith("\n") else l + "\n" for l in base)
            for r in extra:
                f.write(json.dumps({k: r[k] for k in plain}, ensure_ascii=False) + "\n")
        print(f"v12eva/{name}: {len(base)} lab + {len(extra)} eva = {len(base) + len(extra)}")
    (out / "test.jsonl").write_bytes((args.lab / "test.jsonl").read_bytes())

    for s, rs in parts.items():
        print(s, len(rs), dict(Counter((r["category"], r["label"]) for r in rs)))
    rp = [len(r["text"]) for r in rows if r["category"] == "rug_pull"]
    print(f"rug_pull compact chars: median {sorted(rp)[len(rp) // 2]}, max {max(rp)} (firewall window = 1500)")


if __name__ == "__main__":
    main()
