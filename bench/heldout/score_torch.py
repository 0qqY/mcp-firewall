"""Scores prepared texts (node bench/heldout/score.mjs --dump texts.jsonl) with a Hugging Face model in PyTorch and writes the
same result file as score.mjs, so report.mjs / compare.mjs read it. Used for (a) third-party guard models that have no ONNX
export and (b) screening our own checkpoints on the GPU before they are exported.

Windows are the firewall's: 1500 characters with 1/8 overlap, at most 32 per text (head and tail kept), highest window score.

  python -I -X utf8 bench/heldout/score_torch.py --texts texts.jsonl --model <dir> --out result.json [--name label]
      [--positive JAILBREAK,INJECTION]   labels (or indices) whose probabilities are summed; default: evaluate.py's rule
      [--kind qwen3guard]                Qwen3Guard-Gen: 1 - P(Safe) at the "Safety:" position (Unsafe + Controversial);
                                         --strict counts Controversial as safe
      [--threshold 0.5]                  the model's own decision threshold, stored in the result for report.mjs

Model folders are loaded as data only: safetensors weights, no trust_remote_code.
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch

POSITIVE_LABELS = {"INJECTION", "LABEL_1", "JAILBREAK", "UNSAFE", "MALICIOUS"}


def chunk_text(text: str, size: int) -> list[str]:
    """src/ml/classifier.ts chunkText."""
    if not text.strip():
        return []
    if len(text) <= size:
        return [text]
    step = size - size // 8
    chunks, start = [], 0
    while True:
        chunks.append(text[start : start + size])
        if start + size >= len(text):
            return chunks
        start += step


def within_budget(chunks: list[str], limit: int) -> list[str]:
    """src/ml/classifier.ts withinBudget: head and tail windows when a text has too many."""
    if len(chunks) <= limit:
        return chunks
    head = -(-limit // 2)
    return chunks[:head] + chunks[len(chunks) - (limit - head) :]


@torch.inference_mode()
def seqclf_scores(model_dir: Path, pieces: list[str], positive: str | None, batch: int, max_len: int, device: str) -> np.ndarray:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir, dtype=torch.float32).to(device).eval()
    id2label = {int(k): str(v) for k, v in model.config.id2label.items()}
    if positive:
        want = {p.strip().upper() for p in positive.split(",")}
        idx = [i for i, l in id2label.items() if l.upper() in want or str(i) in want]
    else:
        idx = [i for i, l in id2label.items() if l.upper() in POSITIVE_LABELS] or [1]
    print(f"labels {id2label} -> positive {[id2label[i] for i in idx]}", flush=True)
    order = np.argsort([len(p) for p in pieces], kind="stable")
    out = np.zeros(len(pieces), dtype=np.float32)
    for s in range(0, len(order), batch):
        sel = order[s : s + batch]
        enc = tok([pieces[j] for j in sel], truncation=True, max_length=max_len, padding=True, return_tensors="pt").to(device)
        probs = torch.softmax(model(**enc).logits.float(), dim=-1)
        out[sel] = probs[:, idx].sum(dim=-1).cpu().numpy()
    return out


@torch.inference_mode()
def qwen3guard_scores(model_dir: Path, pieces: list[str], strict: bool, batch: int, device: str) -> np.ndarray:
    """Qwen3Guard-Gen prompt moderation. The reply starts "Safety: <Safe|Unsafe|Controversial>"; the three label words start
    with different tokens, so the next-token distribution after "Safety:" gives their probabilities in one forward pass."""
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(model_dir)
    tok.padding_side = "left"
    model = AutoModelForCausalLM.from_pretrained(model_dir, dtype=torch.bfloat16 if device == "cuda" else torch.float32).to(device).eval()
    first = {w: tok.encode(" " + w, add_special_tokens=False)[0] for w in ("Safe", "Unsafe", "Controversial")}
    assert len(set(first.values())) == 3, first
    probe = tok.apply_chat_template([{"role": "user", "content": "hello"}], tokenize=False)
    print(f"label tokens {first}; template tail {probe[-60:]!r}", flush=True)
    order = np.argsort([len(p) for p in pieces], kind="stable")
    out = np.zeros(len(pieces), dtype=np.float32)
    for s in range(0, len(order), batch):
        sel = order[s : s + batch]
        prompts = [tok.apply_chat_template([{"role": "user", "content": pieces[j]}], tokenize=False) + "Safety:" for j in sel]
        enc = tok(prompts, return_tensors="pt", padding=True).to(device)
        logits = model(**enc).logits[:, -1, :].float()
        p = torch.softmax(logits[:, [first["Safe"], first["Unsafe"], first["Controversial"]]], dim=-1)
        out[sel] = (p[:, 1] if strict else p[:, 1] + p[:, 2]).cpu().numpy()
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--texts", type=Path, required=True)
    ap.add_argument("--model", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--name")
    ap.add_argument("--kind", choices=["seqclf", "qwen3guard"], default="seqclf")
    ap.add_argument("--positive")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--chunk", type=int, default=1500)
    ap.add_argument("--max-chunks", type=int, default=32)
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.texts, encoding="utf-8") if l.strip()]
    owners, pieces = [], []
    for i, r in enumerate(rows):
        for c in within_budget(chunk_text(r["text"], args.chunk), args.max_chunks):
            owners.append(i)
            pieces.append(c)
    started = time.time()
    if args.kind == "qwen3guard":
        flat = qwen3guard_scores(args.model, pieces, args.strict, max(1, args.batch // 4), args.device)
    else:
        flat = seqclf_scores(args.model, pieces, args.positive, args.batch, args.max_len, args.device)
    scores = np.zeros(len(rows), dtype=np.float32)
    np.maximum.at(scores, np.array(owners, dtype=np.int64), flat)
    name = args.name or args.model.name
    args.out.write_text(json.dumps({
        "model": name, "threshold": args.threshold, "scoredAt": datetime.now(timezone.utc).isoformat(), "scorer": "score_torch.py",
        "results": [{"id": r["id"], "score": float(s)} for r, s in zip(rows, scores)],
    }, indent=1), encoding="utf-8")
    print(f"{name}: {len(rows)} texts, {len(pieces)} windows, {time.time() - started:.1f} s on {args.device} -> {args.out}", flush=True)


if __name__ == "__main__":
    main()
