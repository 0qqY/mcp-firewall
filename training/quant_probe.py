"""Can the firewall's model run in less memory? Builds quantized variants of an exported fp32 graph and compares each with
fp32 on prepared texts (bench/heldout/score.mjs --dump), with the firewall's windows.

export_onnx.py already tries one variant (dynamic int8 of everything) and removes it when it drifts; that is what happened
to the default model. This script looks at the parts separately, because mmBERT's size is mostly its embedding table
(256k tokens x 768 = 197M of ~307M parameters): quantizing only that table is a different trade from quantizing attention.

  python -I -X utf8 quant_probe.py build  --model ../models/<name> --out <work dir>
  python -I -X utf8 quant_probe.py score  --model ../models/<name> --graph <file.onnx> --texts texts.jsonl --out scores.json
  python -I -X utf8 quant_probe.py report --rows ../bench/heldout/heldout-v1.jsonl --base fp32.json <variant.json> ...
  python -I -X utf8 quant_probe.py q8     --model ../models/<name>

`q8` writes the int8-embedding variant as <model>/onnx/model_quantized.onnx, the file the firewall loads with
`ml.dtype: q8` (opt-in; measured on the default model in bench/q8/README.md). It refuses to replace an existing file
unless --force is given.

`score` runs one graph in its own process and reports that process's peak memory (Windows: peak working set and peak
commit), so graphs can be compared on memory as well as on scores.
"""

import argparse
import ctypes
import json
import sys
import time
from pathlib import Path

import numpy as np

VARIANTS = {
    # name: quantize_dynamic keyword arguments
    "int8-all": {},
    "int8-embedding": {"op_types_to_quantize": ["Gather"]},
    "int8-matmul": {"op_types_to_quantize": ["MatMul"]},
    "int8-matmul-perchannel": {"op_types_to_quantize": ["MatMul"], "per_channel": True},
    "int8-all-perchannel": {"per_channel": True},
}


def chunk_text(text: str, size: int = 1500) -> list[str]:
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


def within_budget(chunks: list[str], limit: int = 32) -> list[str]:
    if len(chunks) <= limit:
        return chunks
    head = -(-limit // 2)
    return chunks[:head] + chunks[len(chunks) - (limit - head) :]


def peak_memory_mb() -> tuple[float, float]:
    """(peak working set, peak commit) of this process in MB; zeros off Windows."""
    if sys.platform != "win32":
        return 0.0, 0.0

    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    c = Counters()
    c.cb = ctypes.sizeof(c)
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
    ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(handle), ctypes.byref(c), c.cb)
    return c.PeakWorkingSetSize / 2**20, c.PeakPagefileUsage / 2**20


def build(args) -> None:
    from onnxruntime.quantization import QuantType, quantize_dynamic

    src = args.model / "onnx" / "model.onnx"
    args.out.mkdir(parents=True, exist_ok=True)
    for name, kw in VARIANTS.items():
        dst = args.out / f"{name}.onnx"
        if dst.exists():
            print(f"skip {name} (exists)", flush=True)
            continue
        started = time.time()
        try:
            quantize_dynamic(str(src), str(dst), weight_type=QuantType.QInt8, **kw)
            print(f"{name}: {dst.stat().st_size / 2**20:.0f} MB in {time.time() - started:.0f} s", flush=True)
        except Exception as e:  # a variant the installed onnxruntime cannot build is reported, not fatal
            print(f"{name}: FAILED {type(e).__name__}: {str(e)[:200]}", flush=True)
    print(f"fp32: {src.stat().st_size / 2**20:.0f} MB")


def q8(args) -> None:
    """The opt-in q8 file: only the embedding table (Gather) in int8, the rest of the graph stays fp32."""
    from onnxruntime.quantization import QuantType, quantize_dynamic

    src = args.model / "onnx" / "model.onnx"
    dst = args.model / "onnx" / "model_quantized.onnx"
    if dst.exists() and not args.force:
        sys.exit(f"{dst} exists (export_onnx.py may have written int8-all there); pass --force to replace it")
    tmp = dst.with_suffix(".tmp.onnx")
    quantize_dynamic(str(src), str(tmp), weight_type=QuantType.QInt8, **VARIANTS["int8-embedding"])
    tmp.replace(dst)
    print(f"wrote {dst} ({dst.stat().st_size / 2**20:.0f} MB, fp32 {src.stat().st_size / 2**20:.0f} MB); use ml.dtype: q8")


def score(args) -> None:
    import onnxruntime as ort
    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(args.model)
    rows = [json.loads(l) for l in open(args.texts, encoding="utf-8") if l.strip()]
    owners, pieces = [], []
    for i, r in enumerate(rows):
        for c in within_budget(chunk_text(r["text"])):
            owners.append(i)
            pieces.append(c)
    so = ort.SessionOptions()
    so.enable_cpu_mem_arena = False  # as the firewall runs it (ml.memoryArena: false)
    so.enable_mem_pattern = False
    loaded = time.time()
    session = ort.InferenceSession(str(args.graph), so, providers=["CPUExecutionProvider"])
    load_s = time.time() - loaded
    label = json.loads((args.model / "config.json").read_text(encoding="utf-8"))["label2id"]["INJECTION"]
    flat = np.zeros(len(pieces), dtype=np.float32)
    order = np.argsort([len(p) for p in pieces], kind="stable")
    started = time.time()
    for s in range(0, len(order), args.batch):
        sel = order[s : s + args.batch]
        enc = tok([pieces[j] for j in sel], padding=True, truncation=True, max_length=512, return_tensors="np")
        logits = session.run(None, {"input_ids": enc["input_ids"].astype(np.int64), "attention_mask": enc["attention_mask"].astype(np.int64)})[0]
        e = np.exp(logits - logits.max(-1, keepdims=True))
        flat[sel] = (e / e.sum(-1, keepdims=True))[:, label]
    run_s = time.time() - started
    scores = np.zeros(len(rows), dtype=np.float32)
    np.maximum.at(scores, np.array(owners, dtype=np.int64), flat)
    ws, commit = peak_memory_mb()
    args.out.write_text(json.dumps({
        "model": args.name or args.graph.stem, "threshold": args.threshold, "scorer": "quant_probe.py (onnxruntime CPU)",
        "graphMB": round(args.graph.stat().st_size / 2**20), "loadSeconds": round(load_s, 1), "msPerWindow": round(1000 * run_s / max(1, len(pieces)), 1),
        "peakWorkingSetMB": round(ws), "peakCommitMB": round(commit),
        "results": [{"id": r["id"], "score": float(s)} for r, s in zip(rows, scores)]}, indent=1), encoding="utf-8")
    print(f"{args.graph.name}: {len(pieces)} windows, load {load_s:.1f} s, {1000 * run_s / max(1, len(pieces)):.0f} ms/window, peak working set {ws:.0f} MB, peak commit {commit:.0f} MB", flush=True)


def report(args) -> None:
    rows = {json.loads(l)["id"]: json.loads(l) for l in open(args.rows, encoding="utf-8") if l.strip()}
    base = json.load(open(args.base, encoding="utf-8"))
    b = {r["id"]: r["score"] for r in base["results"]}
    thr = base["threshold"]
    y = np.array([rows[i]["label"] for i in b])

    def line(res):
        s = np.array([{r["id"]: r["score"] for r in res["results"]}[i] for i in b])
        bs = np.array([b[i] for i in b])
        flips = int(((s >= thr) != (bs >= thr)).sum())
        rec, fpr = 100 * (s[y == 1] >= thr).mean(), 100 * (s[y == 0] >= thr).mean()
        pos, neg = s[y == 1], s[y == 0]
        auc = float((pos[:, None] > neg[None, :]).mean() + 0.5 * (pos[:, None] == neg[None, :]).mean())
        return (f"| {res['model']} | {res.get('graphMB', '-')} | {res.get('peakWorkingSetMB', '-')} | {res.get('peakCommitMB', '-')} | {res.get('loadSeconds', '-')} | "
                f"{res.get('msPerWindow', '-')} | {rec:.1f}% | {fpr:.1f}% | {auc:.3f} | {flips} | {np.abs(s - bs).max():.3f} | {np.abs(s - bs).mean():.4f} |")

    out = [f"Eşik {thr}; {len(b)} satır. `karar farkı`: fp32 ile eşikte farklı karar verilen satır sayısı.", "",
           "| graph | dosya MB | peak working set MB | peak commit MB | yükleme sn | ms/pencere | recall | FPR | AUC | karar farkı | en büyük skor farkı | ortalama skor farkı |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|", line(base)]
    out += [line(json.load(open(p, encoding="utf-8"))) for p in args.variants]
    text = "\n".join(out) + "\n"
    print(text)
    if args.md:
        args.md.write_text(text, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--model", type=Path, required=True)
    b.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("score")
    s.add_argument("--model", type=Path, required=True)
    s.add_argument("--graph", type=Path, required=True)
    s.add_argument("--texts", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--name")
    s.add_argument("--threshold", type=float, default=0.3)
    s.add_argument("--batch", type=int, default=2)
    r = sub.add_parser("report")
    r.add_argument("--rows", type=Path, required=True)
    r.add_argument("--base", type=Path, required=True)
    r.add_argument("--md", type=Path)
    r.add_argument("variants", type=Path, nargs="*")
    q = sub.add_parser("q8")
    q.add_argument("--model", type=Path, required=True)
    q.add_argument("--force", action="store_true")
    args = ap.parse_args()
    {"build": build, "score": score, "report": report, "q8": q8}[args.cmd](args)


if __name__ == "__main__":
    main()
