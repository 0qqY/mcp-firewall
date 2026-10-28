"""Fine-tunes a sequence classifier (SAFE=0, INJECTION=1) on data/{train,val}.jsonl.

Defaults fit an 8 GB GPU: DeBERTa-v3-base, bf16 autocast over fp32 weights, batch 8 x 2 accumulation,
gradient checkpointing and dynamic padding.
"""

import argparse
import json
import math
from pathlib import Path

import numpy as np
import torch
from datasets import load_dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
    set_seed,
)

from metrics import binary_metrics

HERE = Path(__file__).parent
LABELS = {0: "SAFE", 1: "INJECTION"}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-model", default="microsoft/deberta-v3-base",
                    help="e.g. microsoft/deberta-v3-base, jhu-clsp/mmBERT-base, or a baseline to continue from")
    ap.add_argument("--revision", default=None, help="pin a hub commit of --base-model")
    ap.add_argument("--data", type=Path, default=HERE / "data")
    ap.add_argument("--out", type=Path, default=HERE / "runs" / "mcp-pi")
    ap.add_argument("--epochs", type=float, default=3)
    ap.add_argument("--lr", type=float, default=2e-5)
    # Effective batch 16. DeBERTa's disentangled attention is memory-hungry at 512 tokens; 8 per step keeps
    # an 8 GB card out of shared system memory, which Windows otherwise uses silently and slowly.
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--grad-accum", type=int, default=2)
    ap.add_argument("--max-len", type=int, default=512)
    # On by default: 8 GB cards peak at ~3.5 GiB with it, ~8.1 GiB without (spilling into shared memory).
    ap.add_argument("--no-grad-ckpt", dest="grad_ckpt", action="store_false")
    ap.add_argument("--max-train", type=int, default=None, help="limit train rows (smoke tests)")
    ap.add_argument("--precision", choices=["bf16", "fp32"], default="bf16")
    ap.add_argument("--log-steps", type=int, default=50)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    set_seed(args.seed)

    if not torch.cuda.is_available():
        print("WARNING: CUDA not available, training on CPU will be very slow")

    ds = load_dataset("json", data_files={"train": str(args.data / "train.jsonl"), "validation": str(args.data / "val.jsonl")})
    if args.max_train:
        ds["train"] = ds["train"].shuffle(seed=args.seed).select(range(min(args.max_train, len(ds["train"]))))

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, revision=args.revision)
    ds = ds.map(lambda b: tokenizer(b["text"], truncation=True, max_length=args.max_len), batched=True,
                remove_columns=["text", "source"])

    # transformers 5 loads the checkpoint dtype by default (fp16 for deberta-v3-base). Optimizer master
    # weights must be fp32: AdamW's eps underflows in fp16 and every update becomes NaN. bf16 autocast
    # still handles the compute.
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        revision=args.revision,
        dtype=torch.float32,
        num_labels=2,
        id2label=LABELS,
        label2id={v: k for k, v in LABELS.items()},
        ignore_mismatched_sizes=True,
    )

    def compute_metrics(pred):
        logits, labels = pred
        scores = torch.softmax(torch.tensor(logits, dtype=torch.float32), dim=-1)[:, 1].numpy()
        return binary_metrics(np.asarray(labels), scores, 0.5)

    bf16 = args.precision == "bf16" and torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    # transformers 5 dropped warmup_ratio; warm up over the first 6% of optimizer steps.
    total_steps = math.ceil(len(ds["train"]) / (args.batch * args.grad_accum)) * args.epochs
    training_args = TrainingArguments(
        output_dir=str(args.out),
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        save_total_limit=2,
        learning_rate=args.lr,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch,
        gradient_accumulation_steps=args.grad_accum,
        num_train_epochs=args.epochs,
        weight_decay=0.01,
        warmup_steps=max(1, int(total_steps * 0.06)),
        bf16=bf16,
        gradient_checkpointing=args.grad_ckpt,
        logging_steps=args.log_steps,
        dataloader_num_workers=0,
        report_to="none",
        seed=args.seed,
    )
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=ds["train"],
        eval_dataset=ds["validation"],
        processing_class=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
    )
    trainer.train()

    best = args.out / "best"
    trainer.save_model(str(best))
    tokenizer.save_pretrained(str(best))
    metrics = trainer.evaluate()
    (best / "val_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))
    if torch.cuda.is_available():
        peak = torch.cuda.max_memory_allocated() / 2**30
        vram = torch.cuda.get_device_properties(0).total_memory / 2**30
        print(f"peak GPU memory: {peak:.2f} GiB of {vram:.1f} GiB")
        if peak > vram * 0.95:
            print("WARNING: exceeded dedicated VRAM; lower --batch, --max-len or add --grad-ckpt")
    print(f"saved to {best}")


if __name__ == "__main__":
    main()
