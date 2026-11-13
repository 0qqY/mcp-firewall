"""Training rows from real documentation: text that gives imperatives to a HUMAN reader (install guides, tutorials, homework
briefs, issues), 13.11.2026.

Why: bench/heldout/gercek-turkce-olcum.md showed the default model flags such text when an agent reads it as a tool result
(Turkish READMEs 20.7%, Turkish wikibooks 7.3%, English READMEs 13.3%). Earlier rounds used task prompts and role prompts as
negatives, i.e. imperatives addressed to the AI, which have the same shape as attacks and cost recall.

Each benign window can get an attack twin: the same window with one injection line from the v12eva TRAIN split inserted at a
paragraph break (label 1), so "documentation" alone must not decide; a poisoned README is a real attack path.

Sources are kept apart from the measurement set (bench/heldout/collect_tr_real.py): no wikibooks/wikipedia/wikisource, other
GitHub search queries, and any repository or issue in the measurement files is skipped; windows that share a 10-word sequence
with a measurement or held-out row are dropped.

  python -I docs_data.py fetch                                   # data/docs/docs_raw.jsonl (documents)
  python -I docs_data.py rows                                    # data/docs/docs_rows.jsonl (held-out row format)
  node ../bench/heldout/score.mjs --rows data/docs/docs_rows.jsonl --dump data/docs/docs_texts.jsonl --model <any>
  python -I docs_data.py join                                    # data/docs/{train,val}.jsonl and data/v12docs/
"""

import argparse
import base64
import json
import random
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
DATA = HERE / "data"
OUT = DATA / "docs"
MEASURE = [DATA / "hf_new" / "_external_eval" / f for f in ("tr_real_tools.jsonl", "tr_real_issues.jsonl", "en_control.jsonl")]
HELDOUT = HERE.parent / "bench" / "heldout" / "heldout-v1.jsonl"
UA = "mcp-firewall-bench/1.0 (research)"
TR = re.compile(r"[ğışçöüĞİŞÇÖÜ]")
# texts about prompts, models or injections stay out: their labels would be guesswork
AI_TOPIC = re.compile(r"prompt|jailbreak|injection|ignore (all )?previous|system message|chatgpt|openai|\bllm|\bgpt|claude|gemini|"
                      r"yapay zek|asistan|assistant|\bagent|ajan", re.I)


def gh(*args):
    return json.loads(subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", check=True).stdout)


def raw(repo, branch, path):
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def po_text(src):
    """msgstr strings of a gettext file, joined as paragraphs (python-docs-tr)."""
    out, cur, on = [], [], False
    for line in src.splitlines():
        if line.startswith("msgstr "):
            on, cur = True, [line[7:]]
        elif on and line.startswith('"'):
            cur.append(line)
        else:
            if on:
                s = "".join(json.loads(x) if x.startswith('"') else "" for x in cur)
                if s.strip():
                    out.append(s)
            on = False
    return "\n\n".join(out)


def repo_docs(repo, branch, prefixes, exts, limit, seed, lang):
    tree = gh("api", f"repos/{repo}/git/trees/{branch}?recursive=1")["tree"]
    paths = [t["path"] for t in tree if t["type"] == "blob" and t["path"].endswith(exts) and t["path"].startswith(prefixes)]
    random.Random(seed).shuffle(paths)
    docs = []
    for p in paths[:limit]:
        try:
            src = raw(repo, branch, p)
        except Exception as e:  # noqa: BLE001
            print("  skip", p, e, file=sys.stderr)
            continue
        text = po_text(src) if p.endswith(".po") else src
        docs.append({"source": f"{repo}/{p}", "kind": "docs", "lang": lang, "text": text})
        time.sleep(0.05)
    print(f"{repo}: {len(docs)} documents", file=sys.stderr)
    return docs


def measured():
    repos, urls = set(), set()
    for f in MEASURE:
        for l in open(f, encoding="utf-8"):
            u = json.loads(l)["source"]
            urls.add(u)
            m = re.match(r"https://github.com/([^/]+/[^/]+)", u)
            if m:
                repos.add(m.group(1).lower())
    return repos, urls


def readmes(queries, n, turkish, skip):
    out, seen = [], set(skip)
    for q in queries:
        try:
            items = gh("api", "-X", "GET", "search/repositories", "-f", f"q={q} in:readme", "-f", "per_page=40", "--jq", ".items")
        except subprocess.CalledProcessError as e:
            print("  gh failed", q, e.stderr[:120], file=sys.stderr)
            continue
        time.sleep(2.5)
        for r in items:
            name = r["full_name"].lower()
            if name in seen:
                continue
            seen.add(name)
            try:
                text = base64.b64decode(gh("api", f"repos/{r['full_name']}/readme")["content"]).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                continue
            if len(text) < 300 or (turkish and len(TR.findall(text)) < 15) or (not turkish and TR.search(text)):
                continue
            out.append({"source": f"https://github.com/{r['full_name']}", "kind": "readme", "lang": "tr" if turkish else "en", "text": text})
            if len(out) >= n:
                return out
    return out


def issues(queries, n, skip):
    out, seen = [], set(skip)
    for q in queries:
        try:
            items = gh("api", "-X", "GET", "search/issues", "-f", f"q={q} in:body is:issue", "-f", "per_page=50", "--jq", ".items")
        except subprocess.CalledProcessError as e:
            print("  gh failed", q, e.stderr[:120], file=sys.stderr)
            continue
        time.sleep(2.5)
        for it in items:
            body = (it.get("body") or "").strip()
            if it["html_url"] in seen or len(body) < 150 or not TR.search(body):
                continue
            seen.add(it["html_url"])
            out.append({"source": it["html_url"], "kind": "issue", "lang": "tr", "text": f"{it['title']}\n\n{body}"})
        if len(out) >= n:
            break
    return out[:n]


def fetch(_args):
    OUT.mkdir(parents=True, exist_ok=True)
    repos, urls = measured()
    docs = []
    docs += repo_docs("reactjs/tr.react.dev", "main", ("src/content/learn", "src/content/reference"), (".md",), 180, 1, "tr")
    docs += repo_docs("python/python-docs-tr", "3.12", ("tutorial", "howto", "faq", "using", "library", "installing"), (".po",), 180, 2, "tr")
    docs += repo_docs("laravel-tr/docs", "master", ("",), (".md",), 120, 3, "tr")
    docs += repo_docs("reactjs/react.dev", "main", ("src/content/learn", "src/content/reference"), (".md",), 120, 4, "en")
    docs += readmes(["nasıl kullanılır", "kullanım kılavuzu", "ders notları", "staj projesi", "discord botu", "eğitim serisi",
                     "örnek proje", "masaüstü uygulaması", "otomasyon", "mobil uygulama"], 300, True, repos)
    docs += readmes(["getting started", "quick start", "tutorial project", "course project", "cli tool", "self-hosted",
                     "starter template", "homework"], 200, False, repos)
    docs += issues(["sorun yaşıyorum", "hata veriyor", "neden olmuyor", "rica ediyorum", "özellik isteği", "destek istiyorum",
                    "yardım lazım", "bir sorum var", "nasıl düzeltebilirim"], 300, urls)
    with open(OUT / "docs_raw.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for d in docs:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    print(f"wrote {len(docs)} documents", file=sys.stderr)


def windows(text, size=1500, cap=4):
    """Paragraph-aligned windows of about `size` characters, at most `cap` per document."""
    paras, out, cur = [p for p in re.split(r"\n\s*\n", text) if p.strip()], [], ""
    for p in paras:
        if cur and len(cur) + len(p) > size:
            out.append(cur)
            cur = ""
        cur = (cur + "\n\n" + p) if cur else p[: size * 2]
    if cur:
        out.append(cur)
    return [w for w in out if len(w) >= 300][:cap]


def shingles(text, k=10):
    w = re.findall(r"\w+", text.lower())
    return {" ".join(w[i:i + k]) for i in range(max(0, len(w) - k + 1))}


# injection sources only; chat-style goal hijacks (deepset, jackhhao), task prompts and machine translations into other languages
# do not stand for a line planted in a document
ATTACK_SOURCES = {"tr_1k", "lakera", "devvoice_tr", "devvoice_en", "tr_berat", "lakera+mt_tr", "dev_tr", "dev_en", "injecagent+mt_tr",
                  "eva_prompt_injection", "eva_indirect_prompt_injection"}


def attack_lines(lang, rng, n):
    """Short injection texts from the v12eva TRAIN split only."""
    out = []
    for l in open(DATA / "v12eva" / "train.jsonl", encoding="utf-8"):
        r = json.loads(l)
        t = r["text"].strip()
        if r["label"] != 1 or not 40 <= len(t) <= 300 or "\n" in t or t.startswith(("[", "{", "<")):
            continue
        if (lang == "tr") != bool(TR.search(t)) or r.get("source") not in ATTACK_SOURCES:
            continue
        out.append(t)
    rng.shuffle(out)
    return out[:n]


def rows(args):
    rng = random.Random(13)
    block = set()
    for f in MEASURE + [HELDOUT]:
        for l in open(f, encoding="utf-8"):
            r = json.loads(l)
            block |= shingles(str(r.get("text") or r.get("definition") or ""))
    docs = [json.loads(l) for l in open(OUT / "docs_raw.jsonl", encoding="utf-8")]
    ben, dropped_ai, dropped_overlap = [], 0, 0
    for di, d in enumerate(docs):
        for wi, w in enumerate(windows(d["text"])):
            if AI_TOPIC.search(w):
                dropped_ai += 1
                continue
            if shingles(w) & block:
                dropped_overlap += 1
                continue
            # language by content, not by repository: translation repos keep untranslated pages
            lang = "tr" if len(TR.findall(w)) >= 10 else "en"
            ben.append({"doc": di, "w": w, "lang": lang, "kind": d["kind"], "source": d["source"]})
    rng.shuffle(ben)
    want = {"tr": args.tr, "en": args.en}
    keep = [b for lang in ("tr", "en") for b in [x for x in ben if x["lang"] == lang][: want[lang]]]
    atk = {lang: attack_lines(lang, rng, len(keep)) for lang in ("tr", "en")}
    out = []
    for i, b in enumerate(keep):
        base = {"channel": "output", "kind": "tool_result", "lang": b["lang"], "carrier": b["kind"], "source": b["source"], "doc": b["doc"]}
        out.append({**base, "id": f"DOC-{i:05d}", "cls": f"doc_{b['kind']}", "label": 0, "text": b["w"]})
        if rng.random() < args.twin and atk[b["lang"]]:
            paras = b["w"].split("\n\n")
            # insert within the first ~900 characters so the line survives the 512-token cut in train.py
            cum, ok = 0, [0]
            for k, p in enumerate(paras[:-1], 1):
                cum += len(p) + 2
                if cum > 900:
                    break
                ok.append(k)
            pos = rng.choice(ok)
            text = "\n\n".join(paras[:pos] + [atk[b["lang"]].pop()] + paras[pos:])
            out.append({**base, "id": f"DOC-{i:05d}-atk", "cls": f"doc_{b['kind']}_attack", "label": 1, "text": text, "pair": f"DOC-{i:05d}"})
    with open(OUT / "docs_rows.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    from collections import Counter
    print(f"windows {len(ben)} (dropped: AI topic {dropped_ai}, overlap with measurement/held-out {dropped_overlap})", file=sys.stderr)
    print(f"rows {len(out)}: {Counter((r['lang'], r['carrier'], r['label']) for r in out)}", file=sys.stderr)


def join(_args):
    rows_ = {r["id"]: r for r in (json.loads(l) for l in open(OUT / "docs_rows.jsonl", encoding="utf-8"))}
    texts = [json.loads(l) for l in open(OUT / "docs_texts.jsonl", encoding="utf-8")]
    docs = sorted({r["doc"] for r in rows_.values()})
    random.Random(7).shuffle(docs)
    val_docs = set(docs[: max(1, len(docs) // 12)])  # split by document so a window's twin never sits on the other side
    split = {"train": [], "val": []}
    for t in texts:
        r = rows_[t["id"]]
        split["val" if r["doc"] in val_docs else "train"].append({"text": t["text"], "label": r["label"], "source": f"docs_{r['cls']}"})
    for k, v in split.items():
        with open(OUT / f"{k}.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for r in v:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    out = DATA / "v12docs"
    out.mkdir(exist_ok=True)

    def lines(p):
        return [l if l.endswith("\n") else l + "\n" for l in open(p, encoding="utf-8") if l.strip()]

    for k in ("train", "val"):
        parts = [lines(DATA / "v12eva" / f"{k}.jsonl"), lines(OUT / f"{k}.jsonl")]
        with open(out / f"{k}.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for p in parts:
                f.writelines(p)
        print(f"v12docs/{k}: v12eva {len(parts[0])} + docs {len(parts[1])}", file=sys.stderr)
    (out / "test.jsonl").write_bytes((DATA / "v12eva" / "test.jsonl").read_bytes())


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch")
    r = sub.add_parser("rows")
    r.add_argument("--tr", type=int, default=2400)
    r.add_argument("--en", type=int, default=1200)
    r.add_argument("--twin", type=float, default=0.35)
    sub.add_parser("join")
    a = ap.parse_args()
    {"fetch": fetch, "rows": rows, "join": join}[a.cmd](a)


if __name__ == "__main__":
    main()
