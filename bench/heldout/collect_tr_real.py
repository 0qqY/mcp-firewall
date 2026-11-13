"""Collects REAL Turkish texts the way MCP tools would return them, to measure Turkish false alarms on real tool results
(the HF Turkish false-alarm benchmark is built for chat input, not for tool output).

Sources (all public, no user data sent anywhere):
  wiki      tr.wikipedia random articles        (fetch-style page text)
  vikikitap tr.wikibooks random pages           (how-to / recipes: imperative text)
  vikikaynak tr.wikisource random pages         (laws, regulations, old texts)
  issue     Turkish GitHub issues via `gh`      (title + body, like the GitHub MCP issue tools)
  readme    READMEs of Turkish GitHub repos     (install instructions: imperative text)

Every row is labelled benign (0); flagged rows must be reviewed by hand, since a real page can contain a real injection.
usage: python -I bench/heldout/collect_tr_real.py --out <rows.jsonl> [--per 150] [--only wiki,issue]
"""
import argparse
import base64
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

UA = "mcp-firewall-bench/1.0 (research; contact via repository)"
MAX = 5000  # mcp_server_fetch returns at most 5000 characters per call by default
TR = re.compile(r"[ğışçöüĞİŞÇÖÜ]")


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def wiki_random(host, n, ns=0):
    out, seen = [], set()
    while len(out) < n:
        q = urllib.parse.urlencode({"action": "query", "format": "json", "generator": "random", "grnnamespace": ns, "grnlimit": 20,
                                    "prop": "extracts", "explaintext": 1, "exlimit": 20})
        try:
            d = get_json(f"https://{host}/w/api.php?{q}")
        except Exception as e:  # noqa: BLE001
            print("  retry", host, e, file=sys.stderr)
            time.sleep(3)
            continue
        for p in (d.get("query", {}).get("pages", {}) or {}).values():
            t = (p.get("extract") or "").strip()
            if p["pageid"] in seen or len(t) < 200:
                continue
            seen.add(p["pageid"])
            out.append((f"{p['title']}\n\n{t}"[:MAX], f"https://{host}/?curid={p['pageid']}"))
        time.sleep(0.5)
    return out[:n]


def gh(*args):
    return json.loads(subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", check=True).stdout)


def issues(n):
    out, seen = [], set()
    for q in ["hata alıyorum", "çalışmıyor", "nasıl yapabilirim", "yardımcı olur musunuz", "öneri", "güncelleme sonrası",
              "kurulum sorunu", "teşekkürler", "eklenebilir mi", "giriş yapamıyorum"]:
        try:
            items = gh("api", "-X", "GET", "search/issues", "-f", f"q={q} in:body is:issue", "-f", "per_page=30", "--jq", ".items")
        except subprocess.CalledProcessError as e:
            print("  gh failed", q, e.stderr[:200], file=sys.stderr)
            continue
        for it in items:
            body = (it.get("body") or "").strip()
            if it["html_url"] in seen or len(body) < 80 or not TR.search(body):
                continue
            seen.add(it["html_url"])
            out.append((f"{it['title']}\n\n{body}"[:MAX], it["html_url"]))
        time.sleep(2.5)  # search API: 30 requests per minute
        if len(out) >= n:
            break
    return out[:n]


TR_README_Q = ["türkçe", "kurulum", "proje ödevi", "bitirme projesi", "web sitesi", "uygulama geliştirme", "veritabanı", "bot"]
EN_README_Q = ["installation guide", "node setup guide", "bootcamp homework", "final project", "website", "app development", "database", "bot"]


def readmes(n, queries=TR_README_Q, turkish=True):
    out, seen = [], set()
    for q in queries:
        try:
            repos = gh("api", "-X", "GET", "search/repositories", "-f", f"q={q} in:readme", "-f", "per_page=30", "--jq", ".items")
        except subprocess.CalledProcessError as e:
            print("  gh failed", q, e.stderr[:200], file=sys.stderr)
            continue
        time.sleep(2.5)
        for r in repos:
            name = r["full_name"]
            if name in seen:
                continue
            seen.add(name)
            try:
                d = gh("api", f"repos/{name}/readme")
                text = base64.b64decode(d["content"]).decode("utf-8", "replace").strip()
            except Exception:  # noqa: BLE001
                continue
            if len(text) < 200 or (turkish and len(TR.findall(text)) < 15) or (not turkish and TR.search(text)):
                continue
            out.append((text[:MAX], f"https://github.com/{name}"))
            if len(out) >= n:
                return out
    return out[:n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--per", type=int, default=150)
    ap.add_argument("--only", help="comma-separated source names")
    a = ap.parse_args()
    sources = {
        "wiki": lambda: wiki_random("tr.wikipedia.org", a.per),
        "vikikitap": lambda: wiki_random("tr.wikibooks.org", a.per),
        "vikikaynak": lambda: wiki_random("tr.wikisource.org", a.per),
        "issue": lambda: issues(a.per),
        "readme": lambda: readmes(a.per),
        # English control sets of the same kinds (not Turkish): is the problem Turkish or instructional text in general?
        "en_wikibooks": lambda: wiki_random("en.wikibooks.org", a.per),
        "en_readme": lambda: readmes(a.per, EN_README_Q, turkish=False),
    }
    if a.only:
        sources = {k: v for k, v in sources.items() if k in a.only.split(",")}
    rows = []
    for name, fn in sources.items():
        got = fn()
        print(f"{name}: {len(got)}", file=sys.stderr)
        for i, (text, url) in enumerate(got):
            rows.append({"id": f"TRR-{name}-{i:04d}", "source": url, "channel": "output", "kind": "tool_result", "cls": name,
                         "lang": "en" if name.startswith("en_") else "tr", "carrier": name, "label": 0, "text": text})
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} rows to {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
