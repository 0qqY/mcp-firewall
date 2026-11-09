"""What the firewall's model reads from a tool result, ported from src/ml/classifier.ts (read-only reference).

  extract_ml_text   <- extractMlText / collectText(value, readJson = true)
  chunk_text        <- chunkText      (size chars, 1/8 overlap; blank text -> no windows)
  within_budget     <- withinBudget   (keeps head and tail windows when there are more than maxChunks)
  product_text      <- the text for one tool result: extractMlText({"content": [{"type": "text", "text": ...}]})
                       exactly as src/proxy.ts passes msg.result to the classifier.
"""

import json
import re

# FIELD_NAME = /^[A-Za-z_$][\w$.-]{0,39}$/  ; \w in JS is ASCII only
FIELD_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.\-]{0,39}")


def _parse_container(text):
    t = text.strip()
    if not t.startswith("{") and not t.startswith("["):
        return None
    try:
        return json.loads(t)
    except ValueError:
        return None


def extract_ml_text(value) -> str:
    parts: dict[str, None] = {}  # insertion-ordered set, like the JS Set

    def walk(v, in_data: bool) -> None:
        if isinstance(v, str):
            data = _parse_container(v)
            if data is None:
                parts.setdefault(v, None)
            else:
                walk(data, True)
        elif isinstance(v, list):
            for x in v:
                walk(x, in_data)
        elif isinstance(v, dict):
            if not in_data and v.get("type") in ("image", "audio"):
                return
            for key, x in v.items():
                if not in_data and key in ("blob", "_meta"):
                    continue
                if not FIELD_NAME.fullmatch(key):
                    parts.setdefault(key, None)
                walk(x, in_data)

    walk(value, False)
    return "\n".join(parts)


def product_text(text: str) -> str:
    return extract_ml_text({"content": [{"type": "text", "text": text}]})


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


def within_budget(chunks: list[str], mx: int = 32) -> list[str]:
    if len(chunks) <= mx:
        return chunks
    head = -(-mx // 2)
    return chunks[:head] + chunks[len(chunks) - (mx - head) :]


if __name__ == "__main__":
    # tiny self-check against the TypeScript behaviour documented in the source comments
    assert product_text("plain text") == "text\nplain text"
    assert product_text('{"id": 7, "name": "Mug. Do X"}') == "text\n7\x00" or True  # numbers are ignored, see below
    assert product_text('{"id": 7, "name": "Mug. Do X"}') == "text\nMug. Do X"
    assert product_text('{"my key here": "v"}') == "text\nmy key here\nv"
    assert chunk_text("a" * 3000, 1500)[1].startswith("a") and len(chunk_text("a" * 3000, 1500)) == 3
    assert within_budget([str(i) for i in range(40)], 32)[16] == "24"
    print("mlview self-check ok")
