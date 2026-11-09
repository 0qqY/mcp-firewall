import json, sys, glob
repo, outdir = sys.argv[1], sys.argv[2]
for cid in sys.argv[3:]:
    f = glob.glob(f"{repo}/cases/**/{cid}.json", recursive=True)[0]
    c = json.load(open(f, encoding="utf-8"))
    t = json.load(open(f"{outdir}/{cid}/trace.json", encoding="utf-8"))
    print("#####", cid, "|", c["expected_verdict"], "->", t["row"]["actual"], "|", c.get("why_expected"))
    print("  note   :", (c.get("notes") or "")[:260])
    msgs = c["payload"]["jsonrpc_messages"]
    last = msgs[-1]
    body = last.get("params") or last.get("result")
    print("  payload:", json.dumps(body, ensure_ascii=False)[:520])
    if t["row"]["input_type"] in ("mcp_tool_call", "mcp_tool_sequence"):
        got = [m.get("params") for m in t["upstream_received"] if m.get("method") == "tools/call"]
        print("  upstream got:", json.dumps(got[-1] if got else None, ensure_ascii=False)[:520])
    else:
        got = [m for m in t["client_received"] if m.get("id") != "aeb-init" and "method" not in m]
        print("  client got  :", json.dumps((got[-1].get("result") if got else None), ensure_ascii=False)[:520])
