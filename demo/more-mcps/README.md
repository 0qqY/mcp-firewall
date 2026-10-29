# Ek MCP türleri — firewall arkasında

`demo/filesystem`, `web`, `sql` ve `slack`'e ek olarak beş MCP türü daha, hepsi **yerel mock** (indirme, token,
dış ağ yok). Amaç, firewall'un her koruma katmanını farklı MCP tiplerinde göstermek. Ortak sürücü `_lib.mjs`
sunucuyu gerçek firewall'un (`dist/src/cli.js`) arkasında çalıştırır; üretilen dosyalar her sürücünün yanına
`run-*` adıyla yazılır (`.gitignore`'da).

## Çalıştırma

```bash
npm run build
node demo/more-mcps/gh-run.mjs
node demo/more-mcps/shell-run.mjs
node demo/more-mcps/mail-run.mjs
node demo/more-mcps/docs-run.mjs
node demo/more-mcps/plug-run.mjs
```

ML kullanan demolar için model: `MCP_FIREWALL_MODEL` ile yol verin (varsayılan `./models/mcp-pi-mmbert-soup05-ab2`).
`plug` ML kullanmaz. `docs` ve `plug` rug-pull'u göstermek için sunucuyu **iki kez** çalıştırır (ikincisinde
`RUG=1` ile tanım/şablon sessizce değişir).

## Ne test ediyor

| Demo | MCP türü | Öne çıkan katman(lar) |
|---|---|---|
| `gh-run` | GitHub | **descriptionScan** (zehirli tool açıklaması + gizli Unicode → tool gizlenir), ML (issue injection), DLP (koddaki AWS+GitHub secret), politika (merge/delete reddedilir) |
| `shell-run` | Shell/exec | politika (`rm -rf`, `curl \| sh` argüman reddi), **hiddenText** (çıktıdaki ANSI + zero-width → engellenir), DLP (`.env` dökümü) |
| `mail-run` | E-posta | decoding+ML (gövdede base64 injection), politika (`to` allow-list, harici alıcı reddi), **DLP istek tarafı** (giden metindeki secret maskelenir) |
| `docs-run` | Docs/Prompts | **descriptionScan** (prompt poisoning), **pinning** (sessizce değişen `prompts/get` şablonu → rug-pull engellenir) |
| `plug-run` | Integrations | **pinning** (sessizce değişen tool tanımı → rug-pull, tool gizlenir), **methods.deny** (`resources/*` reddedilir) |

## Not

- Hepsi yerel/denetimli mock'tur; gerçek hesap/üretim değildir. Kalıcılık istemeyen `run-*` çıktıları gitignore'da.
- İlginç bir gözlem: DLP bir secret'i `[REDACTED:…]` ile değiştirince, "key/token" geçen **düz metinde** bu işaret
  ML skorunu yükseltip sonucu tümden bloklayabilir (yapısal veride olmaz). Bu yüzden `mail`/`slack` demolarında
  giden gönderi yalnızca ack döner, metni echo'lamaz.
