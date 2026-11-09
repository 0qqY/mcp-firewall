# bench/: yayımlanmış benchmark'larla ölçüm betikleri

Bu klasör, [docs/benchmark-karsilastirmasi.md](../docs/benchmark-karsilastirmasi.md) içindeki sayıları üreten betikleri içerir.
Üçüncü taraf kod **çalıştırılmaz**: benchmark depoları yalnızca veri kaynağı olarak okunur, çalıştırıcılar ve puanlayıcılar bu depodaki kendi
kodumuzdur. İndirilen depoları her biri için ayrı, boş bir klasöre alın ve betiklere yolu argüman olarak verin.

## aeb/: Agent Egress Bench, MCP vakaları

Ölçülen sürüm: [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench) commit `7339fef95630ce811f66aa39c7bab879d9f9e6e7`
(korpus v2.16.0). 270 vakanın MCP biçimli 87'si çalıştırılır (65 `mcp_stdio`, 22 `mcp_http`); kalanlar HTTP çıkış vekili vakalarıdır.

```bash
npm run build
node bench/aeb/run.mjs --aeb <aeb deposu> --cli dist/src/cli.js --project . \
     --profile <defaults|installed|example-ml|example-ml-block> --out <çıktı>/<profil> [--transport stdio|http|all] [--filter <regex>] [--concurrency 2]
python -I bench/aeb/pipelock_subset.py <aeb deposu> <çıktı>/pipelock_subset.json
python -I bench/aeb/aggregate.py <çıktı> <çıktı>/pipelock_subset.json > tablolar.md
```

- **Profiller:** `defaults` (politika dosyası yok), `installed` (`~/.mcp-firewall/policy-genel.yaml`; yalnızca model yolu mutlak yapılır,
  masaüstü bildirimi kapatılır), `example-ml` (`policy.example.yaml`, yalnızca `ml.enabled: true` ve mutlak model yolu), `example-ml-block`
  (öncekine ek olarak `dlp.action: block`). `probe-taint` skor için değil boşluk sınıflandırması içindir (`example-ml-block` + `get_env`
  kaynağı + oturum modunda `fetch` sink'i; yalnızca `--filter '^mcp-chain-'` ile). Her düzenleme uygulanmazsa çalıştırıcı durur.
  Yardımcılar: `fails.py` (başarısız vakalar), `inspect_case.py` (yük ile iletilen içerik), `decode_probe.mjs` (derlenmiş çözücüyü dener),
  `diff_runs.py` ve `diff_table.py` (aynı yapılandırmanın iki koşusunu, örneğin bir düzeltmeden önce ve sonra, vaka vaka ve profil profil karşılaştırır).
- **Nasıl çalışır:** AEB'nin `docs/RUNNER.md` sözleşmesi izlenir. Çalıştırıcıya ait bir üst akış dinleyicisi (stdio için TCP, HTTP için HTTP) aldığı
  her mesajı kaydeder ve vakadaki yanıtı verir. `mcp_stdio` vakalarında güvenlik duvarı CLI'si, dinleyiciye bağlanan `bridge.mjs` köprüsünün önünde
  çalışır; `mcp_http` vakalarında HTTP gateway'i kullanılır (taşıma değiştirilmez). **İzin** için istek üst akışa değişmeden ulaşmalı; **engel** için
  güvenlik duvarının atfedilebilir yapısal reddi gerekir (`Blocked by Tuuf MCP Firewall` JSON-RPC hatası ya da `[Tuuf MCP Firewall] Blocked`
  `isError` sonucu). Maskeleyerek/silerek ileten davranış ayrı kovadır (`modified`); katı skorda engel sayılmaz, gevşek skorda sayılır.
- **Yalıtım:** her vaka yeni bir güvenlik duvarı süreci, yeni pin dosyası ve benzersiz `MCP_FIREWALL_SESSION` ile çalışır; sürecin
  `USERPROFILE`/`HOME` değeri vaka klasörüdür, böylece gerçek `~/.mcp-firewall` denetim kaydına ve pin dosyasına hiçbir şey yazılmaz
  (koşu sonunda gerçek kayıtta `"server":"aeb"` satırı sayısı kontrol edilir, artmışsa çıkış kodu 3 olur).
- **Bu resmî bir AEB sonucu değildir:** resmî Go çalıştırıcısı, imzalı kanıt paketi ve puanlama sürümü 2.8'in her kuralı uygulanmadı.
  Sonuçlar bu çalıştırıcıya, bu yapılandırmalara ve bu sürüme özgüdür.

## bipia/: BIPIA eşleşmiş kümesi (Liu 2026 yöntemi)

Kaynaklar: [BIPIA](https://github.com/microsoft/BIPIA) commit `a004b69ec0dd446e0afd461d98cb5e96e120a5d0` ve
[benign-instruction-bench](https://github.com/lzwhehe/benign-instruction-bench) commit `5d0ae7c438a7b01be2ac0a2e8bc943e45c8f851f`
(yalnızca `results/normalized_probs_bipia.json` ve `analysis/` tanımları okunur). Çalışma klasörü `<B>` altında: `home/agentsec/BIPIA`, `repo`.

```bash
python -I bench/bipia/build_bipia_mine.py <B>/home/agentsec/BIPIA/benchmark <B>/build/bipia_pairs.jsonl   # 1200 zararsız + 2435 enjekte (test saldırıları)
python -I bench/bipia/score_views.py --training training --build <B>/build --model <model>/best --out <B>/scores/<ad> --sets bipia_pairs   # GPU/CPU, ürün + ham görünüm
python -I bench/bipia/score_onnx_protectai.py --model-dir models/protectai-deberta-v3-pi-v2 --pairs <B>/build/bipia_pairs.jsonl --out <B>/scores/protectai_v2_bipia --test-attacks-only
python -I bench/bipia/report_bipia.py <B> training
# ürün görünümünün (mlview.py) derlenmiş TypeScript ile aynı olduğunun kanıtı:
node bench/bipia/check_port_node.mjs dist/src/ml/classifier.js <B>/build/bipia_pairs.jsonl <B>/build/port_check_node.json
python -I bench/bipia/check_port_py.py <B>/build/bipia_pairs.jsonl <B>/build/port_check_node.json
```

`product` görünümü güvenlik duvarının gördüğü metni (`extractMlText` + 1500 karakterlik pencereler) taklit eder, `raw` görünümü
dedektörlerin makalede gördüğü ham metindir; karşılaştırma için `raw` esas alınmalıdır.
