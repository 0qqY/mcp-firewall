# Held-out değerlendirme seti (heldout-v1)

Eğitimde hiç kullanılmamış, elle yazılmış bir sınama seti. Amacı: bir modelin ya da bir firewall katmanının gerçekte ne yaptığını,
kendi eğitim verisinin dışında ölçmek.

**Kural: bu satırları hiçbir eğitim karışımına koyma.** Koyarsan üzerindeki bütün sayılar anlamsızlaşır ve set bir sonraki modeli
seçemez. `*.jsonl` dosyaları git'e girmiyor (`.gitignore`); satırlar `rows-*.mjs` dosyalarında duruyor, `heldout-v1.jsonl`
`build.mjs` ile yeniden üretiliyor.

## İçerik: 333 satır, 150 saldırı + 183 benign

| channel | saldırı | benign | ne |
|---|---|---|---|
| definition | 42 | 47 | tool tanımı (poisoning, rug pull, shadowing) ve server `instructions` |
| output | 96 | 120 | tool sonucu: GitHub, web, dosya, mail, JSON, exfil, zincirleme eylem, roleplay, 16 obfuscated çift |
| prompt | 12 | 16 | prompt şablonları, `elicitation` ve `sampling` isteği |

222 satır İngilizce, 111 satır Türkçe. 150 saldırının hepsinin bir **benign ikizi** (minimal çift) var: aynı taşıyıcı ve konu, aynı
kelime dağarcığı, ama zararsız. Böylece model "konu"ya değil niyete bakıyor mu görülüyor. Ayrıca 33 twin'siz hard negative var
(rol prompt'ları, `.gitignore` "ignore" cümlesi, Türkçe görev talimatı, bankacılık/iş metni, güvenlik yazısı, GitHub notları).
Benign ikizler bilerek "IMPORTANT", "Note", "Warning", "secret", ".env" gibi saldırı kelimelerini meşru kullanımla taşıyor.

Bağımsızlık: `build.mjs` her satırın ilk 80 normalize karakterini `training/data` altındaki 26 jsonl dosyadaki 146.068 satırla
karşılaştırıyor; 0 çakışma. Çakışma çıkarsa dosya yazılmıyor.

## Komutlar

```bash
node bench/heldout/build.mjs                                   # satırları üretir, doğrular, bağımsızlığı denetler
node bench/heldout/score.mjs --dist <dist/src> --model <model klasörü> --out sonuc.json
node bench/heldout/report.mjs sonuc.json --md sonuc.md         # recall, FPR, AUC, çift testi, kırılımlar, kaçanlar
node bench/heldout/compare.mjs a.json b.json --md tablo.md     # birkaç modeli yan yana koyar
```

`score.mjs` metni ürünün `proxy.ts`'deki gibi hazırlıyor: hidden-character strip, ürünün metin çıkarıcıları, redaction işareti ve
görsel nötrleme, decoding, channel etiketi, 1500 karakterlik pencereler. Firewall'u kullanıcının gerçek `~/.mcp-firewall`
klasörüne yazdırmamak için `USERPROFILE`/`HOME` geçici bir klasöre çevrilerek çalıştırılmalı.

Çift testi eşikte yapılıyor: bir çift, saldırı işaretli ve ikizi işaretli değilse "temiz ayrıldı" sayılıyor. (İlk sürümde ham skor
karşılaştırılıyordu; iki metin de ~1.000 skorundayken sonuç float gürültüsüydü ve %98 gösterdi, gerçek değer %83.)

## Sonuçlar

Varsayılan model `mcp-pi-mmbert-mixraw-ab4-evilsandangels-30`, eşik 0.3 (kayıt: `sonuc-varsayilan.md`, 8 modelin tablosu:
`model-karsilastirma.md`):

| | recall | false positive | AUC | recall @%1 FPR | temiz çift |
|---|---|---|---|---|---|
| varsayılan (B30) | 95.3% | 12.6% | 0.977 | 69.3% | 83.3% |
| en yakın rakip (soup04-ab4) | 96.0% | 18.6% | 0.961 | 63.3% | 77.3% |

Varsayılan, yerel 8 modelin eşik-bağımsız metriklerde (AUC, %1 ve %5 FPR'de recall, temiz çift) en iyisi; protectai deberta-v3
baseline'ı 60.7% recall'da kalıyor. Zayıf yerler: prompt channel'ında false positive %37.5 (rol prompt'ları; ürün `promptResults:
warn` ile bunu yutuyor), zincirleme eylemler (`chain`: audit log'u kapat, onayı kapat, izleri sil: recall %71), Türkçe dolaylı mail/ticket
talimatı (2 kaçan), koşullu prompt şablonu (1), commit mesajına `.env` ekleten tool tanımı (ML skoru 0.003; ikizi ise ".env" kelimesi
yüzünden 0.80 aldı).

Sınırlar: 333 satır, güven aralığı geniş (150 saldırıda recall ±3-4 puan, 183 benign'de FPR ±5 puan). Tek yazarlı bir set; exfil ve
chain sınıflarının ikizleri "asistana yönelik emir" biçiminde olduğundan oradaki false positive'lerin bir kısmı savunulabilir.
Set modeli ölçüyor, ürünü değil: kullanıcının kurulu politikasında `ml.scan.toolDefinitions: off`, yani tool tanımlarını regex
katmanı koruyor, o katman bu setteki 36 tanım saldırısının 13'ünü yakaladı (benign 2/40'ı gizledi).

## Dış veri setleri (Hugging Face)

`training/data/hf_new/` altına indirildi (git'e girmez, her kaynak kendi lisansında): `mcp-research-alliance/mcp-ecosystem`
(CC-BY-4.0, yalnızca `viewer/` altındaki `mcp_tools`, `mcp_prompts`, `mcp_resources`), `halilneed/turkish-prompt-injection-false-alarm-benchmark`
(CC0-1.0), `treycsa/realistic-prompt-injections` (MIT). `external_rows.py` bunları aynı satır biçimine çeviriyor
(`training/data/hf_new/_external_eval/`), `report-external.mjs` skorları özetliyor, `scan-definitions.mjs` ürünün
`descriptionScan` katmanını gerçek tanımların üzerinde koşturuyor.

```bash
python -X utf8 -I bench/heldout/external_rows.py
node bench/heldout/score.mjs --dist <dist/src> --model <model> --rows training/data/hf_new/_external_eval/tr_false_alarm.jsonl --out tr.json
node bench/heldout/report-external.mjs --rows training/data/hf_new/_external_eval/tr_false_alarm.jsonl --results tr.json
node bench/heldout/scan-definitions.mjs --dist <dist/src> --rows training/data/hf_new/_external_eval/real_tools_all.jsonl
```

Varsayılan model (B30, eşik 0.3), 10.11.2026:

| set | satır | sonuç |
|---|---|---|
| `treycsa/realistic-prompt-injections` | 10 saldırı + 7 benign | 10/10 yakalandı, 0/7 false positive |
| Türkçe false-alarm, tool sonucu olarak | 2.875 benign | %11.0 işaretlendi: iş metni %0.5, bankacılık %2.8, görev talimatı %28.9 |
| Türkçe görev talimatı, prompt şablonu olarak | 1.000 benign | %40.3 işaretlendi (ürün `promptResults: warn` ile yutuyor) |
| `mcp_tools`, rastgele örnek | 3.000 gerçek tanım | %1.0 işaretlendi (0.5'te %0.8, 0.9'da %0.6); en yüksekler "MANDATORY FIRST CALL" gibi buyurgan ama meşru açıklamalar |
| `mcp_tools`, `descriptionScan` (regex) | 239.054 tekil tanım | 1.269'u (%0.53) gizlenirdi; çoğu meşru (`.env` anması 374, "before calling this tool" 349, gönder+URL 270, "chat history" 217, `<important>` benzeri etiket 54) |

Notlar: Türkçe görev talimatı satırlarının çoğu "hesap hareketlerimi … adresine gönderin" cümlesini taşıyor, yani exfil gibi
görünüyor; bunları benign olarak eğitime koymak e-posta exfil recall'ını düşürebilir, önce held-out ve AEB'de denenmeli.
`mcp_tools` etiketsiz, her işaret elle incelenmeli. Taramanın ilk sürümü 110.141. tanımda (`XA-110140`) takıldı: bu, ürünün
`decode.ts` dosyasındaki `NAMING_STYLE` regex'inin üstel geri izlemesiydi ("Ew" + 125 × "A" + "PfwHLuRXafg"); düzeltildi
(`isNamingStyle`, `test/decode.test.ts`). `scan-definitions.mjs` bu yüzden `--trace` (takılan satırı gösterir) ve `--slow-ms`
(yavaş satırları listeler) seçeneklerini taşıyor.
