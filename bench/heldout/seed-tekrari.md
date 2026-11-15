# Seed tekrarı: aynı tarif, farklı seed — 15.11.2026

Soru: önceki turlarda adayların B30'a karşı kaybettiği farklar (docs, gap2, tri) eğitim gürültüsünün dışında mı?
B30'un tarifi verisi değiştirilmeden yeniden koşuldu: ham model `data/v12eva`, `--seed 7` (B30'unki 42), 3 epoch,
~2,5 saat (q8 skorlamasıyla CPU paylaşarak); sonra `soup04-ab4` ile %30 karışım ve ONNX export (PyTorch farkı 0,0000). Bu bir aday değil, ölçüm.
Model yalnız yerelde: `models/mcp-pi-mmbert-mixraw-ab4-evilsandangels-s7-30` (git-ignored).

Eşik 0,3, ürün metin yolu (`bench/heldout/score.mjs`); BIPIA `bench/bipia/score_views.py` + `report_bipia.py`.

| ölçüm | B30 | B30 seed 7 | docs-30 (günlük 110) |
|---|---|---|---|
| held-out v1 recall (/150) | 143 | 141 | 141 |
| held-out v1 false alarm (/183) | 23 | 21 | - |
| ek parametre sınıfı (/37) | 15 | 13 | 11 |
| BIPIA AUROC (ürün) | 0,721 | 0,727 | 0,718 |
| BIPIA recall @%1 FPR (ürün) | 0,247 | 0,237 | 0,204 |
| BIPIA recall @%1 FPR (ham) | 0,236 | 0,207 | 0,194 |
| BIPIA FPR @0,3 (ürün) | 0,209 | 0,428 | 0,163 |
| Türkçe README false alarm (150) | %20,7 | %17,3 | %12,0 |
| HF Türkçe false-alarm benchmark (2.875) | %11,0 | %7,8 | %9,6 |
| gerçek Türkçe issue (150) | %8,0 | %6,7 | - |
| İngilizce kontrol (300) | %7,3 | %9,7 | - |
| gerçek tool tanımı (3.000) | %1,0 | %0,8 | - |

## Ne gösteriyor

- Yalnız seed değişince held-out recall 2, ek parametre sınıfı 2 satır oynuyor. docs-30'un held-out kaybı (143 → 141)
  gürültünün içinde; ek parametre kaybının (15 → 11) yarısı gürültü boyunda.
- BIPIA'da %1 FPR'deki recall ürün görünümünde 0,010, ham görünümde 0,029 oynuyor. docs-30'un düşüşü (0,043 / 0,042)
  bundan büyük; o kayıp büyük olasılıkla gerçek, ama tek bir seed tekrarıyla kesin değil.
- Eşik 0,3'teki kalibrasyon seed'le çok oynuyor: BIPIA FPR 0,209 → 0,428. Sabit eşikte karşılaştırmalar (özellikle BIPIA
  @0,3) adaylar arasında güvenilir değil; eşit FPR / ROC karşılaştırması gerekli.
- HF Türkçe benchmark'ta seed farkı (11,0 → 7,8) docs-30'un kazancından (11,0 → 9,6) büyük: o kazanç gürültü.
  Türkçe README'de docs-30'un kazancı (20,7 → 12,0) seed farkından (→ 17,3) büyük kalıyor.
- Sonuç: aday kararları tek koşuya dayanıyor ve ±2 satırlık farklar karar için yetmiyor. Bir sonraki eğitim turunda her
  tarif en az iki seed ile koşulmalı.

Default **değişmedi** (bu bir ölçümdü). Satır dosyaları git-ignored veriden (`night/`, depoda değil);
BIPIA tablosu: [../bipia/bipia-seed7.txt](../bipia/bipia-seed7.txt), dış set sayımları [seed-tekrari-dis-setler.txt](seed-tekrari-dis-setler.txt).
