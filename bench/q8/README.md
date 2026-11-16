# q8 (int8) model ölçümü — 15.11.2026

Soru: varsayılan model (B30, fp32, 1.174 MB) daha az bellekle aynı kararları verebilir mi? Her firewall proxy'si modeli
ayrı yüklediği için bellek, kullanıcı makinesindeki en büyük yük (günlük 97).

## Varyantlar (`training/quant_probe.py`, onnxruntime dynamic int8)

Held-out v1 (333 satır, eşik 0,3, Python onnxruntime CPU, batch 2) — tablo: [heldout-varyantlar.md](heldout-varyantlar.md)

| graph | dosya MB | peak working set MB | karar farkı (333) |
|---|---|---|---|
| fp32 | 1174 | 2726 | 0 |
| int8-embedding (yalnız embedding tablosu) | 611 | 1590 | 1 |
| int8-all | 294 | 1274 | 17 |
| int8-matmul | 857 | 2399 | 22 |

Yalnız embedding tablosunu (256k token × 768, parametrelerin ~%64'ü) int8 yapmak kararı neredeyse hiç değiştirmiyor;
attention/MLP ağırlıklarını (MatMul) int8 yapmak 14-22 karar değiştiriyor. Önceki export'ların "int8 kararları değiştirdi"
notu `int8-all` içindi.

## Ürün yolu (bench/heldout/score.mjs, transformers.js, firewall'un metin hazırlığı)

`int8-embedding` graph'ı ayrı bir model klasörüne `onnx/model.onnx` olarak kondu ve fp32 ile aynı satırlar skorlandı:

- Dış setler, 7.016 satır ([urun-dis-setler.txt](urun-dis-setler.txt)): Türkçe false-alarm benchmark'ı 2.875, gerçek tool
  tanımı 3.000, gerçek Türkçe tool sonucu 600 + issue 150, İngilizce kontrol 300, sarılmış probe 17, ek parametre sınıfı 74.
  **7 karar farkı**, hepsi zararsız satır ve eşiğin yanında (0,27-0,38): 4'ünde q8'de işaret kalkıyor, 3'ü yeni işaret.
- Standart setler, her birinden rastgele 400 satır, 3.200 satır ([urun-standart-ornek.txt](urun-standart-ornek.txt)):
  **3 karar farkı**, hepsi zararsız satır; 8 setin hiçbirinde yakalanan saldırı sayısı değişmedi.
- Held-out dahil toplam 10.549 satırda 11 karar farkı (%0,10), hiçbiri saldırı satırı değil. En büyük skor farkı 0,164.

## Karar

Gece kuralı "her yerde daha iyi": q8 için bu, fp32 ile aynı kararlar demek. 11 zararsız satırda karar değiştiği için
default ve install **değiştirilmedi**. Fark küçük ve yönsüz (zararsız satırlarda 7 işaret kalkıyor, 4 yeni işaret çıkıyor); bellek
kazancı büyük (peak working set 2,7 → 1,6 GB, dosya 1,17 → 0,61 GB). Opt-in bir seçenek olarak sunulabilir; ölçülmeyenler:
BIPIA, AEB, poligon, Node'da proxy başına gerçek bellek.

## Opt-in olarak eklendi (16.11.2026)

`python -I -X utf8 training/quant_probe.py q8 --model <model>` int8-embedding graph'ını modelin kendi klasörüne
`onnx/model_quantized.onnx` olarak yazar; politikada `ml.dtype: q8` ile yüklenir. Default değişmedi.
Node'da ölçüm (`bench/heldout/score.mjs --dtype fp32|q8`, held-out 333 satır, aynı makine, sırayla): peak resident
memory **2.032 → 1.076 MB**, süre 21 → 20 s, 1 karar farkı (HB-015, zararsız, 0,306 → 0,296), en büyük skor farkı 0,068.
Python'daki ölçümle aynı satır. Bu, tek bir Node sürecinin belleği; çalışan bir proxy'de ölçülmedi. BIPIA, AEB ve
poligon hâlâ ölçülmedi.

Yeniden üretmek: `python -X utf8 quant_probe.py build --model ../models/<B30> --out <dizin>`, sonra
[score_variants.sh](score_variants.sh) ve `node bench/heldout/score.mjs --model <int8-embedding klasörü> --rows <satırlar>`.
Satır dosyaları git-ignored veriden üretildi (`night/q8/rows`, depoda değil).
