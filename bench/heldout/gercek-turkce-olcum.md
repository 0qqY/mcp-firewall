# Gerçek Türkçe tool sonuçlarında false alarm (13.11.2026)

Soru: HF'deki Türkçe false alarm benchmark'ı (`halilneed/...`, görev talimatlarında %28,9) chat guardrail'i için yapılmış;
gerçek MCP tool sonuçlarında durum ne?

**Veri:** `collect_tr_real.py`, 1050 gerçek metin, hepsi zararsız kabul edildi ve işaretlenenlerin hepsi elle okundu.
fetch sunucusu gibi en çok 5000 karakter. Metinler git'e girmez (`training/data/hf_new/_external_eval/tr_real_*.jsonl`,
`en_control.jsonl`; lisanslar karışık: Wikipedia CC-BY-SA, README'ler repo repo).

**Model:** default B30 (`mixraw-ab4-evilsandangels-30`), ürünün metin hazırlığıyla (`score.mjs`), 1500 karakter pencere.

| kaynak | n | ≥0,3 | ≥0,9 | İngilizce karşılığı (≥0,3) |
|---|---|---|---|---|
| tr.wikipedia rastgele madde | 150 | 1,3% | 0,7% | - |
| tr.wikisource (kanun, belge) | 150 | 1,3% | 0,7% | - |
| tr.wikibooks (ders, tarif, kurulum) | 150 | **7,3%** | 4,0% | en.wikibooks 1,3% (≥0,9: 0,7%) |
| Türkçe GitHub README | 150 | **20,7%** | 11,3% | İngilizce README 13,3% (≥0,9: 6,0%) |
| Türkçe GitHub issue | 150 | 8,0% | 5,3% | - |
| **toplam Türkçe** | 750 | 7,7% | 4,4% | |

İşaretlenen 58 Türkçe ve 22 İngilizce metnin hepsi elle okundu; hiçbiri saldırı değil.

## Ne çıktı
- **Sorun gerçek, ama "Türkçe" sorunu değil, "talimat metni" sorunu.** Ansiklopedi ve kanun metni temiz (%1,3).
  Okuyana emir kipiyle hitap eden metinler alarm veriyor: kurulum rehberi ("şu komutu çalıştırın", "private key'leri
  saklayın"), ödev açıklaması ("bu hafta ... geliştireceksiniz"), programlama dersi ("bir dosya oluşturun").
  İngilizce README'lerde de %13,3.
- **Türkçe bunu büyütüyor:** aynı tür metinde ders kitabı 5,6 kat (7,3 / 1,3), README 1,6 kat (20,7 / 13,3).
- **Threshold çözmez:** alarmların çoğu 0,9'un üstünde, model emin.
- **Kurulu policy'de etkisi büyük:** `policy-genel.yaml`'da `toolResults: block`. fetch ya da GitHub üzerinden bir
  Türkçe README okuyan ajan kabaca 5'te 1 bloklanır.
- Gerçek audit log'da 7 Kasım'dan beri ML block olmaması bu tür metnin okunmamasından; ölçüm bunu gösteriyor.

## Önceki denemelerden farkı
Önceki eğitim turlarında negatif veri "görev talimatı" ve rol prompt'larıydı: AI'a verilen emirler. Onları zararsız
öğretmek saldırıyla aynı şekli öğretmek demekti, recall düştü. Buradaki metinler AI'a değil, **insana** emir veriyor.
Bu fark eğitimle öğretilebilir görünüyor; ama zehirli README de gerçek bir saldırı yolu, bu yüzden her aday held-out,
AEB ve poligonda ölçülmeli.
