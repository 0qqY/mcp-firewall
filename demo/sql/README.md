# SQL MCP — firewall arkasında (kapsamlı test)

Belleğe kurulu bir SQLite veritabanını (Node'un yerleşik `node:sqlite`'ı — ayrı veritabanı gerekmez) tek bir
`query` tool'uyla sunan bir MCP sunucusu. Düşmanca bir seed ile firewall'un tüm katmanlarını bir koşuda dener:
satırlara gömülü injection (açık + base64), satırlardaki çok türlü secret/PII ve tehlikeli SQL.

## Çalıştırma

```bash
npm run build
node demo/sql/run.mjs
```

Model depoda tutulmaz; `MCP_FIREWALL_MODEL` ile yolunu verin (varsayılan `./models/mcp-pi-mmbert-mixraw-ab4-evilsandangels-30`).
Kendi kendine yeter; dış ağ gerekmez.

## Kapsanan 12 sorgu

| Sorgu | Ne test eder | Firewall |
|---|---|---|
| `SELECT … products` | sıradan satırlar | **geçer** |
| `SELECT … tickets id=2` | satırda açık injection | **engellenir** — ML (~1,000) |
| `SELECT … tickets id=3` | satırda **base64** injection | **engellenir** — decoding + ML |
| `SELECT … app_config` | github/aws/slack token + SSH özel anahtar | **maskelenir** — DLP (4 tür) |
| `SELECT … customers` | kredi kartı + TCKN + IBAN | **maskelenir** — DLP (PII) |
| `SELECT … deploy_config` | saklı `.env`, bağlamsal `AWS_SECRET_ACCESS_KEY` | **maskelenir** — DLP (aws_access_key + aws_secret_key) |
| `DROP TABLE …` | şema silme | **engellenir** — politika (istek tarafı) |
| `DELETE FROM …` | veri silme | **engellenir** — politika |
| `UPDATE … SET …` | veri değiştirme | **engellenir** — politika |
| `SELECT 1; DROP …` | stacked ifade | **engellenir** — politika (deseni ikinci ifadede de yakalar) |
| `ATTACH DATABASE …` | dosya ekleme | **engellenir** — politika |
| `SELECT … WHERE … LIKE` | filtreli okuma (kontrol) | **geçer** |

## Notlar

- **Salt-okunur politika:** `query` tool'unun `sql` argümanı `insert/update/delete/drop/alter/truncate/create/replace/attach/detach/pragma/vacuum/reindex`
  için reddedilir; tehlikeli ifade veritabanına hiç ulaşmaz (`tools.rules` → `arguments.sql.deny`, `i` bayrağıyla büyük/küçük harf duyarsız).
- **Bağlamsal AWS gizli anahtarı:** satır JSON olarak döndüğü için gerçek satır sonu `\n` biçiminde kaçışlanır ve
  etikete bir `n` yapışır. Detektörün etiket başındaki `\b` sınırı bunu reddediyordu; kaldırıldı, artık JSON içinde
  kaçışlanmış `.env` bloğundaki `AWS_SECRET_ACCESS_KEY=` değeri de maskeleniyor. (Yakalayan ekleme testi: `test/engine.test.ts`.)
- Bir satıra gizlenmiş talimat ("Supabase destek talebi" sınıfı) sonuç tarafında ML tarafından yakalanır; katmanlar
  birbirini yedekler.
