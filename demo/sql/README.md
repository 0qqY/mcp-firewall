# SQL MCP — firewall arkasında

Belleğe kurulu bir SQLite veritabanını (Node'un yerleşik `node:sqlite`'ı — ayrı veritabanı gerekmez) tek bir
`query` tool'uyla sunan bir MCP sunucusu. Firewall'un üç katmanını aynı anda gösterir: tool sonucundaki dolaylı
injection (ML), tool sonucundaki secret (DLP) ve tehlikeli SQL (istek tarafı politika).

## Çalıştırma

```bash
npm run build
node demo/sql/run.mjs
```

Model depoda tutulmaz; `MCP_FIREWALL_MODEL` ile yolunu verin (varsayılan `./models/mcp-pi-mmbert-soup05-ab2`).
Kendi kendine yeter; dış ağ gerekmez.

## Beklenen sonuç

| Sorgu | Ne test eder | Firewall |
|---|---|---|
| `SELECT … FROM products` | sıradan satırlar | **geçer** |
| `SELECT … FROM tickets` | bir satırın gövdesine gömülü injection | **engellenir** — ML, tool sonucunu tarar (~1,000) |
| `SELECT … FROM app_config` | bir satırda GitHub token | **maskelenir, geçer** — DLP sonuçtaki token'ı redakte eder |
| `DROP TABLE products` | şema/veri değiştiren ifade | **engellenir** — politika, `query` tool'unun `sql` argümanını reddeder; sunucuya hiç ulaşmaz |

Son satır salt-okunur veritabanı erişimini gösterir: `INSERT/UPDATE/DELETE/DROP/ALTER/…` istek tarafında reddedilir,
veritabanına ulaşmaz (`tools.rules` → `query` → `arguments.sql.deny`). "Supabase destek talebi" senaryosundaki gibi
bir satıra gizlenmiş talimat ise sonuç tarafında ML tarafından yakalanır.
