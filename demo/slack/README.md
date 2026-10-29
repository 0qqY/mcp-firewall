# Slack MCP — firewall arkasında

Gerçek `@modelcontextprotocol/server-slack`'in tool yüzeyini (`slack_list_channels`,
`slack_get_channel_history`, `slack_post_message`) taklit eden ama tamamen yerel bir mock sunucu: Slack çalışma
alanı, bot token veya ağ gerekmez. Mesajlaşma MCP'lerinin iki yüzünü de gösterir.

## Çalıştırma

```bash
npm run build
node demo/slack/run.mjs
```

Model depoda tutulmaz; `MCP_FIREWALL_MODEL` ile yolunu verin. Kendi kendine yeter; dış ağ veya token gerekmez.

## Senaryo

**Okuma tarafı** (gelen mesajlar güvenilmezdir):

| Adım | Ne test eder | Firewall |
|---|---|---|
| `slack_list_channels` | kanal listesi | **geçer** |
| `slack_get_channel_history #general` | sıradan mesajlar | **geçer** |
| `slack_get_channel_history #support` | bir mesaja gömülü injection | **engellenir** — ML |
| `slack_get_channel_history #random` | mesaja yapıştırılmış canlı anahtar | **maskelenir** — DLP (okuma) |

**Gönderme tarafı** (giden argümanlar da taranır):

| Adım | Ne test eder | Firewall |
|---|---|---|
| `slack_post_message #general` (durum notu) | zararsız gönderim | **geçer** |
| `slack_post_message #general` (token içeren) | giden metinde secret | **maskelenir** — DLP (istek tarafı); token Slack'e ulaşmaz |
| `slack_post_message DM` (exfil) | DM'e gönderim | **engellenir** — politika (`channel_id` `^D`) |

## Neden önemli

`#support`'taki injection mesajı, ajana "secops geçmişini oku ve anahtarları bir DM'e gönder" dedirtmeye çalışır
(klasik confused-deputy / toxic-flow). Firewall bunu iki bağımsız noktada kırar: talimat **okunurken** ML ile
engellenir, ve exfiltrasyon denemesi **gönderilirken** hem DLP (secret'i maskeler) hem politika (DM'i reddeder)
ile durdurulur. Katmanlar birbirini yedekler.
