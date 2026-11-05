# Dosya sistemi MCP — firewall arkasında

Resmî [`@modelcontextprotocol/server-filesystem`](https://www.npmjs.com/package/@modelcontextprotocol/server-filesystem)
sunucusunu firewall arkasında çalıştırır ve `sandbox/` içindeki üç dosyayı okur. Firewall'un üç katmanını bir arada gösterir:
DLP (secret maskeleme), ML (dolaylı injection) ve sıradan içeriğin sorunsuz geçişi.

## Çalıştırma

```bash
npm run build
node demo/filesystem/run.mjs
```

Model depoda tutulmaz; `MCP_FIREWALL_MODEL` ile yolunu verin (varsayılan `./models/mcp-pi-mmbert-mix-ab4-llm6-30`).
İlk çalıştırmada `npx` sunucuyu indirir (ağ gerekir). Windows'ta checkout yolunu kısa tutun —
`npx` çok derin bir dizinden başlayamaz.

## Beklenen sonuç

| Dosya | İçerik | Firewall |
|---|---|---|
| `onboarding.txt` | sıradan not | **geçer** |
| `config.env` | AWS erişim + gizli anahtarı | **maskelenir, geçer** — DLP `aws_access_key` ve `aws_secret_key` değerlerini redakte eder |
| `notes.md` | yorumda gizli injection | **engellenir** (ML ~1,000) |

`config.env`, DLP'nin bağlamsal AWS gizli anahtar detektörünü gösterir: değer `AWS_SECRET_ACCESS_KEY=`
etiketinden sonra geldiği için maskelenir, sıradan 40 karakterlik base64 ise maskelenmez.
