# Web getirme MCP — firewall arkasında

Yerel iki sayfa sunar ve gerçek `fetch` yapan küçük bir MCP sunucusuyla (`fetch-server.mjs`) onları firewall
arkasından getirir. Getirilen web içeriğine gömülü dolaylı injection'ın yakalandığını gösterir — web/tarayıcı
MCP'lerinin en büyük saldırı yüzeyi.

## Çalıştırma

```bash
npm run build
node demo/web/run.mjs
```

Model depoda tutulmaz; `MCP_FIREWALL_MODEL` ile yolunu verin (varsayılan `./models/mcp-pi-mmbert-mix-ab4-lab-30`).
Kendi kendine yeter; dış ağ gerekmez.

## Beklenen sonuç

| Sayfa | İçerik | Firewall |
|---|---|---|
| `/article` | sıradan blog yazısı | **geçer** |
| `/promo` | HTML yorumunda gizli injection | **engellenir** (ML ~1,000) |

Firewall web sunucusunu görmez; yalnızca `fetch_url` sonucunu tarar. İstemciye `/promo` için
sayfa içeriği değil firewall mesajı gider.
