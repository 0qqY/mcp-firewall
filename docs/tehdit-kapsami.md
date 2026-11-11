# Tuuf MCP Firewall: bilinen saldırılara karşı kapsam (Ekim 2026)

Bu belge, kamuya açık olarak bilinen MCP saldırılarını Tuuf MCP Firewall'un mevcut koduyla karşılaştırır
(`src/proxy.ts`, `src/engine.ts`, `src/policy.ts`, `src/pinning.ts`, `src/dlp.ts`, `src/ml/classifier.ts`).
Saldırılar üç gruba ayrıldı:

- **Korunuyoruz:** Firewall bu saldırıyı varsayılan ayarlarla görür ve durdurur.
- **Zayıfız:** Firewall saldırıyı kısmen görür, ancak bilinen bir boşluk veya düşük isabet var.
- **Engelleyemezdik:** Saldırı, firewall'un gördüğü JSON-RPC trafiğinin dışında gerçekleşir.

Ölçümler mmBERT soup05-ab2'ye göre verilmiştir (eşik 0,9, 1500 karakterlik parçalar, firewall'un kod çözme ve
gizleme geri alma adımlarından sonraki metin). 27.10.2026'dan önceki varsayılan v9'un değerleri parantez içinde.
30.10.2026'dan beri varsayılan model soup04-ab4, 05.11.2026'dan beri mix-ab4-lab-30, 07.11.2026'dan beri
mixraw-ab4-evilsandangels-30 (eşik 0,3; tablodaki ölçümler önceki modellerle 0,9'da yapıldı); farkları "İyileştirmeler"
21., 28., 29. ve 30. maddelerde.

## Firewall'un gördüğü ve görmediği trafik

| Kanal | Taranıyor mu? |
|---|---|
| `tools/list` (tool adı, açıklaması, şemadaki **değerler**) | Evet: regex, gizli Unicode kontrolü, ML ve hash sabitleme (pin) |
| `tools/call` sonucu, `resources/read` | Evet: DLP ve ML |
| `prompts/get` (prompt şablonu) | Evet: DLP, gizli karakter ve tanım desenleri engelliyor; ML varsayılan olarak yalnızca uyarıyor (27.10.2026'dan itibaren); şablon sabitlendikten sonra değişirse engelleniyor (28.10.2026'dan itibaren) |
| `tools/call` argümanları | Evet: DLP ve isteğe bağlı argüman regex kuralları |
| Şemadaki **anahtar adları** (parametre adları) | Evet (27.10.2026'dan itibaren): adlar kelimelere ayrılıp regex ve ML'e veriliyor |
| JSON-RPC `error` yanıtları (`error.message` / `error.data`) | Evet (27.10.2026'dan itibaren): DLP, gizli karakter ve ML |
| El sıkışma yanıtındaki sunucu `instructions` alanı | Evet: zehirliyse alan çıkarılıyor. `initialize`'da 27.10.2026'dan, MCP 2026-07-28'in `server/discover` yanıtında 29.10.2026'dan itibaren; o tarihe kadar bu sürümde talimatlar taranmadan geçiyordu ve sunucu kodu kontrolü çalışmıyordu |
| `prompts/list`, `resources/list`, `resources/templates/list` açıklamaları | Evet (27.10.2026'dan itibaren): zehirli kayıt gizleniyor |
| Sunucudan istemciye giden `sampling/createMessage` ve `elicitation/create` içeriği | Evet (27.10.2026'dan itibaren): gizli karakter ve ML; işaretlenen istek sunucuya reddediliyor |
| Sunucu sürecinin kendi ağ ve dosya erişimi | **Hayır**: firewall yalnızca stdio'yu görüyor. 08.11.2026'dan itibaren `sandbox` açıksa görmüyoruz ama sınırlıyoruz: sunucu kilitli bir Docker konteynerinde çalışıyor (ağ yok, salt okunur kök, yalnızca bağlanan klasörler) |

## 1. Korunuyoruz

| Saldırı | Örnek | Bizim savunmamız |
|---|---|---|
| Tool açıklaması zehirleme / "line jumping" | Invariant Labs TPA (2025); Trail of Bits "Jumping the line" | `tools/list` üzerinde regex desenleri, gizli Unicode kontrolü ve ML taraması; şüpheli tool modelden gizleniyor. Eğitimde MCPTox verisi var. |
| Rug pull (onaydan sonra tanımın değiştirilmesi) | OWASP MCP03; ETDI makalesi | Her tool tanımının SHA-256 hash'i sabitleniyor; tanım değişirse tool gizleniyor ve operatör onaylayana kadar gizli kalıyor; hidden olan bir tool'a adıyla gelen `tools/call` da reddediliyor (10.11.2026'ya kadar tool yalnızca list'ten çıkarılıyordu; client list'i cache'lemişse çağrılabiliyordu; external review'da bulundu). Bu alandaki en güçlü savunmamız. Çıktı şeması (`outputSchema`) 29.10.2026'dan itibaren ayrı sabitleniyor; böylece aynı pin, MCP 2026-07-28 ile bağlanan istemcide de eski sürümle bağlananda da tutuyor. |
| Tool çıktısındaki dolaylı prompt injection | GitHub MCP "toxic agent flow" (Invariant, Mayıs 2025); Supabase destek talebi senaryosu; LLMail tarzı e-postalar | `tools/call` ve `resources/read` sonuçları ML ile taranıp engelleniyor. İngilizce LLMail sonuçları: başarılı saldırıların %99'u (v9: %96), tüm saldırıların %95'i (v9: %90) yakalanıyor. |
| Sır ve kişisel veri sızıntısı (OWASP MCP01) | Anahtarların veya token'ların araç çıktısına ya da argümana düşmesi | DLP özel anahtarları, AWS erişim anahtarını ve (etiketinden tanınan) AWS gizli anahtarını, GitHub, Slack, Anthropic, OpenAI ve Stripe anahtarlarını, JWT'yi, kart numaralarını (Luhn kontrolüyle), TR IBAN'ı ve TCKN'yi (sağlama kontrolüyle) iki yönde de maskeliyor. |
| Tehlikeli tool'lar ve yöntemler | `delete_*`, `exec`, sampling | Tool izin/yasak listeleri, argüman regex kuralları ve `methods.deny` ayarı var. |
| Bozuk veya devasa mesajlar | Ayrıştırıcıyı bozma, bellek tüketme | Firewall hata durumunda mesajı geçirmiyor (fail-closed); 32 MB'tan büyük satırlar atılıyor. |
| Full-Schema Poisoning (talimatın parametre adına gizlenmesi) *(27.10.2026'da kapatıldı)* | CyberArk "Poison everywhere" (Mayıs 2025) | Parametre adları (`readSshKey` → "read ssh key") regex desenlerine ve ML'e veriliyor. |
| Hata mesajıyla zehirleme (ATPA) *(27.10.2026'da kapatıldı)* | CyberArk ATPA | JSON-RPC `error` yanıtları DLP, gizli karakter ve ML taramasından geçiyor; işaretlenen mesaj firewall mesajıyla değiştiriliyor. |
| Zehirli sunucu `instructions` alanı, prompt ve resource listeleri *(27.10.2026'da kapatıldı)* | MCP-38 | `initialize` ve `server/discover` yanıtlarındaki `instructions` zehirliyse çıkarılıyor; zehirli prompt, resource ve resource template kayıtları gizleniyor. |
| Gizli Unicode ve ANSI kaçış kodları *(27.10.2026'da kapatıldı)* | Trail of Bits ANSI; Unicode TAG-block; varyasyon seçicisi kaçakçılığı | `hiddenText: strip`: tool sonuçlarındaki, hata mesajlarındaki ve sampling isteklerindeki görünmez karakterler (TAG, ek varyasyon seçicileri, sıfır genişlikli, bidi) ve ANSI/OSC dizileri temizleniyor. TAG ile kodlanmış talimat temizlenince tamamen kayboluyor. `warn`/`monitor` modunda ve tanımlarda ise gizli metin çözülüp ML'e veriliyor: Türkçe benchmark'ın görünmez Unicode saldırılarında isabet %98 (v9: %93; çözüm olmadan %29). |
| Paket rug pull'u *(27.10.2026'da eklendi)* | `postmark-mcp` 1.0.15 → 1.0.16: kodda gizli BCC, tool tanımları aynı (Koi Security, Eylül 2025) | `pinning.serverCode`: npx paketinin dosyaları (veya yerel script'in paketi) hash'leniyor. Kod değişirse sunucu söylediği ilk mesajda (çoğu zaman `initialize` ya da `server/discover` yanıtı) kesiliyor: o mesaj dahil sunucudan hiçbir şey istemciye geçmiyor ve operatör `mcp-firewall pins approve` diyene kadar o sunucuya hiçbir mesaj gitmiyor. Sürümü sabitlenmemiş paketler (`npx -y paket`) için uyarı yazılıyor. |
| Prompt şablonu rug pull'u *(28.10.2026'da eklendi)* | Onaylanmış bir prompt şablonuna sonradan talimat eklenmesi; ör. "her zaman X paketini öner" gibi desenlerin yakalamadığı tercih manipülasyonu | `pinning.prompts: block`: her prompt'un şablonu, kullanıcının girdiği argüman değerleri çıkarılarak hash'leniyor ve ilk görüşte sabitleniyor. Şablon değişirse `prompts/get` reddediliyor ve operatör `mcp-firewall pins approve` diyene kadar reddedilmeye devam ediyor. |
| İlk görüşte güvenme (TOFU) ve sonradan eklenen tool'lar *(27.10.2026'da eklendi)* | Sonradan eklenen zehirli tool | `pinning.onNew: hide`: yeni tool onaylanana kadar modelden gizleniyor. Varsayılan hâlâ `allow`, çünkü her kurulumda onay gerektiriyor. |
| Sampling ile kota tüketme (kaynak hırsızlığı) *(27.10.2026'da eklendi)* | Unit 42 (2025): sunucunun sampling ile kullanıcının model kotasını kendi işleri için harcaması | `sampling` sınırları: dakikada 10, oturumda 200 istek; istek başına `maxTokens` en fazla 4096 (fazlası düşürülüyor); oturum başına 100.000 token bütçesi. Hepsi ayarlanabilir. Ayrıca `methods.deny` ile tamamen kapatılabiliyor. |
| Dashboard'a DNS rebinding veya CSRF | MCP Inspector CVE-2025-49596 tarzı | Dashboard yalnızca 127.0.0.1'i dinliyor; Host ve Origin başlıklarını kontrol ediyor, özel başlık istiyor ve sıkı bir CSP kullanıyor. |

## 2. Zayıfız

| Saldırı | Örnek | Neden zayıfız | Düzeltme |
|---|---|---|---|
| Sampling ve elicitation kötüye kullanımı *(kısmen iyileşti)* | Unit 42: konuşma ele geçirme, gizli tool çağrısı (2025); elicitation ile oltalama | İçerik gizli karakter ve ML ile taranıyor (`ml.scan.serverRequests`). İkna edici ve emir içermeyen oltalama metinleri hâlâ yakalanmıyor. | Elicitation için tavsiye: `methods.deny` ile kapatmak. |
| Uzun çıktıyla dolgu (padding) *(ayarla kapatılabilir)* | Saldırıyı yaklaşık 42.000 karakterlik metnin ortasına gömmek | Varsayılan hâlâ `ml.onTruncated: warn` (büyük dosya okumalarını bozmamak için). `block` seçilirse taranamayan metin engelleniyor. | Ayar: yüksek riskli sunucularda `onTruncated: block`. |
| Sunucular arası gölgeleme *(kısmen iyileşti)* | Cross-server shadowing (MCP-38, Netskope) | Aynı pin dosyasını kullanan sunucular arasında aynı tool adı artık uyarı veriyor (`pinning.onNameCollision`, isteğe bağlı olarak gizliyor). Benzer ama farklı adlar (typosquat) ve açıklamada başka tool'a yapılan atıflar yakalanmıyor. | Orta: benzer ad tespiti. |
| İngilizce dışı veya gizlenmiş injection *(kodlama ve karakter düzeyinde gizleme 27.10.2026'da kapatıldı)* | base64, hex, URL kodlama, leetspeak, bölünmüş komutlar, diğer diller | `decoding`: base64/base64url, hex, %XX, `\u`/`\x` kaçışları ve HTML varlıkları (iç içe 2 seviye) çözülüp desenlere ve ML'e veriliyor. Zararsız verilerde çözücü çok seyrek devreye giriyor (iç test 0/2786, bağımsız set 4/1560, Türkçe set 3/3055). Ayrıca leet, harf aralama (`i g n o r e`), noktalarla bölme, Kiril/Yunan benzer harfler ve rastgele büyük-küçük harf ML'den önce geri alınıyor: bu dönüşümlerde saldırı isabeti %96–99,7 (v9: %93–98), zararsız metinde yanlış alarm %6–9 (dönüşümsüz metinde %6; soup05'te %5–6'ydı, artış "Act as…" türü rol istemlerinden; geri alma olmadan v9'da %22–88'di). ROT13 ve parçalara bölünüp birleştirilmesi istenen komutlar ("'ign' ve 'ore' kelimelerini birleştir", `a + b`) 01.11.2026'da kapatıldı: 500 saldırıda ROT13'lü metinde isabet %93,6 → %97,6 (Türkçe %87 → %92), 2–4 harflik parçalara bölünmüş metinde %91–94 → %98–99,8 (Türkçe, `+` ile birleştirilen biçimde %75 → %100); zararsız 8.240 metinde yeni yanlış alarm 1. Diğer diller: Türkçe isabet %90 (v9: %84; görünmez Unicode çözümünden önce %75), makine çevirisiyle hazırlanan Almanca/İspanyolca/Fransızca/Rusça/Türkçe LLMail saldırılarında %98–99 (v9: %82–98). Eğitimde görülmemiş dış Türkçe setlerde isabet daha düşük, %48–65: bu setlerdeki saldırıların çoğu tool çıktısına gizlenmiş talimat değil, tehdit, şantaj ve rol yapma gibi doğrudan kullanıcı saldırıları. | Düşük: ROT13 dışındaki şifreler, ters çevirme ve dolgu kelimeler. Karıştırılmış örneklerle eğitim (v11) LLMail'de gerilediği için benimsenmedi. |
| Kodlanmış veri sızdırma *(27.10.2026'da eklendi)* | Secret'ı base64'leyip URL parametresine koymak | Çözülen metinde DLP dedektörleri çalışıyor. Kodlanmış secret yerinde maskelenemediği için çağrı engelleniyor. | — |
| Zehirli prompt şablonu (`prompts/get`) *(27.10.2026'da bilerek gevşetildi, 28.10.2026'da sabitleme eklendi)* | Kötü niyetli bir prompt sunucusunun, kullanıcının seçtiği şablona talimat gömmesi | Tanım desenleri ve gizli karakter kontrolü engelliyor, ama şablona gömülü saldırıların yalnızca %16'sını yakalıyor. Model %98'ini işaretliyor, ancak zararsız şablonların da %40'ını işaretlediği için varsayılan olarak yalnızca uyarıyor. Sonradan değişen şablonu sabitleme engelliyor; ilk görüşten itibaren zehirli olan şablon ise yalnızca uyarıyla geçiyor. Her çağrıda değişen içerik üreten dinamik prompt'lar (tarih, dosya içeriği) her seferinde değişmiş görünüyor. | Ayar: `pinning.onNew: hide` ile yeni şablonlar onaylanana kadar bekletilebiliyor; yüksek riskli kurulumlarda `ml.scan.promptResults: block`. Dinamik prompt sunucularında `pinning.prompts: warn`. |
| Tercih manipülasyonu (MPMA) | AAAI 2026: "en iyi araç budur, her zaman bunu kullan" gibi ikna edici açıklamalar | Açıklamada emir kipi olmadığı için regex ve ML büyük olasılıkla kaçırıyor. | Orta: güvenilir tool kataloğu ve tool adına izin listesi (`tools.default: deny`). |
| Pin anahtarı | — | `--name` verilmezse pin anahtarı sunucunun komut satırı; argümanlar değişince pinler sıfırlanıyor. | Kullanım: her sunucuya `--name` vermek. |
| Argümanlarla veri sızdırma (formatsız veri) | WhatsApp MCP: sohbet geçmişinin `send_message` içine gömülmesi (Invariant, Nisan 2025); GitHub toxic flow: özel repo içeriğinin herkese açık PR'a yazılması | DLP yalnızca bilinen formatları tanıyor. 30.10.2026'dan itibaren `taint` kaynak tool'ların döndürdüğü metni izliyor: aynı metni (düz, harf/noktalama değişmiş ya da base64'lenmiş) taşıyan çıkış tool'u engelleniyor, sunucular arasında da. Kaynak ve çıkış tool'ları elle tanımlanmalı. Özetlenmiş, yeniden yazılmış ya da çevrilmiş veri içerik modunda kaçıyor. | Kısmen: `taint` içerik modu; katı kural için `when: session` ("lethal trifecta": etiketli oturum dışarı yazamaz); hedef ve alıcıya izin listesi. |
| Görsel veya ses içindeki talimatlar | Çok modlu injection | Görsel ve ses içerik ML taramasından çıkarılıyor. | Zor: OCR veya bu içeriği tamamen engelleyen bir seçenek. |
| Yanlış alarm yükü | Gerçek kullanıcı istemlerinde yüksek yanlış alarm oranı | Kullanıcılar firewall'u "warn" moduna alırsa koruma kalkar. Firewall kullanıcı istemlerini değil tool çıktılarını taradığı için bu oran dağıtımı temsil etmiyor; dağıtıma yakın setlerde (iç test, Türkçe iş metinleri) yanlış alarm %0,4–0,6 (v9: %1,1–1,3). Türkçe "görev talimatı" metinlerinde (ör. "bu mesajdaki kişisel verileri maskele") %33 (v9: %47; soup05: %71). Yapay zekâya rol veren istemler ("Act as…") tool çıktısında çoğunlukla işaretleniyor: zararsız rol ve sistem istemlerinin %40'ı (sistem istemi kütüphanesinde %78). Bu yüzden prompt şablonlarında (`prompts/get`) model artık yalnızca uyarıyor. Gerçek bir sunucuda tool tanımlarında da yüksek: GitHub'ın resmî MCP sunucusunun (v2.0.3) 46 tanımından 21'i işaretlendi (skor 0,90–0,999; ör. "Get the contents of a file or directory from a GitHub repository"), tanım taraması `tools/list`'i 112 saniye sürdürdü. GitHub kurulumunda `ml.scan.toolDefinitions: off` (28.10.2026). Tool sonuçlarında da: prompt injection'ı anlatan zararsız içerik (bu deponun README'si, testleri ve konusu prompt olan commit mesajları) GitHub MCP üzerinden okunurken engellendi (`list_commits` 0,994; aynı mesaj tek başına 0,004). 29.10.2026'dan itibaren JSON tutan sonuçlarda model ham JSON'u değil değerleri okuyor: commit listesi 0,008'e indi. Konusu prompt olan mesaj (0,996) ve gerçek saldırı örnekleri içeren dosyalar hâlâ engelleniyor. | Görev talimatı verisi (`training/task_prompts.py`) görev talimatlarındaki oranı %71'den %33'e indirdi. Rol istemleri için denenen v10, LLMail isabetini %60'a indirdiği için benimsenmedi. Sıradaki: güvenlik konulu zararsız metinlerle zor negatif verisi. |

## 3. Engelleyemezdik (firewall'un görüş alanı dışında)

| Saldırı | Örnek | Neden |
|---|---|---|
| İlk sürümünden itibaren kötü niyetli sunucu kodu (tedarik zinciri) | Typosquat paketler; postmark-mcp 1.0.16 ile ilk kez kurulan bir sunucu | Sunucu veriyi kendi ağ bağlantısıyla, JSON-RPC dışından gönderiyor. Firewall yalnızca protokol trafiğini görüyor. Kod sabitleme yalnızca *değişikliği* yakalar; ilk kurulan sürüm referans kabul edilir. Sonradan güncellenen paket artık yakalanıyor (aşağıdaki nota bakın). 08.11.2026'dan itibaren `sandbox` (Docker) sunucunun dosya ve ağ erişimini sınırlıyor: `network: none` iken sunucu veriyi dışarı gönderemez ve makinenin dosyalarını okuyamaz. Ağ açıldığında (`bridge`) sunucunun kendi bağlantısı yine görünmez. |
| Sunucu tarafı açıklar | Anthropic Filesystem MCP "EscapeRoute" CVE-2025-53109/53110 (sembolik bağlantı ve önek atlatma); MCP sunucularında komut enjeksiyonu (OWASP MCP05) | Açık sunucu kodunun içinde çalışıyor. Argüman regex kuralları (`..`, `/etc`, `;`) bir kısmını kesebilir ama varsayılan olarak tanımlı değiller. |
| İstemci ve aracı yazılım açıkları | mcp-remote CVE-2025-6514 (OAuth `authorization_endpoint` üzerinden komut çalıştırma); MCP Inspector CVE-2025-49596 ve CVE-2025-58444 | OAuth akışı JSON-RPC başlamadan önce, `mcp-remote` sürecinin içinde gerçekleşiyor. |
| Yapılandırma dosyası saldırıları | Cursor MCPoison CVE-2025-54136; CurXecute CVE-2025-54135; IDE'lerin proje tanımlı MCP sunucularını otomatik çalıştırması (CSA, Temmuz 2026) | Firewall da aynı `mcp.json` içinde tanımlı; saldırgan bu dosyayı değiştirirse firewall'u devreden çıkarabilir veya firewall'suz yeni bir sunucu ekleyebilir. |
| Uzak HTTP/SSE sunucuları, OAuth ve token sorunları | Token passthrough, confused deputy, kapsam genişlemesi (OWASP MCP01/02/07) | 30.10.2026'dan itibaren `mcp-firewall gateway` uzak Streamable HTTP sunucularının mesajlarını da denetliyor. Kimlik doğrulama katmanı ise kapsam dışı: OAuth akışı gateway üzerinden yürümüyor, token `--header` ile veriliyor ve gateway token'ın kapsamını denetlemiyor. |
| Metinsiz kötüye kullanım | Model, injection içermeyen meşru verilerle kendi kendine yanlış bir aksiyon seçiyor; kullanıcı "her zaman izin ver" demiş | Tespit edilecek bir saldırı metni yok; niyeti ancak politika belirleyebilir. |

### Not: postmark-mcp bir rug pull'du, ama bizim pin mekanizmamızın gördüğü türden değil

"Rug pull" kelimesi iki farklı saldırı için kullanılıyor:

| | Tool tanımı rug pull'u | Paket (kod) rug pull'u |
|---|---|---|
| Ne değişiyor | `tools/list` içindeki açıklama veya şema | Sunucunun kaynak kodu (yeni npm sürümü) |
| Saldırıyı kim yapıyor | Model (değişen talimata uyarak) | Sunucunun kendisi (modelden habersiz) |
| Örnek | Invariant Labs rug pull demosu, OWASP MCP03 | `postmark-mcp` 1.0.16 |
| Bizim pin mekanizmamız | Yakalar (hash değişir, tool gizlenir) | Yakalamaz (tanım aynı, hash aynı) |

`postmark-mcp` paketinin ilk 15 sürümü temizdi. 1.0.16 sürümünde `sendEmail` fonksiyonunda Postmark API'ye giden
isteğe tek satır eklendi: `Bcc: 'phan@giftshop[.]club'`. Snyk'in incelemesine göre tool adı, açıklaması ve şeması değişmedi.
Model yine aynı `send_email` çağrısını yapıyor ve firewall aynı argümanları, aynı sonucu görüyor. BCC adresi
JSON-RPC trafiğinde hiç görünmüyor, çünkü sunucu bu adresi Postmark API'ye kendi HTTPS bağlantısıyla gönderiyor.
Bu yüzden 26.10.2026 sürümü bu saldırıyı engelleyemezdi.

**27.10.2026'dan itibaren: sunucu kodu sabitleme (`pinning.serverCode`, `src/codepin.ts`).** Sunucu ilk mesajını
gönderdiğinde (normalde `initialize` yanıtı) firewall, npx'in kurduğu paketin dosyalarını
(`<npm önbelleği>/_npx/*/node_modules/postmark-mcp`) hash'leyip pin dosyasında saklıyor. 1.0.16 kurulduğunda
`index.js` değiştiği için hash değişiyor; firewall bekleyen `initialize` isteğini hataya çeviriyor, o oturumda
sunucuya hiçbir `send_email` çağrısı ulaşmıyor ve kayıt "possible package rug pull" olarak düşüyor. Operatör kodu
inceleyip `mcp-firewall pins approve` diyene kadar bu sürüyor. (10.11.2026'ya kadar kontrol yalnızca el sıkışma
yanıtında çalışıyordu: yanıttan önce gelen bir `elicitation` ya da `sampling` isteği, ya da hiç gelmeyen bir yanıt
kontrolü atlıyordu. Harici incelemede bulundu ve kapatıldı.)
Testte bu senaryo birebir canlandırıldı (`test/codepin.test.ts`): aynı tool tanımları, `index.js`'e eklenmiş bir `Bcc` satırı.

Sınırları: ilk kurulan sürüm referans kabul edildiği için ilk günden kötü olan paketleri (typosquat) yakalamaz.
Onlar için sunucuyu sandbox içinde çalıştırmak gerekir. 08.11.2026'dan itibaren `sandbox` var (README: "Sandbox (Docker)"),
ama ağ ya kapalı ya açık: Docker adres bazlı izin listesi sunmuyor. Sunucunun ağa ihtiyacı yoksa `network: none` ile
veri sızdırması engellenir; ihtiyacı varsa (ör. e-posta API'si) postmark-mcp türü bir saldırı, izin verilen API'ye
kötü niyetli istek atmaya devam eder. Bunun için kendi Docker ağınızda çıkış proxy'si gerekir.
27.10.2026'dan itibaren `uvx`, `uv tool run` ve `pipx run` ile çalışan Python paketleri de otomatik bulunuyor
(paketin wheel `RECORD` dosyasındaki dosyalar hash'leniyor). Gerçek kurulumla doğrulandı (uv 0.13.5, Windows,
`uvx mcp-server-time` 2026.10.19): ilk çalıştırmada uv önbelleğindeki 9 dosya bulunup sabitlendi; ikinci çalıştırma
eşleşti; `server.py`'ye tek satır eklenince firewall `initialize`'ı "possible package rug pull" diyerek engelledi;
dosya geri alınınca sunucu yeniden çalıştı. PATH'ten doğrudan çalışan kurulu araçlar, derlenmiş
ikili dosyalar ve `python -m` için kod yolu `--code` ile elle verilmelidir.

## Medium yazısı için: hangi modül hangi saldırıyı yakalar

| Modül | Dosya | Yakaladığı saldırılar | Yakalayamadıkları |
|---|---|---|---|
| Tool politikası (izin/yasak, argüman regex) | `src/engine.ts`, `src/policy.ts` | Tehlikeli tool çağrıları, yasaklı yöntemler (ör. `sampling/createMessage`), elle tanımlanmış argüman kalıpları (`..`, `/etc`, alıcı/URL izin listesi) | Kural yazılmamış her şey; niyet |
| Açıklama tarayıcı (regex ve gizli Unicode) | `src/engine.ts` `scanToolDefinition`, `scanText` | Tool, prompt ve resource tanımlarında, `prompts/get` şablonlarında ve sunucu `instructions` alanında klasik tool poisoning ifadeleri ("ignore previous instructions", `<IMPORTANT>`, `~/.ssh`, "do not tell the user"); parametre adlarındaki talimatlar; görünmez karakterler ve ANSI kodları | Yeni ifade biçimleri, ikna edici açıklamalar (MPMA) |
| Gizli metin temizleyici | `src/engine.ts` `stripHiddenChars`, `hiddenText` | Tool sonuçlarında, hata mesajlarında ve sampling isteklerinde Unicode TAG kaçakçılığı, varyasyon seçicisi kaçakçılığı, sıfır genişlikli ve bidi karakterleri, ANSI/OSC dizileri | Görünür ama yanıltıcı metin (homoglifler; bunları kod çözücü ML için geri alıyor) |
| Sunucular arası ad kontrolü | `src/pinning.ts` `collisions` | Başka bir sunucunun zaten sunduğu tool adı (tool shadowing) | Benzer adlar (typosquat), tek sunucu kullanımı |
| Tool pinleme (SHA-256) | `src/pinning.ts` | Tool tanımı rug pull'u (OWASP MCP03), şema veya açıklamanın sessizce değiştirilmesi; `onNew: hide` ile onaysız yeni tool'lar; çıktı şeması ayrı sabitlendiği için MCP sürümünden bağımsız | İlk günden zehirli tanımlar (`onNew: allow` iken) |
| Prompt şablonu pinleme | `src/pinning.ts` `hashPromptTemplate`, `pinning.prompts` | Onaylanan `prompts/get` şablonunun sonradan değiştirilmesi (argüman değerleri hash'e girmiyor) | İlk günden zehirli şablonlar (`onNew: allow` iken); her çağrıda değişen dinamik prompt'larda yanlış alarm |
| Sunucu kodu sabitleme | `src/codepin.ts`, `pinning.serverCode` | npm (npx) ve Python (uvx, pipx) paketlerinde paket rug pull'u (postmark-mcp 1.0.16), sürümü sabitlenmemiş paketler için uyarı | Typosquat ve ilk sürümden kötü paketler, otomatik bulunamayan kod (PATH'teki kurulu araç, ikili dosya, `python -m`; `--code` gerekir) |
| ML sınıflandırıcı (mmBERT) | `src/ml/`, `training/` | Tool çıktısındaki ve hata mesajlarındaki dolaylı injection (GitHub issue, e-posta, destek talebi, web sayfası), tanımlarda yeni ifadelerle yazılmış zehirleme, sampling ve elicitation içeriği, jailbreak metinleri, Türkçe injection (%90) ve Almanca/İspanyolca/Fransızca/Rusça injection | Görsel/ses, çok uzun çıktıların ortası (`onTruncated: warn` iken), kodlanmış metin; doğrudan kullanıcı saldırılarının bir kısmı (tehdit, şantaj, rol yapma; dış setlerde isabet %48–65); zararsız rol istemini zehirli olandan ayırmak (prompt şablonlarında bu yüzden yalnızca uyarı) |
| DLP | `src/dlp.ts` | API anahtarları (Stripe dahil), özel anahtarlar, AWS erişim ve (etiketinden) gizli anahtarı, JWT, kart, TR IBAN, TCKN sızıntısı (istek ve yanıt); kodlanmış (base64, hex, %XX; base64 içinde hex dahil iki katman) hâlleri; görünmez karakterlerle bölünmüş anahtarlar; JSON property name (key) olarak taşınan secret'lar (key maskelenir); komşu alanlara bölünmüş (en çok 4 kısa alan) ve `image`/`audio`/`blob` içine gizlenmiş anahtarlar (bunlar yerinde maskelenemediği için engelleniyor) | Formatsız veri (sohbet geçmişi, özel repo içeriği); etiketsiz çıplak gizli değerler; araya başka alan girmiş ya da ayrı çağrılara dağılmış parçalar (bunun için `taint`) |
| Kod çözücü | `src/decode.ts`, `decoding` | base64/hex/URL/kaçış dizisi/HTML varlığı/ROT13 ile gizlenmiş ya da birleştirilmek üzere parçalara bölünmüş talimatlar ve secret'lar (iç içe 2 seviye); Unicode TAG ve varyasyon seçicisi kaçakçılığıyla saklanan metin (ML ve desenler gizli metni okur); leetspeak, harf aralama, noktalarla bölme, benzer harfler (homoglif), rastgele büyük-küçük harf | Şifrelenmiş metin (ROT13 dışı), ters çevrilmiş metin, dolgu kelimelerle bölünmüş komutlar |
| Fail-closed proxy | `src/proxy.ts`, `src/jsonrpc.ts` | Bozuk mesajlar, 32 MB üzeri mesajlar, iç hata durumunda trafiğin sızması | — |
| Dashboard güvenliği | `src/dashboard/server.ts` | Kendi arayüzümüze DNS rebinding ve CSRF | — |
| Sandbox (Docker) *(08.11.2026'da eklendi)* | `src/sandbox.ts`, `sandbox` | Sunucu sürecinin makinede serbestçe dosya okuması, ağa çıkması ve program başlatması: ağ yok (`none`), salt okunur kök, tüm yetkiler kapalı, root olmayan kullanıcı, kaynak sınırı; kimlik bilgisi klasörleri ve firewall'un kendi dosyaları bağlanamıyor; image'ın içerik kimliğiyle kod sabitleme | Ağ açıkken (`bridge`) sunucunun izinli hedefe kötü niyetli isteği (adres bazlı izin listesi yok); bağlanan klasördeki veri; Docker ve çekirdek açıkları; uzak (gateway) sunucular |

## İyileştirmeler

**27.10.2026'da yapılanlar** (testli, 48/48 geçiyor):

1. JSON-RPC `error` yanıtları, `initialize.instructions` alanı ve `prompts/list`, `resources/list`, `resources/templates/list` yanıtları taranıyor.
2. Şemadaki parametre adları regex ve ML taramasına katıldı (Full-Schema Poisoning).
3. `hiddenText`: tool sonuçlarında, hata mesajlarında ve sampling isteklerinde görünmez karakterler ve ANSI/OSC dizileri temizleniyor (veya engelleniyor). Unicode varyasyon seçicisi kaçakçılığı da kapsamda.
4. `ml.scan.serverRequests`: `sampling/createMessage` ve `elicitation/create` içeriği ML ile taranıyor.
5. `ml.onTruncated: block` seçeneği: taranamayan uzun metin engellenebiliyor.
6. `pinning.onNameCollision`: sunucular arası aynı tool adı uyarı veriyor veya gizleniyor.
7. `pinning.serverCode`: sunucu kodu sabitleme (paket rug pull'u, postmark-mcp).
8. `pinning.onNew: hide` ve `mcp-firewall pins list/approve`: yeni ve değişen her şey, görülen hash'iyle onaylanıyor (54/54 test).

9. `decoding`: kodlanmış metinler çözülüp desen, ML ve DLP taramasına ekleniyor (59/59 test).

10. `sampling`: dakika ve oturum başına istek sınırı, istek başına `maxTokens` tavanı, oturum token bütçesi (64/64 test).

11. `uvx`/`uv tool run`/`pipx run` paketleri için otomatik kod bulma (66/66 test).

12. Karakter düzeyinde gizlemeyi geri alma (`decoding` içinde): leet, harf aralama, noktalarla bölme, benzer harfler,
    rastgele büyük-küçük harf. Gizlenmiş zararsız metinde yanlış alarm %22–88'den %4–5'e indi; saldırı isabeti korundu (68/68 test).
    Aynı sorun için denenen model eğitimi (v11) LLMail'de gerilediği için benimsenmedi.

13. Görünmez Unicode (TAG, varyasyon seçicisi) ile gizlenmiş metin çözülüp ML'e veriliyor: v9'un Türkçe isabeti %75'ten %84'e çıktı.
14. Varsayılan model, çok dilli mmBERT karışımı (soup05) oldu: Türkçe %86, çevrilmiş saldırılarda %97–99, LLMail %98.
    Node'da PyTorch ile aynı kararları veriyor; transformers.js tokenizer farkı `export_onnx.py` içinde düzeltildi.
15. Varsayılan model soup05-ab2 oldu (çeviri bileşeni görev talimatı verisiyle yeniden eğitildi): Türkçe görev
    talimatı metinlerinde yanlış alarm %71'den %33'e indi; Türkçe isabet %90, LLMail %99, çevrilmiş saldırılarda
    %98–99. Eğitimde görülmemiş dış setlerde İngilizce isabet %49'dan %60'a çıktı, Türkçede değişmedi. Bedeli: rol
    istemlerinde daha fazla yanlış alarm (karıştırılmış sette %5'ten %7'ye). Node'da 750 satırın 749'unda PyTorch
    ile aynı karar; gerçek model testi bu modelle geçiyor (69/69 test).
16. `ml.scan.promptResults` (varsayılan `warn`): `prompts/get` şablonlarında model yalnızca uyarıyor; tanım desenleri
    ve gizli karakter kontrolü engelliyor. Zararsız rol istemlerinde yanlış engelleme %40'tan %0,6'ya indi (72/72 test).
17. `pinning.prompts` (28.10.2026, varsayılan `block`): prompt şablonları sabitleniyor. Argüman değerleri hash'ten
    önce çıkarılıyor; isteğe bağlı argüman şablonu değiştirebildiği için her argüman kümesi ayrı sabitleniyor. Değişen
    şablon onaylanana kadar reddediliyor; `onNew: hide` yeni şablonları da bekletiyor (75/75 test).
18. MCP 2026-07-28 uyumu (29.10.2026): `server/discover` yanıtı da el sıkışma sayılıyor (sunucu talimatları
    taranıyor, sunucu kodu kontrol ediliyor); tool pininde çıktı şeması ayrı hash'leniyor ve eski pinler kendiliğinden
    taşınıyor; model, el sıkışma yanıtından sonra yükleniyor (el sıkışma 5,8 sn'den 0,6–1,1 sn'ye indi).
19. JSON'a duyarlı ML metni (29.10.2026): JSON tutan tool sonuçlarında model değerleri okuyor. GitHub commit
    listesindeki yanlış alarm 0,994'ten 0,008'e indi; sentetik saldırılar 1,000'de kaldı (85/85 test).
20. Gerçek MCP testleri ve DLP açığı (29.10.2026): resmî `@modelcontextprotocol/server-filesystem` ve gerçek
    `fetch` yapan bir sunucu firewall arkasında denendi (`demo/filesystem`, `demo/web`). Dosya sistemi testinde
    DLP'nin `aws_access_key` detektörünün yalnızca `AKIA…` erişim anahtarı kimliğini yakaladığı, 40 karakterlik
    AWS gizli anahtar değerini kaçırdığı görüldü; değeri yalnızca ML "injection" olarak yakalıyordu. Çözüm: bağlamsal
    `aws_secret_key` detektörü — değer `(aws_)secret_access_key` etiketiyle `=`/`:` sonrası geldiğinde maskeleniyor,
    çıplak 40 karakterlik base64 ise yanlış alarm olmasın diye bırakılıyor. Artık `config.env` DLP'de maskelenip
    geçiyor (87/87 test).
21. Varsayılan model soup04-ab4 oldu (30.10.2026; çeviri bileşenine güvenlik mühendisliği metni ve geliştirici
    diliyle yazılmış saldırılar eklendi, karışım oranı 0,4). Depodaki gerçek geliştirici metinlerinde yanlış alarm
    %13'ten %7'ye indi (commit mesajlarında %17'den %0'a). Eğitimde görülmemiş sınır çiftleri setinde isabet
    %66'dan %70'e çıktı (tool kötüye kullanımında %48'den %78'e), yanlış alarm %27'den %24'e indi. LLMail %99'da
    kaldı; Türkçe isabet %90'dan %89'a indi, Türkçe yanlış alarm %12'den %9'a indi. Bedeli: çevrilmiş setteki
    zararsız metinlerde yanlış alarm %0,8'den %2,2'ye, İngilizce görev talimatlarında %39'dan %53'e çıktı. Node'da
    798 satırda PyTorch ile aynı karar (88/88 test).
22. `paths` yol kısıtı (30.10.2026): yol argümanları kanonik biçimleriyle (`%2e%2e` ve çift kodlama, `file://`, `~`,
    `..`, sembolik bağ ve junction, Windows kısa adları, sondaki nokta/boşluk, `::$DATA`) izinli köklere ve yasak
    kalıplara göre denetleniyor. UNC yolları dosya sistemine sorulmadan reddediliyor (sormak NTLM özetini o sunucuya
    gönderirdi); `\\.\pipe\` gibi aygıt yolları da reddediliyor. Kalan sınır: denetimden sonra değiştirilen bağ
    (TOCTOU). 97/97 test.
23. `taint` veri akışı takibi (30.10.2026): kaynak tool sonuçlarının 8 kelimelik dizileri ve anahtara benzeyen
    kelimeleri SHA-256 özetleri olarak tutuluyor; çıkış tool'unun argümanında (çözülmüş biçimleri dahil) bulunursa
    çağrı engelleniyor. `when: session` etiketli oturumda çıkış tool'unu tamamen kapatıyor. DLP bulgusu `secret`
    etiketi veriyor. Aynı istemcinin firewall'ları etiketleri ortak bir dosyada paylaşıyor (WhatsApp ve GitHub
    toxic flow örnekleri tek sunucuda, dosya sistemi → Slack gibi akışlar sunucular arası). Kalan sınır: yeniden
    yazılmış veya çevrilmiş veri. 107/107 test (ML modeli testi hariç).
24. Kullanıcı onayı (30.10.2026): `action: ask` kuralları ve `taint.action: ask` çağrıyı bekletip kullanıcıya MCP
    elicitation penceresiyle soruyor. Pencerede argümanlar görünmez karakterlerden temizlenmiş olarak gösteriliyor.
    Reddedilen, 120 sn içinde cevaplanmayan ya da sorulamayan (istemci desteklemiyor) çağrı engelleniyor. Kalan
    sınır: onay yorgunluğu ve elicitation desteklemeyen istemciler. 120/120 test (ML modeli testi hariç).
25. Streamable HTTP gateway (30.10.2026): `mcp-firewall gateway --upstream <url>` uzak MCP sunucularının önüne
    yerel bir HTTP uç noktası koyuyor; her istemci oturumu kendi firewall örneğiyle bütün kontrollerden geçiyor.
    `Origin` denetimi (DNS rebinding), yalnızca localhost'ta dinleme ve ortam değişkeninden okunan başlıklar var.
    Kalan sınırlar: OAuth keşfi, akış sürdürme ve uzak sunucuda kod sabitleme. 127/127 test (ML modeli testi hariç).
26. Farklı yöntemlerle yeniden test (30.10.2026): işletim sistemine sorarak 120 bin yol yazımı, gerçek metinde taint
    ölçümü, saldırı senaryoları, resmî SDK v2 sunucusu ve Claude Code ile birlikte çalışma, çok süreçli yük ve
    mutasyon testi. Bulunup kapatılanlar: hard link ile kök dışına çıkma (`paths.hardLinks`), onay penceresinin
    sahte cevapla geçilmesi (tahmin edilebilir id), uzun argümanla gizlenen alıcı ve tool adıyla sahte satır, DNS
    rebinding (`Host` denetimi), kopan uzak akışta asılı kalma, kapanmayan oturumlar, SDK v2 tool'larının `$schema`
    yüzünden zehirli sayılması, 2026 başlıklarının eksikliği ve taint'in büyük harf, JSON kaçışı, HTML, görünmez
    karakter, satırlara bölünmüş/PEM base64, camelCase ve parça parça gönderimi kaçırması. 139/139 test (ML dahil).
27. SIEM çıktısı (31.10.2026): audit kayıtları syslog (RFC 5424; UDP, TCP, doğrulanmış TLS) ya da OTLP/HTTP ile
    merkezi log sistemine gidiyor; bir saldırı girişimi tek makinedeki dosyada kalmıyor. Kayıtlar JSON olarak
    kaçışlandığı için kötü niyetli bir sunucu tool adı ya da hata metniyle SIEM'de sahte kayıt üretemiyor. ML'yi
    tetikleyen metin varsayılan olarak gönderilmiyor. Alıcı kapalıyken firewall beklemiyor. Kalan sınır: dosya ve
    kuyruk yerel; makineyi ele geçiren biri kayıtları gönderilmeden silebilir. OpenObserve ve Fluent Bit ile gerçek
    SIEM'de denendi. 150/150 test (ML dahil).

28. Varsayılan model mix-ab4-llm6-30 oldu (05.11.2026): ab4 ile DeepSeek verisiyle eğitilen soup04-llm6'nın
    ağırlık ortalaması (%70 ab4, %30 llm6), yeni eğitim yok. Eşik 0,9'da ab4'e göre: içinde meşru istek geçen araç
    çıktılarında (DeepSeek test bölümü) yanlış alarm %54,5'ten %30,3'e, depodaki gerçek metinlerde %6,6'dan %4,7'ye,
    red team kılıflarında %8,0'dan %7,3'e indi. Türkçe 89,0 / 8,7 → 88,6 / 8,6 (isabet / yanlış alarm). Bedeli:
    kılıflı Türkçe setinde isabet %77,8'den %72,8'e indi (yanlış alarm %16,6'dan %14,1'e); kaçanların çoğu sohbet
    botuna yönelik tehdit ve zararlı istek. Diğer setlerde isabet kaybı 1 puanın altında. Node'da ONNX ile PyTorch
    arasında olasılık farkı 0,0000 (171/171 test).
29. Varsayılan model mix-ab4-lab-30 oldu (05.11.2026 akşamı): llm6 tarifine panelde etiketlenmiş 107 gerçek olayın
    %60'ı (10 kat) eklendi, aynı biçimde karıştırıldı (%70 ab4). Ayrılan 48 gerçek olayda (eşik 0,9) yanlış alarm
    29/31'den 21/31'e indi, saldırı yakalama 14/17'de kaldı. Diğer setlerde mix-30 ile fark 1 puanın altında
    (Türkçe 88,3 / 8,4; DeepSeek testinde yanlış alarm %25,8). Ölçüm payı küçük. 171/171 test.
30. Varsayılan model mixraw-ab4-evilsandangels-30, eşik 0,3 oldu (07.11.2026): v12lab'e ikiz veri seti evilsandangels
    eklenerek eğitilen ham modelin %30'u, soup04-ab4'ün %70'i. 16 kümede yanlış alarm hepsinde düştü (gerçek olaylarda
    %67,7 → %22,6 eşik 0,9'da, %45,2 eşik 0,3'te; DeepSeek testinde %25,8 → %3,0 / %6,1; gerçek MCP metinlerinde
    %5,0 → %0,9 / %2,2). Eşik 0,3'te yakalama yalnız ind −3,7, obf −2,8, ml −2,0, rt −0,7 puan düştü, wtr, tr, boundary
    ve test kümelerinde arttı ya da aynı kaldı. Eşik 0,9'da yakalama 7 kümede düşer, bu yüzden model yalnız 0,3 ile
    varsayılan. Rug pull örneklerinin yakalaması hâlâ zayıf (%52–60); bu tehdide karşı asıl savunma araç sabitleme.
    ONNX ile PyTorch arasında olasılık farkı 0,0000; int8 200 satırda 5 kararı değiştirdiği için silindi. 171/171
    test, 10 demo beklenen sonuçları verdi (zararsız metinler geçti, saldırılar engellendi).
31. Sunucu sandbox'ı (08.11.2026): `sandbox` açıkken sunucu makinede değil, kilitli bir Docker konteynerinde çalışıyor
    (`src/sandbox.ts`): ağ yok (`none`), salt okunur kök, tüm Linux yetkileri kapalı, root olmayan kullanıcı, bellek/CPU/süreç
    sınırı, ortam değişkenleri yalnızca adıyla geçiyor, klasör bağlama kimlik bilgisi klasörlerini, ev dizinini, politikanın ve
    firewall'un kendi dosyalarını ve Docker soketini reddediyor (sembolik bağlar çözüldükten sonra yeniden denetleniyor).
    Ham docker bayrağı kabul edilmiyor. Sunucu kodu sabitleme bu modda image'ın içerik kimliğini hash'liyor. Gerçek Docker
    Desktop'ta (Windows) denendi: konteynerde kullanıcı `nobody`, `touch /x` "Read-only file system", ağ "bad address", yetkiler
    `CapEff 0000000000000000`, salt okunur bağlamaya yazılamıyor, yazılabilir bağlamaya yazılıyor; GitHub MCP v2.0.3 (46 tool)
    `network: none` ile firewall üzerinden `initialize` ve `tools/list`'e cevap verdi, çıkışta konteyner kalktı, firewall sert
    öldürülünce de 1 saniyede kalktı. Kalan sınırlar: ağ açıkken sunucunun kendi bağlantısı görünmez ve adres bazlı izin listesi
    yok; bağlanan klasördeki veri sunucuya açıktır; Docker'ın yalıtımı VM sınırı değildir. 200/200 test (29'u yeni).
32. Firewall'un kendi erişilebilirliği (10.11.2026): gerçek MCP tool tanımlarıyla ölçüm yaparken (239.054 tanım,
    `mcp-research-alliance/mcp-ecosystem`) `deobfuscate` içindeki bir regex'in (`NAMING_STYLE`) uzun bir büyük harf dizisinde
    ("Ew" + 125 × "A" + "Pfw…", bir base64 başlangıcı) üstel zamanda geri izleme yaptığı görüldü. Tarama event loop'unda
    senkron koştuğu için tek bir tool tanımı, tool sonucu ya da web sayfası o server'ın bütün trafiğini durdurabiliyordu;
    saldırgan bir server bunu bilerek yapabilir. Regex, aynı dili tek geçişte okuyan bir durum makinesiyle değiştirildi
    (`isNamingStyle`; eski regex'le yaklaşık 340 bin kelimede birebir aynı sonuç), 239.054 tanımın hepsi yaklaşık 4 dakikada
    taranıyor. Aynı ölçümde `descriptionScan` gerçek tanımların %0.53'ünü gizlerdi (çoğu meşru: `.env` anması, "before
    calling this tool", `<important>` etiketi), varsayılan ML rastgele 3.000 gerçek tanımın %1.0'ını işaretledi. Held-out sette
    (`bench/heldout`) tanım saldırılarını regex 13/36, ML %97.6 yakalıyor. Kurulu kopya yenilenene kadar eski kodda.

**Sıradakiler:**

1. "Görev talimatı" metinlerinde kalan yanlış alarm (Türkçe benchmark %33, iç testte İngilizce %53) ve dış Türkçe setlerdeki düşük isabet (%48–65).
2. Sandbox'ta adres bazlı çıkış izin listesi (iç Docker ağı + proxy), image'ı sürümü sabit paketle kuran `sandbox build` yardımcısı ve Podman desteği; belgelere paket sürümünü sabitleme tavsiyesi.
3. Güvenlik konulu zararsız metinlerde kalan yanlış alarm (ölçüm soup04-ab4 ile; mix-30'da depodaki metinlerde %6,6 → %4,7): soup04-ab4 depodaki Markdown paragraflarının %11'ini hâlâ saldırı sayıyor (çoğu saldırı örneği içeren belgeler). Sınır çiftleri setinde RAG bağlamı zehirleme isabeti %66'dan %58'e indi.
4. Tool tanımlarında ML taraması (`ml.scan.toolDefinitions: warn`): gerçek ekosistemde yaklaşık %1 işaretleme, held-out tanım saldırılarında recall %97.6 (regex %36); başlangıç gecikmesi ölçülmeli.
5. Held-out sette görünen boşluklar için ayrı eğitim verisi: zincirleme eylem (audit/onay kapatma), Türkçe dolaylı mail talimatı, koşullu prompt şablonu, tanımda konu kelimesine tepki. Held-out satırlarına dokunmadan, farklı ifadelerle; karar held-out + AEB/BIPIA + 107 panel olayıyla.

## Kaynaklar

- [MCP-38 tehdit taksonomisi (arXiv 2603.18063)](https://arxiv.org/pdf/2603.18063)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/), [Cycode özeti](https://cycode.com/blog/owasp-mcp-top-10/)
- [Beyond the Protocol (arXiv 2506.02040)](https://arxiv.org/pdf/2506.02040), [ETDI (arXiv 2506.01333)](https://arxiv.org/pdf/2506.01333)
- [CyberArk: Poison everywhere (FSP/ATPA)](https://cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)
- [Trail of Bits: ANSI terminal kodları](https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/)
- [Unicode TAG-block gizleme (arXiv 2607.05744)](https://arxiv.org/pdf/2607.05744)
- [Unit 42: MCP sampling saldırı vektörleri](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [Invariant Labs: GitHub MCP açığı](https://invariantlabs.ai/blog/mcp-github-vulnerability), [Docker: WhatsApp MCP](https://www.docker.com/blog/mcp-horror-stories-whatsapp-data-exfiltration-issue/)
- [Simon Willison: Supabase MCP lethal trifecta](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/)
- [MPMA (arXiv 2505.11154)](https://arxiv.org/pdf/2505.11154)
- [Snyk: postmark-mcp](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/)
- [JFrog: CVE-2025-6514 mcp-remote](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/), [Oligo: CVE-2025-49596](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596), [CVE-2025-58444](https://www.sentinelone.com/vulnerability-database/cve-2025-58444/)
- [Cymulate: EscapeRoute CVE-2025-53109/53110](https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/)
- [CSA: MCP tool zehirleme ve IDE otomatik çalıştırma (Temmuz 2026)](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-auto-execution-20260701/)
