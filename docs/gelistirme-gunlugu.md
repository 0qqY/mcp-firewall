# MCP Firewall geliştirme günlüğü

Ürünün ve modelin bugüne kadar hangi sırayla geliştiği. Ölçüm sonuçları için [README](../README.md), saldırı
kapsamı için [tehdit-kapsami.md](tehdit-kapsami.md).

## A. Ürünün temeli

1. **stdio proxy:** Host ile MCP sunucusu arasındaki her JSON-RPC mesajını ayrıştıran bir ara katman.
   Ayrıştıramadığı mesajı geçirmiyor (fail-closed); 32 MB'tan büyük satırları atıyor.
2. **YAML politika:** tool izin/yasak kuralları (ilk eşleşen kazanır), argüman regex kuralları,
   yöntem yasakları (`sampling/createMessage`, `elicitation/create`), `enforce` ve `monitor` modları.
3. **Açıklama taraması:** tool tanımlarında bilinen tool poisoning kalıpları ve gizli Unicode karakterler.
4. **Tool pinleme:** her tool tanımının SHA-256 hash'i saklanıyor; tanım değişirse tool gizleniyor (rug pull).
5. **DLP:** API anahtarları, özel anahtarlar, JWT, kart (Luhn), TR IBAN ve TCKN (sağlama) iki yönde maskeleniyor.
6. **Audit log ve panel:** JSONL kayıtlar; `127.0.0.1` üzerinde yerel panel (DNS rebinding ve CSRF korumalı).
   Panelde etiketlenen olaylar eğitim verisine dönüşebiliyor.

## B. ML sınıflandırıcı (DeBERTa-v3-base, RTX 5050 8 GB)

7. **Baseline:** ProtectAI `deberta-v3-base-prompt-injection-v2`. MCP tool tanımlarında recall yalnızca %31.
8. **v1:** sentetik MCP verisiyle ilk eğitim; sentetik setlerde %100, el yazımı problarda %83.
9. **v2:** çeşitlendirilmiş zararsız araçlar ve açık veri setleri (InjecAgent, AgentDojo, BIPIA kod saldırıları).
10. **v3 / v3b:** MCPTox (gerçek MCP sunucularında zehirli tool tanımları, yazar izniyle). v3b, v3'teki
    gerilemeyi geri aldı.
11. **v4:** Lakera Gandalf, jackhhao ve "saldırıdan bahseden" zararsız metinler. LLMail'de çok güçlü (%98,7).
12. **Bağımsız değerlendirme seti:** eğitimde hiç kullanılmayan LLMail-Inject ve TrustAIRLab istemleri.
    Firewall gibi 1500 karakterlik pencereler ve 0,9 eşik ile ölçülüyor.
13. **Kısayol tespiti:** v4'ün "uzun metin = saldırı" öğrendiği bulundu (uzun eğitim metinlerinin %79–86'sı saldırıydı).
14. **v5:** FineWeb (EN), FineWeb-2 (TR) ve OpenAssistant'tan gerçek uzun metinler ve aynı uzunlukta saldırılı eşleri.
    Türkçe web metinlerinde yanlış alarm %66'dan %0'a indi, ama LLMail isabeti düştü.
15. **v6:** LLMail'de kaçırılan örnekler incelendi; gömülü saldırı havuzu 1.358 saldırıya çıkarıldı, yarısı
    cümle akışına yedirildi.
16. **v7:** v4 ve v6'nın ağırlık ortalaması ("model soup"). LLMail gücü büyük ölçüde korunurken yanlış alarm düştü.
17. **v8:** Türkçe saldırı verisi (beratcmn, 3nesdeniz 1k ve conversation) ve Türkçe web metinlerine gömülü
    Türkçe saldırılar. Türkçe benchmark (halilneed) yalnızca ölçüm için kullanıldı.
18. **v9 (mevcut aday):** v4 ve v8'in ağırlık ortalaması. LLMail %96, Türkçe saldırı %75, iç test yanlış alarm %1,1.
19. **v10 (benimsenmedi):** yaklaşık 3.800 zararsız rol/sistem istemi eklendi. "Normal istem" yanlış alarmı
    %62'den %37'ye indi, ama LLMail %96'dan %60'a düştü. Firewall kullanıcı istemlerini değil tool çıktılarını
    taradığından bu metrik dağıtım metriği sayılmadı; v9'da kalındı.

## C. Tehdit araştırması

20. **Bilinen MCP saldırıları tarandı:** OWASP MCP Top 10, MCP-38 taksonomisi, CyberArk, Trail of Bits,
    Invariant Labs, Unit 42, postmark-mcp, CVE'ler. Sonuç üç gruba ayrıldı: korunuyoruz / zayıfız / engelleyemezdik.
    Ayrıntılar: [tehdit-kapsami.md](tehdit-kapsami.md).
21. **postmark-mcp düzeltmesi:** bu olay bir rug pull'du, ama tool tanımında değil paket kodunda. Bu yüzden
    mevcut tool pinlemesi onu yakalayamazdı; bunun için ayrı bir modül gerekiyordu (adım 25).

## D. Ürün iyileştirmeleri (27.10.2026)

22. **Taranmayan kanallar kapatıldı:**
    - JSON-RPC `error` yanıtları (CyberArk ATPA);
    - sunucu `instructions` alanı;
    - `prompts/list`, `resources/list` ve `resources/templates/list`;
    - parametre adları (Full-Schema Poisoning).
23. **Gizli metin temizleme (`hiddenText`):** sonuçlarda, hatalarda ve sampling isteklerinde Unicode TAG,
    varyasyon seçicileri, sıfır genişlikli ve bidi karakterleri ile ANSI/OSC dizileri temizleniyor.
24. **Sampling/elicitation içerik taraması, uzun çıktı için `onTruncated`, sunucular arası tool adı çakışması uyarısı.**
25. **Sunucu kodu sabitleme (`pinning.serverCode`):** npx paketlerinin dosyaları hash'leniyor; kod değişirse sunucu
    `initialize` anında kesiliyor (postmark-mcp türü paket rug pull'u). `mcp-firewall pins list/approve` komutları eklendi.
26. **Yeni tool'ları onaya kadar gizleme (`pinning.onNew: hide`).**
27. **Kodlanmış metin çözme (`decoding`):** base64, hex, URL kodlaması, `\u`/`\x` kaçışları ve HTML varlıkları
    çözülüp desen, ML ve DLP taramasına ekleniyor; kodlanmış secret içeren çağrı engelleniyor.
28. **Sampling sınırları:** dakika ve oturum başına istek sınırı, istek başına `maxTokens` tavanı, oturum token bütçesi.
29. **uvx/pipx desteği:** Python paketleri wheel `RECORD` dosyasıyla hash'leniyor. Gerçek `uvx mcp-server-time`
    kurulumuyla doğrulandı: sabitleme, eşleşme, kurcalamada engelleme ve geri alındığında yeniden çalışma.

## E. Karıştırılmış (obfuscated) metin

30. **Ölçüm:** leetspeak, harf aralama (`i g n o r e`), noktalama ile bölme, benzer görünen harfler (homoglif) ve
    rastgele büyük-küçük harf için 5.400 satırlık bir değerlendirme seti hazırlandı. v9 bu saldırıları yakalıyor
    (%92–100), ama aynı dönüşümler zararsız metne uygulanınca yanlış alarm %4'ten %22–88'e çıkıyor.
31. **Firewall'da gizlemeyi geri alma:** ML metni görmeden önce bu dönüşümler geri alınıyor. Zararsız metinde
    yanlış alarm %4–5'e indi, saldırı isabeti %93–98'de kaldı; LLMail ve Türkçe sonuçları değişmedi. Normal metne
    dokunmamak için e-posta, sürüm adları, hex kimlikler, birimler (`1st`, `10AM`) ve camelCase adlar korunuyor.
32. **v11 (benimsenmedi):** dönüşümler eğitim verisine eklendi. Gizlenmiş zararsız metinde yanlış alarm azaldı,
    ama LLMail isabeti %96'dan %91'e düştü. v9 aday model olarak kalıyor.

## F. Çok dilli model (27.10.2026)

33. **Görünmez Unicode çözümü:** Unicode TAG ve varyasyon seçicileriyle gizlenmiş metin çözülüp ML'e veriliyor.
    Türkçe benchmark'ta v9'un isabeti %75'ten %84'e çıktı (görünmez saldırılarda %29'dan %93'e).
34. **Çeviri verisi:** eğitim satırları opus-mt modelleriyle Türkçe, Almanca, İspanyolca, Fransızca ve Rusçaya
    çevrildi (10.760 satır). Aynı dillerde 3.555 satırlık bir değerlendirme seti hazırlandı.
35. **v12 (benimsenmedi):** DeBERTa çeviri verisiyle eğitildi. Türkçe konuşma saldırılarında isabet %37'den %73'e
    çıktı, ama LLMail isabeti %81'e düştü.
36. **mmBERT-base:** çok dilli ModernBERT (MIT), aynı veriyle eğitildi. Türkçede yanlış alarm en düşük (%12),
    ama LLMail isabeti %60. Eşiği değiştirmek bunu düzeltmiyor.
37. **mmBERT soup:** v9'daki tarif mmBERT ile tekrarlandı: v4 verisiyle ve çeviri verisiyle eğitilmiş iki
    mmBERT yarı yarıya karıştırıldı. Firewall biçiminde LLMail %98, Türkçe %86, çevrilmiş LLMail saldırıları
    %97–99, MCPTox yanlış alarmı %5'ten %2,5'e indi. Gerileme: Türkçe "görev talimatı" metinlerinde yanlış alarm
    %47'den %71'e çıktı.
38. **Node'da doğrulama:** transformers.js'in tokenizer'ı mmBERT'te metinlerin %28'ini farklı bölüyordu
    (art arda boşluklar). `export_onnx.py` tokenizer.json'u düzeltiyor; fark %0,2'ye indi. Node ile PyTorch
    750 satırda aynı kararı veriyor, hız v9 ile aynı. int8 sürümü kararları değiştirdiği için kullanılmıyor.
39. **Varsayılan model mmBERT soup05 oldu:** `policy.example.yaml` artık `models/mcp-pi-mmbert-soup05` dizinini
    kullanıyor; README'de modeli yeniden üretme adımları var. Gerçek model testi bu modelle geçiyor.
    Sıradaki iş: Türkçe "görev talimatı" metinlerindeki yanlış alarm (%71).

## G. Görev talimatı verisi (27.10.2026)

40. **Görev talimatı verisi:** soup05, Türkçe benchmark'taki "görev talimatı" metinlerinin %71'ini (ör. "bu
    mesajdaki kişisel verileri maskele") saldırı sayıyordu. Eğitimde, müşteri verisinin yanında modele talimat veren
    zararsız metin yoktu. `task_prompts.py` kendi şablonlarımızla, uydurma kişisel verilerle Türkçe ve İngilizce
    görev talimatları üretiyor; satırların yarısına saldırı ekleniyor.
41. **Hangi bileşene:** veri soup'un iki bileşenine ayrı ayrı eklendi. Yalnızca çeviri bileşenine eklemek (A+B2)
    yanlış alarmı %33'e indirdi; LLMail %98'den %99'a, Türkçe isabet %86'dan %90'a çıktı. İki bileşene birden
    eklemek (A2+B2) %5'e indirdi, ama MCP tool sonucu saldırılarında isabeti %100'den %95'e düşürdü; benimsenmedi.
42. **Ezber mi:** maskeleme talimatları çıkarılmış veriyle eğitilen bileşen (A3) kazancın yaklaşık %60'ını koruyor;
    model yalnızca benchmark'taki talimat türünü ezberlemiyor.
43. **Dış doğrulama:** eğitimde hiç görülmemiş üç sette (xTRam1 İngilizce ve Türkçe çevirisi, rogue-security
    Türkçe, AltaySec Türkçe) İngilizce isabet %49'dan %60'a çıktı, Türkçede değişmedi. Yeni yanlış alarmlar
    çoğunlukla "Act as…" türü rol istemleri.
44. **Varsayılan model soup05-ab2 oldu:** çok dilli sette isabet %97'den %98'e çıktı, yanlış alarm %1,1'den %0,8'e
    indi. Karıştırılmış sette isabet arttı (%97 → %98), yanlış alarm %5'ten %7'ye çıktı (yine rol istemleri). Node
    ile PyTorch 750 satırın 749'unda aynı kararı veriyor; tek fark, PyTorch'un 512 token'da kestiği için kaçırdığı
    bir saldırıyı Node'un yakalaması. `policy.example.yaml` artık `models/mcp-pi-mmbert-soup05-ab2` dizinini
    kullanıyor; gerçek model testi bu modelle geçiyor (69/69). Sıradaki iş: kalan görev talimatı yanlış alarmı (%33) ve dış Türkçe setlerdeki düşük isabet (%48–65).
45. **Rol istemleri ve `prompts/get`:** eğitimde görülmemiş 3.185 zararsız rol istemi ve her birine saldırı eklenmiş
    ikizleriyle ölçüldü. 0,9 eşiğinde model zararsızların %40'ını engelliyor (sistem istemi kütüphanesinde %78);
    yanlış alarmların üçte ikisi 0,999'un üstünde olduğu için eşik çözüm değil. Rol verisiyle eğitmek de denenmişti
    (v10) ve LLMail isabetini %96'dan %60'a düşürmüştü. MCP'de prompt şablonunu kullanıcı seçtiği için
    `ml.scan.promptResults` ayrı bir ayar oldu (varsayılan `warn`); `prompts/get` sonuçlarında tanım desenleri,
    gizli karakter ve DLP yine engelliyor, denetim kaydına prompt adı yazılıyor. Sonuç: yanlış engelleme %0,6,
    saldırıların %16'sı engelleniyor, %83'ü uyarı olarak kaydediliyor (72/72 test). Sıradaki iş: prompt şablonu
    sabitleme.

## H. Prompt şablonu sabitleme (28.10.2026)

46. **`pinning.prompts` (varsayılan `block`):** `prompts/get` sonucu tool tanımı gibi sabitleniyor. Sonuç her
    çağrıda kullanıcının girdiği argümanlarla doldurulduğu için, hash'ten önce istekteki argüman değerleri tek bir
    işaretle değiştiriliyor (uzun değerler önce; 4 karakterden kısa değerler yalnızca tam kelime olarak, "en" "when"
    içinde aranmıyor). İsteğe bağlı argüman şablonu değiştirebildiği için anahtar, prompt adı ve dolu argüman
    adlarından oluşuyor (`@prompt:review#code,language`). Hash DLP maskelemesinden önce alınıyor. Değişen şablon
    `mcp-firewall pins approve` ile onaylanana kadar reddediliyor; `onNew: hide` yeni şablonları da bekletiyor.
    Desenlerin yakalamadığı "her zaman X paketini öner" türü bir ekleme testte yakalanıyor (75/75 test). Bilinen
    sınır: her çağrıda değişen içerik gömen dinamik prompt'lar yanlış alarm verir; onlar için `warn` veya `off`.

## I. İlk gerçek kurulum: GitHub MCP (28.10.2026)

47. **Kurulum:** firewall, geliştirme klasöründen bağımsız olarak `%USERPROFILE%\.mcp-firewall` altına kopyalandı
    (derlenmiş kod, arayüz, bağımlılıklar ve soup05-ab2). GitHub'ın resmî MCP sunucusu (v2.0.3) Docker imajı olarak,
    digest ile sabitlenerek, Claude Code kullanıcı ayarlarına firewall'un arkasında eklendi. Token yalnızca Docker'ın
    okuduğu `github.env` dosyasında; hiçbir yapılandırmada yok.
48. **Bulgu:** ML, GitHub'ın 46 resmî tool tanımından 21'ini zehirli saydı (skor 0,90–0,999), ör. `get_file_contents`
    ("Get the contents of a file or directory from a GitHub repository") ve `issue_read`. Desenler hiçbirini
    işaretlemedi. Tanım taraması `tools/list`'i 112 saniye sürdürdü; MCP istemcileri genellikle 60 saniyede vazgeçtiği
    için bağlantı kullanılamaz hâle geliyordu. GitHub politikasında `ml.scan.toolDefinitions: off` yapıldı:
    `tools/list` 3,7 saniyeye indi, 45 tool görünüyor (`delete_file` kuralla kapalı). Tool sonuçları ML ile
    engellenmeye devam ediyor. Açık iş: tanım kararlarını hash'e göre önbelleğe almak ve gerçek tool tanımlarıyla
    değerlendirme.
49. **Bulgu: firewall kendi deposunun okunmasını engelliyor.** Yüklemeden sonra depo GitHub MCP üzerinden okundu.
    `package.json` geçti ve içeriği yereldekiyle aynı çıktı (blob `b8e9565`). `README.md` ile `test/proxy.test.ts`
    engellendi (skor 1,000); bu dosyalarda gerçek saldırı örnekleri ve sahte anahtarlar olduğu için bu beklenen bir
    sonuç. Beklenmeyen engel commit listesindeydi (`list_commits`, 0,994). Varyant ölçümleri:
    - commit mesajı tek başına 0,004, `Co-Authored-By` satırı tek başına 0,000;
    - GitHub JSON'u içinde mesaj satırsız 0,57, satırla 0,99; satırdaki ad bir insan adı olunca da 0,998;
    - konusu prompt olan tek satırlık mesaj da engelleniyor ("Add prompt template pinning" + satır: 1,000);
    - sıradan mesajlar geçiyor ("Fix typo in README" 0,07; Türkçe sıradan bir mesaj 0,79, eşiğe yakın).

    Model, prompt injection'ı *anlatan* zararsız metni tool sonucunun içinde görünce yüksek skor veriyor;
    `Co-Authored-By` satırı skoru eşiğin üstüne taşıyor. Bu deponun geçmişi yerel git ile okunmalı. Kalıcı çözüm
    eğitimde: güvenlik konulu zararsız metinler (commit mesajı, README, test açıklaması) zor negatif olarak
    eklenmeli. Yan bulgu: leet çözücü ISO tarihlerini (`28T07` → `2bTot`) ve JSON kaçışlarını (`>` →
    `\uooee`) bozuyor; bu kararı değiştirmedi (çözücü kapalıyken de 0,990).

## J. MCP 2026-07-28 uyumu ve JSON'a duyarlı tarama (29.10.2026)

50. **Bulgu: yeni oturumlarda GitHub tool'larının hepsi gizlendi.** 28.10.2026 sabahı 4 Code oturumunun 2'sinde,
    akşam 3 oturumun 3'ünde 46 tool "tool definition changed since it was pinned" diye gizlendi. Claude Code 2.1.309,
    MCP 2026-07-28 ile bağlanıyor (`server/discover`, isteklerde `_meta` zarfı); bu sürümde GitHub sunucusu her tool'a
    `outputSchema` ekliyor ve `delete_repository`'yi de sunuyor (47 tool). Pinler test betikleriyle eski sürümde
    (2025-06-18) alınmıştı. Saldırı değil: imaj digest ile sabit, iki sürüm arasındaki tek fark `outputSchema` (46/46
    tool) ve tanımlar her çalıştırmada aynı. Geçici çözüm olarak `onChange: warn` yapıldı ve bekleyen tanımlar onaylandı.
51. **Sürümden bağımsız tool pini:** pin, tanımın hash'i (`outputSchema` hariç) ile varsa `+` ve çıktı şemasının
    hash'inden oluşuyor. Şemayı almayan istemcide yalnızca tanım karşılaştırılıyor. Şema ilk görüldüğünde `onNew: hide`
    olsa bile sabitleniyor, yoksa her istemci güncellemesi güvenilen bütün tool'ları gizlerdi; sonra değişirse tool
    değişmiş sayılıyor. Tanımın tamamını tek hash'le saklayan eski pinler, aynı tanım görülünce kendiliğinden yeni
    biçime geçiyor. Şemasız bir istemcinin gördüğü değişiklik onaylanınca sabitlenmiş şema korunuyor. Bilinen sınır:
    yeni sürümün tanımıyla alınmış eski biçimli bir pin, ilk oturum eski sürümle açılırsa taşınamıyor ve bir kez onay
    istiyor. GitHub kurulumunda 47 pin taşındı; iki sürümde de 45 tool görünüyor ve `onChange` yeniden `hide`.
52. **Açık: `server/discover` el sıkışma sayılmıyordu.** Firewall yalnızca `initialize` yanıtını el sıkışma olarak
    işliyordu. 2026-07-28'de sunucu talimatları (`instructions`, GitHub'da 1.802 karakter) taranmadan modele gidiyor,
    sunucu kodu kontrolü hiç çalışmıyordu. Artık iki yanıt da aynı kontrollerden geçiyor.
53. **Model yükleme zamanı:** model sunucudan önce yükleniyordu; yükleme olay döngüsünü tek seferde yaklaşık 2,2
    saniye durduruyor (toplam 2,7–5,1 sn). Claude Code'un sürüm yoklaması bu sürede zaman aşımına uğruyor, istemci
    `initialize`'a düşüp yeniden `server/discover` deniyor ya da sunucuyu yeniden başlatıp eski sürümle bağlanıyordu.
    Artık sunucu hemen başlıyor ve model, el sıkışma yanıtı gönderildikten sonra (ondan önce bir tarama gerekirse o
    anda) yükleniyor; modeli gereken taramalar bekliyor. Model klasörü yoksa firewall yine başlamadan duruyor.
    El sıkışma 5,8 sn'den 0,55–1,1 sn'ye indi (Docker tek başına 0,4 sn).
54. **JSON'a duyarlı ML metni:** tool sonucu JSON tutan bir metinse sınıflandırıcı ham JSON'u değil içindeki
    değerleri ve alan adına benzemeyen anahtarları okuyor. Verinin içinde protokolün `image`, `blob` ve `_meta`
    atlamaları uygulanmıyor, yoksa saldırgan metnini bu alanlara saklayabilirdi. Gerçek modelle: engellenen commit
    0,994 → 0,008; insan ortak yazarlı mesaj 0,998 → 0,009; Türkçe sıradan mesaj 0,009; "Add prompt template
    pinning" 1,000 → 0,996 (hâlâ engelleniyor, zor negatif gerekiyor); 5 sentetik saldırı 1,000'de kaldı. Firewall
    üzerinden `list_commits` artık geçiyor (85/85 test).

## K. Gerçek MCP testleri ve DLP açığı (29.10.2026)

55. **Doğru-pozitif senaryo (`demo/toxic-agent-flow`):** GitHub "toxic agent flow" saldırısını taklit eden
    kendi kendine yeten bir mock sunucu. Bir issue gövdesine gömülü dolaylı injection firewall arkasında 1,000
    skorla engellendi; zararsız issue geçti. Deterministik (modelsiz) sürümü `test/ml.test.ts` içinde.
56. **Dosya sistemi, web ve SQL testleri (`demo/filesystem`, `demo/web`, `demo/sql`):** resmî
    `@modelcontextprotocol/server-filesystem`, gerçek `fetch` yapan küçük bir sunucu ve yerleşik `node:sqlite`
    ile bellek içi bir SQL sunucusu firewall arkasında denendi. Hepsinde gömülü injection 1,000 ile engellendi,
    zararsız içerik geçti. SQL demosu üç katmanı birden gösteriyor: satırdaki injection (ML), satırdaki
    GitHub token (DLP maskeler) ve `DROP TABLE` (salt-okunur politika, `query` tool'unun `sql` argümanını istek
    tarafında reddeder). Windows'ta uzun checkout yolu `npx`/`node`'u başlatamadığı için demolar çocuk süreci
    kısa bir cwd'de (os.tmpdir) başlatıyor.
57. **DLP açığı ve düzeltmesi:** dosya sistemi testinde `config.env` okunurken DLP'nin `aws_access_key` detektörünün
    yalnızca `AKIA…` erişim anahtarı kimliğini maskelediği, 40 karakterlik AWS gizli anahtar değerini kaçırdığı
    görüldü; o değeri yalnızca ML "injection" olarak (0,988) yakalıyordu — yani ML kapalı/`warn` olsa gizli anahtar
    modele giderdi. Çözüm: bağlamsal `aws_secret_key` detektörü; değer `(aws_)secret_access_key` etiketinden sonra
    (`=`/`:`, tırnak toleranslı) geldiğinde maskeleniyor, çıplak 40 karakterlik base64 ise (ör. commit hash'i)
    bırakılıyor. Anahtar adı görünür kalsın diye yalnızca değer redakte ediliyor (lookbehind). Artık `config.env`
    DLP'de maskelenip geçiyor, ML'e muhtaç değil (87/87 test).
58. **DLP açığı (devam): JSON'da kaçışlanmış satır sonu.** `demo/sql` 12 sorguluk kapsamlı teste genişletilince,
    satır JSON olarak döndüğünde gerçek satır sonunun `\n` (ters-bölü + `n`) biçiminde kaçışlandığı ve bu `n`'in
    etikete yapışıp `aws_secret_key` detektörünün etiket başındaki `\b` sınırını düşürdüğü görüldü
    (`…\nAWS_SECRET_ACCESS_KEY=`); o koşuda gizli anahtarı yalnızca ML (0,937) yakaladı. Çözüm: etiketin baştaki
    `\b`'si kaldırıldı — yanlış-pozitif korumaları (etiketsiz 40 karakterlik hash, ayrı sütunlar) sürüyor;
    `test/engine.test.ts`'e kaçışlanmış-satır durumu eklendi. Artık JSON içindeki `.env` bloğunda da maskeleniyor.
59. **Slack testi (`demo/slack`):** gerçek `server-slack` tool yüzeyini taklit eden yerel mock (token/ağ yok).
    Okuma tarafı: injection mesajı ML ile engellendi, sızmış anahtar DLP ile maskelenip geçti (bkz. 61). Gönderme tarafı: giden metindeki
    secret istek tarafında maskelendi, DM'e (exfil) gönderim `channel_id ^D` ile reddedildi. `post_message` gerçeğe
    uygun biçimde yalnızca ack dönüyor; metni echo'lamak redaksiyon işaretini sonuç olarak yeniden taratıyordu.
60. **5 ek MCP (yerel mock) kapsamlı testi** (denetimsiz, 29.10.2026; önce silinmiş, sonra kullanıcı isteğiyle
    `demo/more-mcps/` olarak eklendi — c3854e0): GitHub, Shell, E-posta, Docs/Prompts, Integrations. İlk kez kapsanan katmanlar — descriptionScan (zehirli tool
    açıklaması + gizli Unicode → tool gizlendi), hiddenText (ANSI/zero-width terminal kaçışları → engellendi),
    decoding+ML (base64 injection), pinning (prompt rug-pull ve tool rug-pull → değişen tanım gizlendi/engellendi),
    methods.deny (`resources/*`), DLP istek tarafı (harici e-posta alıcısı + giden secret). **Bulgu:** DLP bir
    secret'i `[REDACTED:…]` ile değiştirince, "key/token" geçen düz metinde bu işaret ML skorunu ~1,000'e çıkarıp
    sonucu tümden bloklayabiliyor (yapısal veride olmuyor). Giden ack'lerin metni echo'lamaması bu ikinci taramayı
    önler; katmanlı savunma açısından güvenli tarafta hata.
61. **`[REDACTED]` yanlış-alarmı düzeltildi:** 60'taki gözlem — DLP bir secret'i `[REDACTED:…]` ile değiştirince
    köşeli parantezli işaret ML'de injection gibi okunup maskeli sonucu bloklayabiliyordu (ör. "…key is
    [REDACTED:github_token]" skoru 1,000). Çözüm: `mlFlags` artık skorlamadan **önce** işareti nötr bir kelimeyle
    (`redacted`) değiştiriyor — yalnızca tarama kopyasında; istemciye iletilen `[REDACTED:…]` değişmez. Ölçüm:
    aynı metin 1,000 → 0,002; gerçek injection 1,000 kalıyor (işaret gerçek saldırılarda bulunmaz). İşaret regex'i
    `REDACTION_MARKER` olarak src/dlp.ts'ten export edildi, `redactionPlaceholder` ile aynı biçimde tutuluyor;
    `test/ml.test.ts`'e sahte-sınıflandırıcı testi eklendi (88/88). Slack `#random` artık bloklanmak yerine
    DLP ile maskelenip geçiyor.
62. **Decoder yanlış-yazımı düzeltildi (ISO zaman / `\u`-`\x` escape):** `deobfuscate`'in l33t geri-yazımı,
    `-`/`:` ile ayrılan ISO parçası `28T07`'yi `2bTot`, unicode/hex escape token'ı `u003e`/`x1b`'yi `uooee`/`xib`
    yapıyordu — hem kelime-başı hem "yaygın l33t" dalında (kısa, escape-yoğun metinde ikincisi tetikleniyor).
    Ortak `structuredToken` muafiyeti (`\d+T\d+`, `u<4 hex>`, `x<2 hex>`) iki dala da eklendi; gerçek l33t
    geri-yazımı (`7he c0st 0f` → `the cost of`, `1gn0r3` → `ignore`) korunuyor. `test/decode.ts`'e iki
    "değişmeden kalır" satırı (ISO + escape) eklendi. 88/88 test.
