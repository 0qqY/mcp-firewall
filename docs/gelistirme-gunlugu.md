# Tuuf MCP Firewall geliştirme günlüğü

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
63. **Varsayılan model soup04-ab4 oldu (30.10.2026):** soup05-ab2 bu deponun kendi commit mesajlarının ve
    Markdown paragraflarının %13'ünü saldırı sayıyordu. `training/dev_corpus.py` güvenlik mühendisliği konulu
    zararsız metin ve saldırılı eşlerini üretiyor (`--dev-corpus`). `voiced()` ise geliştirici diliyle yazılıp ajana
    hitap eden saldırılar ve zararsız eşlerini ekliyor (`--dev-voiced`). Yalnızca konu metniyle eğitilen B3 yanlış
    alarmı %4'e indirdi ama geliştirici diliyle yazılmış saldırıları kaçırdı. Bunu eğitimde görülmemiş bir setle
    doğruladık: 3nesdeniz/agentic-prompt-injection-boundary-pairs'te isabet %66'dan %58'e indi. B4 (iki veri birlikte)
    gece boyunca 0,3–0,6 oranlarında karıştırıldı. Saldırının görevini tekrarlayan eşleri çıkaran B5 denemesi
    (`--no-close-mirrors`) kaçan Türkçe ve LLMail saldırılarını geri getirmedi. Seçilen A+B4 (0,4): gerçek metin FPR
    %13,2 → %6,6, sınır seti %65,8/%27,3 → %69,7/%24,2, LLMail %99,0 (=), Türkçe FPR %12,3 → %8,7. Bedeli:
    çevrilmiş set FPR %0,8 → %2,2, İngilizce görev talimatı FPR %39 → %53. ONNX fp32 (int8 silindi), Node 798 satırda
    0 karar farkı, 88/88 test. `policy.example.yaml`, demolar, gerçek model testi ve `temizlik.ps1` yeni dizini
    kullanıyor; önceki model `models/mcp-pi-mmbert-soup05-ab2` geri dönüş için duruyor.
64. **`paths` yol kısıtı (30.10.2026):** regex'le yol denetimi `%2e%2e/`, Windows kısa adları ve junction'larla
    atlatılabiliyordu. Yeni `src/paths.ts`: değer ve %-çözülmüş biçimleri (en çok 3 kat) `file://`, `~`, `base`'e göre
    göreli yol ve `..` çözülerek mutlak yola çevriliyor. Var olan en uzun ön ek `realpathSync.native` ile açılıyor
    (bağlar, junction'lar, 8.3 adlar). Windows'ta sondaki nokta/boşluk ve `:akış` atılıyor, `\\?\C:\` ön eki
    sökülüyor. Kalıplar `**` / `*` / `?` glob'ları ve eşleşen dizinin altını da kapsıyor. Test sırasında bulunan
    açık: `\\sunucu\paylaşım` yolunda `existsSync` Windows'u o sunucuya bağlatıyordu (2,7 sn; NTLM özeti sızabilir).
    Artık UNC yollarına dosya sistemi çağrısı yapılmıyor. `\\.\pipe\`, `\\.\C:`, `\\?\GLOBALROOT` gibi aygıt yolları
    reddediliyor. `test/paths.test.ts` 9 test (Windows'a özgü 3'ü başka sistemde atlanıyor), toplam 97/97.
    `policy.example.yaml`'daki `read_file` kuralı regex yerine `paths` kullanıyor.
65. **`taint` veri akışı takibi (30.10.2026):** DLP formatsız veriyi (sohbet geçmişi, özel repo içeriği) tanımıyordu.
    Yeni `src/taint.ts`: `sources` tool'larının sonuçları oturumu etiketliyor (varsayılan `private`; DLP bulgusu
    `secret`). Etiketle birlikte metnin 8 kelimelik dizilerinin ve 16+ karakterlik harf-rakam karışık kelimelerinin
    SHA-256 özetleri tutuluyor; metnin kendisi saklanmıyor. `sinks` çağrısı DLP'den sonra, iletilmeden önce
    denetleniyor: `content` argümanlarda (ve çözülmüş base64/hex/%XX biçimlerinde) eşleşen özet arıyor, `session`
    etiket varken her çağrıyı reddediyor. Her sunucu ayrı süreç olduğundan `scope: shared` etiketleri
    `mcp-firewall-taint/<ppid veya MCP_FIREWALL_SESSION>.jsonl` dosyasına ekleyip diğer firewall'ların eklediklerini
    okuyor; süresi dolan dosyalar açılışta siliniyor. Etiketler modelin gördüğü (maskelenmiş) metne göre veriliyor.
    `test/taint.test.ts` 11 test, toplam 107/107 (ML modeli testi hariç).
66. **Kullanıcı onayı, `action: ask` (30.10.2026):** tool kurallarına ve `tools.default`'a `ask`, `taint.action`'a
    `ask` eklendi. Argüman, `paths` ve DLP denetimlerinden geçen çağrı sunucuya iletilmiyor; firewall istemciye
    kendi id'siyle (`mcp-firewall-approval-N`) `elicitation/create` gönderiyor ve cevabı sunucuya iletmeden
    yakalıyor. Bekleme istemci kuyruğunu durdurmuyor: aynı anda gelen diğer çağrılar geçiyor. Cevap `accept` ise
    çağrı iletiliyor, `remember` işaretliyse tool oturum boyunca bir daha sorulmuyor. `decline`/`cancel`, hata
    yanıtı ya da `approval.timeoutSeconds` (120) sonunda çağrı reddediliyor; zaman aşımında istemciye
    `notifications/cancelled` gidiyor, geç gelen cevap düşürülüyor. Elicitation desteği `initialize`
    `capabilities`'ten ya da 2026-07-28'de istek `_meta`'sından okunuyor; yoksa `approval.fallback` (deny).
    Pencere metninde argümanlardan görünmez karakterler ve ANSI kodları siliniyor. Testte bulunan: cevapsız
    pencerenin zamanlayıcısı süreci 120 sn açık tutuyordu, `unref()` edildi. `test/approval.test.ts` 13 test,
    toplam 120/120 (ML modeli testi hariç).
67. **Streamable HTTP gateway (30.10.2026):** yeni `src/gateway.ts` ve `mcp-firewall gateway` komutu. Politika
    motorunu yeniden yazmamak için her istemci oturumuna bellekte dört akışla bir `FirewallProxy` açılıyor; gateway
    yalnızca HTTP'yi çeviriyor. İstek içeren POST'a SSE ile cevap veriliyor; cevaplar istek id'sine göre doğru
    akışa yönlendiriliyor, sunucu istekleri ve firewall'un onay pencereleri en son açık POST akışına, yoksa GET
    akışına gidiyor, o da yoksa bekletiliyor. Uzak sunucuya her mesaj ayrı POST; JSON ve SSE yanıtları okunuyor,
    `Mcp-Session-Id` iki tarafta ayrı tutuluyor, GET ve DELETE iletiliyor. Ulaşılamayan sunucu ya da HTTP hatası
    JSON-RPC hatasına çevriliyor. `--header` `${VAR}` açıyor; tanımsız değişken boş token yerine hata veriyor.
    Statik başlık istemcinin `Authorization`'ını geçersiz kılıyor. ML yükleyicisi paylaşılıyor (oturum başına
    model yüklenmiyor); CLI'deki yükleme kodu stdio ile ortak `classifierLoader`'a taşındı. `test/gateway.test.ts`
    7 test (sahte uzak sunucuyla), toplam 127/127 (ML modeli testi hariç). Gerçek CLI ile uçtan uca denendi.
68. **Farklı yöntemlerle yeniden test (30.10.2026):** önceki testler örnek girdilerle yazılmıştı; bu kez sonucu
    dışarıdan bir doğruluk kaynağıyla karşılaştıran yöntemler kullanıldı.
    - `paths`: 120 bin yol yazımı üretilip her birinin hangi dosyayı açtığı işletim sistemine soruldu (dosya
      kimliği); sızıntı yalnızca hard link'te çıktı. `paths.hardLinks` (varsayılan `deny`, nlink > 1) eklendi.
    - `taint`: gerçek belgelerde 20 gizleme biçimiyle yakalama oranı ölçüldü. Büyük Türkçe harfler, JSON kaçışları,
      HTML, görünmez karakterler, tam genişlikli ve Kiril harfler, satırlara bölünmüş ve PEM başlıklı base64,
      leetspeak, camelCase ve kısa parçalara bölünmüş gönderim kaçıyordu; metin sadeleştirme ve çağrılar arası
      son kelimeler eklendi. Ortak dosyaya yalnızca yeni özetler yazılıyor (dosya büyümesi). Kalan sınırlar:
      dolgu kelimeler, ters çevirme, ROT13, çeviri ve yeniden yazma.
    - Onay: firewall'un istek id'si tahmin edilebiliyordu ve sunucu aynı id ile kendi isteğini gönderip kullanıcının
      cevabını onay gibi kullandırabiliyordu; id'ler rastgele (UUID), bu aralıktaki sunucu istekleri reddediliyor.
      600 karakterlik önizleme uzun bir argümanla alıcıyı gizleyebiliyordu, tool adındaki satır sonu sahte satır
      ekleyebiliyordu; argümanlar ayrı satırlarda, tek satıra indirilmiş olarak gösteriliyor.
    - Gateway: `Host` denetimi (421, `--allow-host`), boşta kalan oturumların kapanması, kopan uzak akışta hata
      cevabı, 2026-07-28 başlıklarının (`Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`) iletilen gövdeden üretilmesi.
      Resmî SDK v2 sunucusunun tool'ları `$schema` URL'si yüzünden zehirli sayılıyordu; JSON Schema anahtar
      kelimeleri taramadan çıkarıldı.
    - Birlikte çalışma: resmî SDK v2 sunucusu, gerçek dosya sistemi sunucusu ve Claude Code el sıkışmasıyla 13/13.
      Yük: 12 süreç aynı taint dosyasına yazarken bozuk satır 0; 500 eşzamanlı çağrıda yanlış alıcıya giden cevap 0.
    - Mutasyon testi: koda 44 küçük hata tek tek sokuldu. İlk turda 42 hatanın 14'ü testlerden kaçıyordu; yeni testlerle
      kaçan tek hata UNC yolunun dosya sistemine sorulması (sonucu değiştirmiyor, yalnızca yan etkisi var). Toplam
      139/139 test (ML dahil).
69. **SIEM çıktısı: syslog ve OTLP (31.10.2026):** yeni `src/siem.ts` ve `audit.siem` politika bloğu. `AuditLog`
    her kaydı JSONL dosyasının yanında sink'lere de veriyor; varsayılan olarak `allow` kayıtları ve ML alıntıları
    gönderilmiyor. Syslog RFC 5424 (MSGID = karar, mesaj = JSON), UDP'de 8 KB sınırı ve kısaltma, TCP/TLS'te
    octet-counting; TLS sertifikası her zaman doğrulanıyor (`ca` ile özel CA). OTLP/HTTP JSON, saniyede bir toplu
    istek, 429/5xx'te artan aralıklarla tekrar. İki sink de sınırlı kuyrukla çalışıyor (`queueLimit`, en eski
    düşer, sayısı stderr'e). Firewall çıkarken (`child exit`, gateway SIGINT/SIGTERM) kuyruğa en çok 2 sn veriliyor:
    istemci çağrıdan hemen sonra kapansa da son kayıt gidiyor. OTLP başlıklarında `${VAR}`, tanımsızsa politika
    hatası. Testler gerçek UDP/TCP/TLS (openssl ile üretilen sertifika) ve HTTP alıcılarıyla:
    satır/alan sahteleme, kapalı alıcıda sıralı teslim ve yeniden bağlanma, 5000 kayıtta kuyruk sınırı, güvenilmeyen
    sertifikanın reddi, 503/429 tekrarı ve 400'de düşürme. Gerçek CLI ile uçtan uca: engellenen çağrının kaydı
    firewall kapanmadan iki alıcıya da ulaştı, token stderr'de görünmedi.
    Gerçek bir SIEM ile deneme: OpenObserve (Docker, yalnızca 127.0.0.1) OTLP'yi doğrudan aldı; ML, DLP, kural ve
    zehirli tool kayıtları SQL ile sorgulanabildi, alıntı alanı gelmedi. OpenObserve'ün syslog alıcısı kaldırıldığı
    için önüne Fluent Bit kondu; burada bulunan: Fluent Bit ve düz TCP rsyslog octet-counting değil satır sonu
    çerçevesi bekliyor. `syslog.framing: newline` eklendi (JSON mesajda ham satır sonu olmadığından güvenli). TCP ve
    UDP ile her çalıştırmanın 13 kaydı da ulaştı. SIEM kapalıyken oturum aynı kararlarla sürdü, uyarı stderr'e yazıldı.
    `test/siem.test.ts` 11 test, toplam 150/150 (ML dahil).
70. **ROT13 ve parçalara bölünmüş komutlar (01.11.2026):** `src/decode.ts` iki yeni çözüm yapıyor. ROT13: en az üç
    kelimelik her cümle döndürülüyor ve sonuç sık kullanılan İngilizce/Türkçe kelimelerle (talimat sözcükleri dahil)
    doluysa, döndürülmeden önce dolu değilse kabul ediliyor; tek harfli kelimeler sayılmıyor ("Logical Coherence B"
    gibi metinler bu yüzden takılmıyordu). Parça birleştirme (`joinPieces`): `'ign' + 'ore'`, değişkenler
    (`a = '...'; b = '...'; a + b`) ve parçaları birleştirmeyi isteyen cümleler ("concatenate", "join", "birleştir",
    "yan yana"). Harften sonra gelen tek tırnak kesme işareti sayılıyor ("don't", "İstanbul'da"). İkisi de iç içe
    kodlamayla çalışıyor (base64'lenmiş parçalar, ROT13'lü base64).
    Ölçüm soup04-ab4 ile, eşik 0.9, 500 saldırı (test 200, LLMail başarılı 150, Türkçe 150), önce → sonra:
    ROT13 tek başına %93,6 → %97,6 (İngilizce %96,3 → %100, Türkçe %87,3 → %92); "ROT13 ile çöz" önekiyle zaten
    %100. 2–4 harflik parçalar `+` ile %91,4 → %99,8 (Türkçe %75,3 → %100), "birleştir" cümlesiyle %93,8 → %98,2.
    Uzun parçalarda (kelimeler bütün kalıyor) model zaten %99–100 yakalıyordu; birleştirilmiş metin eklendiğinde
    iki biçimde 3–4 saldırı eşik altına düştü (%100 → %99,2 ve %99,4 → %98,8). Zararsız 8.240 metinde (test,
    bağımsız set, Türkçe set) çözücü 20 metinde devreye girdi, hepsi bağımsız setteki rol yapma kartları; yeni yanlış
    alarm 1 (`Age("20" + "twenty years")` içeren bir karakter kartı), kaybolan 0. Toplam 156/156 test.
71. **Red team döngüsü (02.11.2026 gecesi):** `training/redteam.py` eğitim setindeki saldırıları ve zararsız metinleri
    sekiz kılıfa sarıyor (JSON alanı, log satırı, kod yorumu, HTML/Markdown, e-posta, belge notu, araç çıktısı,
    YAML/CSV; Türkçe tohumlara Türkçe kılıf), mevcut modelle puanlıyor ve kaçırılan saldırılarla yanlış alarmları eğitim
    verisine çeviriyor. Panelde verilen etiketler (`mcp-firewall-labels.jsonl`, geri alınanlar hariç) aynı dosyaya
    ekleniyor; gerçek kayıtta henüz etiket yok. Değerlendirme seti (`data/eval_redteam.jsonl`, 5.200 satır) eğitimde hiç
    kullanılmayan tohumlar (test bölümü + LLMail başarılı saldırılar) ve hiç kullanılmayan kılıf cümleleriyle kuruldu.
    Bulgu: kılıf modeli çoğunlukla yanlış alarma itiyor. soup04-ab4'te aynı test bölümünün yanlış alarmı düz metinde
    %4,0, kılıflı metinde %8,0 (Türkçe %6,0 → %16,3); isabet %98,6 → %97,3.
    Üç aday (A = v4, alfa 0.4; eşik 0.9; ab4 → aday):
    - ab6, tur 1: her kılıfa kaçırılan/yanlış alarm sayısı kadar diğer etiketten de örnek eklendi (4.172 satır).
      Kılıflı FPR 8,0 → 5,7, devreal FPR 6,6 → 4,7; ama Türkçe FPR 8,7 → 12,5 (görev talimatları %21,8 → %33,2),
      deepset isabeti 81,7 → 70,0, LLMail saldırıları 95,5 → 92,5.
    - ab7, tur 2 (ab6'ya karşı yeni tohumlar, +2.234 satır): kılıflı FPR 6,6, Türkçe FPR 12,0; tur 1'den iyi değil.
    - ab8, sıkı tarif (`--no-top-up --hard 0.9`: yalnızca gerçek 81 kaçırma ve 1.437 yanlış alarm): kılıflı FPR 4,5,
      devreal 3,5, Türkçe FPR 7,1 (görev talimatları 18,1), test FPR 3,1; ama Türkçe isabet 89,0 → 83,3, boundary
      isabeti 69,7 → 60,0, devvoice FPR 1,2 → 8,3. Alfa 0.3 her şeyi kötüleştirdi (kılıflı FPR 12,2).
    Tur 1'deki Türkçe görev talimatı artışının nedeni: kılıflar "başlık satırı + altında içerik" biçiminde ve dengelemek
    için eklenen saldırı ikizleri bu biçimi saldırıyla ilişkilendirdi ("KVKK gereği kişisel alanları gizle" + kayıt
    0.05 → 0.99). Sıkı tarif bunu düzeltti ama yanlış alarmların ağırlığı saldırı isabetini düşürdü. Hiçbir aday
    varsayılanı geçmedi; soup04-ab4 kaldı. Sonraki deneme için: sıkı tarife Türkçe saldırıların kılıflı ikizleri
    eklenmeli (yalnızca Türkçe isabet düştü), yanlış alarm satırları daha az ağırlıkla.
72. **Panelde MCP sunucuları ve risk puanı (01.11.2026):** Ana sayfanın en üstüne "MCP sunucuların" bölümü eklendi
    (`src/dashboard/inventory.ts`, `GET /api/servers`). Liste Claude Code (`~/.claude.json`, genel ve proje) ve Claude
    Desktop ayarlarından, firewall ile sarılmış girişlerde `--name`/`--policy` ve `--` sonrasındaki asıl komut ayrılarak
    kuruluyor; yalnızca olay kaydında görülen sunucular da ekleniyor. Her sunucu kendi politikası ve pin dosyasıyla
    puanlanıyor (0–100; 30 altı düşük, 60 ve üstü yüksek). Maddeler: firewall dışında (+45), izleme modu (+20), onaysız
    komut aracı (+20), ML kapalı (+15) ya da sonuçlarda engellemiyor (+10), onaysız silme (+15), okuma + dışarı yazma
    varken taint kapalı (+15, "lethal trifecta"), onay bekleyen pin değişikliği (+15), DLP kapalı (+10), sabitleme
    kapalı (+10), sabit olmayan sürüm (+10; etiketli imaj +5), düz metin anahtar (+10), son 7 günde engellenen saldırı
    (+3..10), onaysız yazma araçları (+8), uzak sunucu (+5), yeni araçlara onaysız güven (+4). Geçmiş "rug pull"
    olayları değil bekleyen değişiklikler sayılıyor: 28.10'daki outputSchema geçişinin 231 olayı onaylanmıştı. Gerçek
    GitHub MCP 37 puan (orta): taint kapalı (+15), 33 engellenen saldırı (+10), 20 onaysız yazma aracı (+8), `onNew:
    allow` (+4). 162/162 test.
73. **Beş yeni MCP sunucusu (01.11.2026):** filesystem, memory, playwright (npm) ve fetch, git (PyPI), en az iki hafta önce
    çıkmış sürümlerle `~/.mcp-firewall/servers` altına kuruldu ve Claude Code'a firewall arkasında eklendi (ortak
    `policy-genel.yaml`, olay kaydı ve pin dosyası GitHub'la ortak; filesystem ve git yalnızca `~/MCP-Klasor`,
    playwright `--isolated`). İlk puanlar sınıflandırmada iki hatayı gösterdi: `browser_drop` (sürükle-bırak) silme
    sayılmıştı, yerel yazan memory/filesystem "okunan içerik dışarı yazılabiliyor" alıyordu, fetch ise dışarı kanal
    sayılmıyordu. Artık `drop` yalnızca table/database gibi bir kelimeyle silme; URL'ye giden araçlar (fetch, navigate)
    hem içerik getiren hem dışarı kanal; yazma araçları yalnızca dışarıda okunan bir yere yazıyorsa (push, issue,
    comment, send...) dışarı kanal. Sonuç: playwright 47, github 37, memory 27, fetch 19, filesystem 12, git 12.

74. **Red team tur 4 (01.11.2026):** Önerilen tarif denendi: sıkı tarif + Türkçe saldırıların kılıflı ikizleri
    (`--tr-twins 800`: kullanılmamış Türkçe tohumlardan 2.400'ü bir kılıfa sarılıp puanlandı, en düşük puanlı 800'ü
    eklendi) + yanlış alarm satırlarının %60'ı (`--benign-keep 0.6`). 881 saldırı, 862 zararsız satır; aday soup04-ab9.
    ab4'e göre: kılıflı FPR 8,0 → 7,6, devreal 6,6 → 5,7, mcptox FPR 2,5 → 0, RAG zehirleme isabeti 58 → 68; ama
    Türkçe isabet 89,0 → 87,4 ve Türkçe FPR 8,7 → 11,5 (görev talimatları 21,8 → 29,8), devsyn FPR 2,4 → 5,0,
    devvoice FPR 1,2 → 6,7, sistem istemi çıkarma isabeti 82 → 62. Türkçe ikizler isabeti kısmen geri getirdi ama
    tur 1'deki "başlık + içerik" yanlış alarmını da geri getirdi. Varsayılan değişmedi: soup04-ab4. Dört turun dersi:
    bu kılıf verisiyle tek bir alfa-0.4 çorbası hem Türkçe isabeti hem Türkçe FPR'ı birlikte iyileştirmiyor; sıradaki
    fırsat gerçek olay kaydı etiketleri (şu an 0).
75. **Gerçek olay etiketleri ve `ml.review` (01.11.2026):** Gerçek olay kaydındaki 33 ML tespitinin hepsi yanlış alarmdı
    (base64 resimler, GitHub araç tanımları, GitHub hata mesajları, bu deponun README/test/commit metinleri, bir CSS
    sayfası) ve öyle etiketlendi. Kayıtta yalnızca alarm veren metin tutulduğu için etiket sayısı sınırlıydı:
    `ml.review.nearMiss` skoru eşiğin altında kalıp geçirilen metni, `ml.review.sample` geçirilen trafikten bir payı
    skoruyla kayda yazar (`info`); panelin ML sekmesinde "Eşik altı" listesi ve "Zararsız" / "Saldırı, kaçırıldı"
    etiketleri eklendi. Ardından gerçek filesystem, fetch ve git sunucuları üzerinden tatbikat yapıldı: eğitim
    tarafındaki red team satırlarından 90 metin (değerlendirme setlerine dokunulmadı) dosya, yerel web sayfası ve
    commit mesajı olarak okutuldu; 79 olay bilinen doğruya göre etiketlendi. Toplam 112 etiket: 33 doğru tespit,
    79 yanlış alarm. Tatbikat metinleri ab4'ün kaçırdığı ve yanlış alarm verdiği zor örneklerdi; yerel web sunucusunun
    8765 portu WSL'e ait çıktı, 18765 kullanıldı.
76. **Panel tek ekran sekmeleri (01.11.2026):** Ana sayfa üç sekmeye bölündü: Genel bakış (MCP sunucuları, sayılar,
    küçültülmüş 12 saatlik şerit), Son olaylar (son 8 tespit ve detay), Analiz (dağılım, eşik simülasyonu, ML katmanı,
    etiket bekleyenler). 1440×900 ve 1366×768'de üçü de kaydırmadan sığıyor; mobilde menü tek satır, yatay kayıyor.
77. **Masaüstü bildirimi (01.11.2026):** Engelleme yalnızca modele hata olarak dönüyordu; kullanıcı görmüyordu.
    `audit.notify` ile firewall engellediği anda masaüstü bildirimi gösteriyor (Windows bildirimi, macOS osascript,
    Linux notify-send). 30 saniye içindeki ardışık engellemeler tek özet bildirim oluyor. Metin ortam değişkeniyle
    geçiyor, komut satırına girmiyor. Varsayılan kapalı; kullanıcının iki politikasında açıldı. 167/167 test.
78. **Etiketlerle eğitim ve gömülü resim filtresi (02.11.2026):** 112 panel etiketinin hepsi 10 kat ağırlıkla
    v12dev2'ye eklenip eğitildi, v4 ile 0,4 çorbası soup04-ab10. ab4'e göre yanlış alarm hemen her sette düştü
    (kılıflı 8,0 → 5,1, devreal 6,6 → 4,1, Türkçe 8,7 → 7,0, Türkçe görev talimatı 7,7 → 1,0) ama isabet de düştü
    (Türkçe 89,0 → 87,7, boundary 69,7 → 65,3, LLMail başarılı 99,0 → 97,7). ab4/ab10 karışımları iki modelin
    arasına doğrusal düştü. Aynı FPR'da iki modelin isabeti neredeyse aynı (kılıflı 97,3/97,6, Türkçe 89,0/89,0,
    AUC farkı < 0,003): eğitim ayrımı iyileştirmedi, skorları kaydırdı, yani eşiği yükseltmekle eşdeğer. Varsayılan
    ab4 kaldı. Bunun yerine gerçek yanlış alarmlar türlerine ayrıldı: 33'ün 22'si GitHub araç tanımlarıydı ve hepsi
    tanıma gömülü simgelerden (`data:image/png;base64`) geliyordu; de-obfuscation bu diziyi sözde metne de
    çeviriyordu ("base64" → "base6a"). ML girdisinde gerçek resim imzası taşıyan data URI'ler artık "image" kelimesiyle
    değiştiriliyor; kayıttaki örneklerde 22 alarmın 22'si eşiğin altına iniyor, değerlendirme setlerindeki saldırılarda
    gerçek resim içeren yok. Kalan gerçek alarmlar (README, testler, GitHub hata mesajları 1,000; bir CSS sayfası 0,95)
    için bağlama göre eşik ölçüldü: 1,000'deki alarmlara hiçbir eşik yetmiyor, tek CSS sayfası için ayar eklemek
    erken; bağlam eşiği eklenmedi. Gerçek GitHub sunucusunda (v2.0.3) tanım taraması açıkken 46 tanımın 0'ı
    işaretlendi (önceden 21), hiçbiri 0,5'i geçmedi; tarama 40 sn (önceden 112). 169/169 test.
79. **Kanal etiketleri ve rol istemi ikizleri (02–03.11.2026):** Firewall kullanıcının mesajını hiç görmez; yalnızca
    araç tanımı, araç sonucu ve prompt şablonu görür. Model her parçanın başında kanalı görsün diye
    `[tool definition]`, `[tool output]`, `[prompt template]` etiketleri eklendi (`training/channels.py`; firewall
    tarafında model klasöründeki `mcp-firewall.json` `{"channelTags": true}` derse etiket eklenir, ab4 gibi etiketsiz
    modellerde hiçbir şey değişmez). Üç deneme, hepsi v4 tarifi + v12dev2, 0,4 çorbası; ab4'e karşı eşik 0,9:
    soup04-ctx (yalnız etiket): şablonlarda isabet 98,2 → 96,5, yanlış alarm 38,0 → 0,0; ama araç sonucunda LLMail
    97,2 → 64,3, boundary isabeti 69,7 → 36,5 (v10 etkisi tekrarlandı: rol istemi araç sonucunda 0,9% yakalandı).
    soup04-twin (zararsız rol istemlerinin yarısı `[tool output]` etiketiyle saldırı olarak da eklendi): araç
    sonucundaki rol istemleri %97,5 yakalandı ama şablon isabeti 87,7, LLMail 88,8, boundary FPR 24 → 74.
    soup04-twin2 (tamamı ikizlendi): şablonlarda 94,7 / 0,0, LLMail 96,8, Türkçe 88,3 / 8,5; ama araç sonucunda yanlış
    alarm yaklaşık iki katı (devreal 6,6 → 12,6, devvoice 1,2 → 10,8, boundary 24 → 76, obf 6,3 → 13,3). Tek model
    iki kanal için zıt sınırı öğrenirken araç sonucu tarafı bozuluyor. Varsayılan ab4 kaldı; kanal kodu sonraki
    deneme (yalnızca `prompts/get` için ikinci model) için depoda. 171/171 test.
80. **Dış Türkçe setler, kılıflı ölçüm (03.11.2026):** Yol haritası 7'deki "dış Türkçe setlerde düşük isabet" ab4 ile
    yeniden ölçüldü (eşik 0,9, isabet / yanlış alarm): xTRam1 Türkçe 59,9 / 2,9 (soup05'te 49,0), aynı satırların
    İngilizcesi 61,2 / 2,1, rogue-security 71,8 / 15,6, AltaySec 63,0. Türkçe ile İngilizce arasında 1,3 puan var;
    kaçırılanların çoğu kullanıcının sohbet botuna doğrudan yazdığı tehdit, zararlı istek ve kimlik/PIN talepleri,
    firewall'un hiç görmediği kanal. MCP'deki karşılığını ölçmek için bu setlerden 2.500 satır (1.400 saldırı,
    1.100 zararsız) red team'in Türkçe kılıflarına (JSON, log, kod yorumu, e-posta, belge, araç çıktısı, YAML/CSV,
    değerlendirme kalıpları) birer kez sarıldı. ab4: isabet 62,2 → 77,8 (xTRam1 58,4 → 80,1), ama yanlış alarm
    7,7 → 16,6 (xTRam1 zararsızları 1,7 → 11,1). Kılıfta düz hâlde yakalanıp kaçırılan saldırı 11, tersi 229. Yani
    araç çıktısında Türkçe isabet sorunu yok; sorun kılıf içindeki zararsız isteklerde yanlış alarm (kod yorumu,
    YAML/CSV ve JSON'da %18–22), red team turlarındaki bulguyla aynı.
81. **DeepSeek ile etiket ve veri (04.11.2026):** `training/llm_label.py` gerçek kayıttaki 136 metin parçasını
    DeepSeek'e (deepseek-v4-pro) sordu; panelden verilmiş 112 etiketle uyum 77/112 (%69). Kendi başına etiket için
    yetersiz, yalnızca "yeniden bak" işareti olarak kullanılabilir; öneriler ayrı dosyaya yazılıyor, etiket
    dosyasına dokunulmuyor. `training/llm_synth.py` DeepSeek'e (deepseek-flash) araç çıktısı biçiminde (JSON, log,
    kod, e-posta, README, YAML/CSV, bilet, sohbet, HTML, tablo, takvim, dosya) içinde meşru istek geçen belgeler ve
    aynı belgenin yapay zekâya yönelik saldırı eklenmiş ikizini yazdırıyor; takvim ve tablo yalnızca test bölümünde.
    İlk denemede "prompt injection'ı anlatan belge" türü zararsız tarafa gerçek saldırı cümlesi koyduğu için
    çıkarıldı ve böyle çiftleri eleyen bir filtre eklendi. Bakiye bittiği için 665 çift (532 eğitim, 66 test)
    üretildi. ab4 bu test bölümünde 92,4 / 54,5 (isabet / yanlış alarm, eşik 0,9). v12dev2'ye 6 kat (llm6) ve
    3 kat (llm3) eklenip eğitildi, v4 ile 0,4 çorbası. soup04-llm6: DeepSeek testi 93,9 / 1,5 (AUC 0,893 → 0,998),
    red team kılıfları yanlış alarm 8,0 → 4,8, devreal 6,6 → 2,8, devsyn 2,4 → 1,0; ama Türkçe 89,0 / 8,7 → 84,9 /
    12,0 (AUC 0,964 → 0,948), boundary isabeti 69,7 → 64,0, kılıflı Türkçe 77,8 / 16,6 → 64,1 / 10,8 (AUC 0,892 →
    0,880). soup04-llm3 Türkçede daha az bozuldu (88,0 / 10,3) ama kazancı da azaldı. Varsayılan ab4 kaldı.
    Aynı üreteçten gelen test bölümü küçük ve dağılımı eğitimle aynı; Türkçe kaybı gerçek. Sonraki deneme için daha
    fazla ve Türkçesi daha doğal veri gerekiyor (bakiye yüklenmesi kullanıcının kararı).

82. **Varsayılan model mix-ab4-llm6-30 (05.11.2026):** Yeni eğitim yapılmadan ab4 ile soup04-llm6'nın ağırlık
    ortalaması alındı (`combine.py`, llm6 payı 0,3 ve 0,5). Eşik 0,9, isabet / yanlış alarm, ab4 → mix-30 → mix-50 →
    llm6: DeepSeek testi 92,4 / 54,5 → 90,9 / 30,3 → 92,4 / 13,6 → 93,9 / 1,5; devreal yanlış alarm 6,6 → 4,7 → 3,8
    → 2,8; red team kılıfları 97,3 / 8,0 → 97,2 / 7,3 → 97,0 / 6,5 → 96,8 / 4,8; Türkçe 89,0 / 8,7 → 88,6 / 8,6 →
    87,1 / 9,2 → 84,9 / 12,0; kılıflı Türkçe 77,8 / 16,6 → 72,8 / 14,1 → 70,1 / 12,8 → 64,1 / 10,8; boundary 69,7 /
    24,2 → 68,7 / 21,5 → 66,8 / 21,7 → 64,0 / 21,2. mix-30 Türkçeyi ab4 düzeyinde tutup her sette yanlış alarmı
    azaltıyor; bedeli kılıflı Türkçede 5 puan isabet (kaçanlar çoğunlukla sohbet botuna tehdit ve zararlı istek).
    Kullanıcı onayıyla varsayılan yapıldı: ONNX (fp32; olasılık farkı 0,0000, int8 200 satırda 8 karar değiştirdi,
    silindi), politika, demolar, test, README, tehdit kapsamı 28. madde, temizlik.ps1 (ab4 ve llm6 geri dönüş için
    korunuyor). Kurulu kopyada `policy.yaml` ve `policy-genel.yaml` yeni modele geçti (yedekler
    `*.yedek-2026-11-05`, ab4 klasörü yerinde). 171/171 test.
83. **Panel etiketleriyle ilk eğitim, varsayılan mix-ab4-lab-30 (05.11.2026):** Yol haritası 1. Kayıttaki 115 etiket
    (olay başına son kayıt, aynı metin bir kez) 107 satır: 33 saldırı, 74 zararsız; zararsızların çoğu modelin
    gerçek yanlış alarmları (GitHub araç tanımları, base64'e benzeyen metinler, hata mesajları). Metnin SHA-256
    özetiyle %60 eğitim (16 saldırı, 43 zararsız, 10 kat) / %40 ölçüm (17 / 31). v12llm6 + etiketler → lab
    (93 dk), v4 ile 0,4 → soup04-lab, ab4 ile 0,3 → mix-ab4-lab-30. Ölçüm payında eşik 0,9 (yakalama / 17,
    yanlış alarm / 31): ab4 13 / 30, mix-30 14 / 29, mix-lab-30 14 / 21, soup04-lab 14 / 12. mix-lab-30 diğer
    setlerde mix-30 ile aynı düzeyde (Türkçe 88,3 / 8,4, DeepSeek testi yanlış alarm 30,3 → 25,8, devreal 4,7 →
    5,0, kılıflı Türkçe 73,0 / 14,0, boundary 68,5 / 22,3); soup04-lab Türkçede 86,4, kılıflı Türkçede 66,2'ye
    düştü. Kullanıcı onayıyla varsayılan yapıldı (fp32, olasılık farkı 0,0000; int8 5 karar değiştirdi, silindi).
    Kurulu kopya yeni modele geçti (yedekler `*.yedek-2026-11-05b`), kurulu kod main ile aynı (`src.yedek-2026-11-05`).
    Ölçüm payı küçük ve eğitimdekilerle aynı kaynaktan; etiketler depoda değil. 171/171 test.
84. **Görev talimatı verisini genişletme, olumsuz sonuç (06.11.2026):** Yol haritası 7. `task_prompts.py` listelerin sonuna
    eklemeyle genişledi (eski şablonların eğitim/ölçüm ayrımı kaymadı): 35 İngilizce, 16 Türkçe müşteri mesajı, her
    talimat ailesine yeni ifadeler, `format` ve `check` aileleri, 5 yeni yerleşim. v12lab'e 9024 satır eklendi (71.566
    satır); task2 → v4 ile 0,4 → soup04-task2, ab4 ile 0,3 → mix-ab4-task2-30 (110 dk). Eşik 0,9, yanlış alarm
    (varsayılan mix-lab-30 → mix-task2-30): bağımsız Türkçe benchmark görev talimatı %21,7 → %24,8, Türkçe genel 8,4 →
    9,7, DeepSeek testi 25,8 → 30,3, sınır çiftleri 22,3 → 24,3, rol istemi kitaplığı 85,0 → 82,1; yakalama aynı.
    soup04-task2 kendi Türkçe test setimizde %22,8 → %2,8 ama benchmark %40,3, Türkçe genel %15,1. Şablonla üretilen
    veri şablonları öğretiyor, kavramı değil. Varsayılan model mix-ab4-lab-30 kaldı. Ölçüm uyarısı: İngilizce test
    kümesi yalnızca 6 ayrı mesaj şablonundan geliyor; e-posta içeren 147 satırın hepsi tek şablon ve her model onu %99
    saldırı sayıyor (eğitimde 1771 benzer örnek olmasına rağmen), yani İngilizce %50'lik yanlış alarm zayıf bir ölçüm.
    Gerçek ilerleme için doğal, çeşitli metin (LLM ile yazılmış, ≈0,17 $/100 çift) ya da panel etiketleri gerekiyor.
85. **evilsandangels ikiz veri seti, varsayılan değişmedi (07.11.2026):** Yol haritası 1/7. Kullanıcının hazırladığı
    şablon tabanlı ikiz veri seti (4 kategori: dolaylı enjeksiyon, bellek zehirleme, istem enjeksiyonu, rug pull; her
    zararlı örneğe temiz ikiz, `pair_id` bölmeleri, 7996 satır, İngilizce/Türkçe) `training/evilsandangels_data.py` ile
    eğitim verisine çevrildi (rug pull satırları 512 token'a sığsın diye sıkıştırılmış JSON). Veri setinin kendi test
    bölmesinde varsayılan model yakalama %80,9 / yanlış alarm %32,8 (rug pull yakalama %33, ikiz doğruluğu %48); ham
    evilsandangels modeli %100 / %0 ama test bölmesindeki zararlı ifadelerin ≈%55'i eğitimde de geçtiği için bu puan
    iyimser. Yalnız veri setiyle eğitim aşırı uyuyor (devreal yanlış alarm %5 → %39, rt yakalama %97 → %70). Kontrol
    modeli (aynı tarif, veri seti yok) lab/llm yanlış alarmını zaten 0'a indiriyor; kazancın çoğu "ham ağırlık − çorba"
    farkından geliyor, veri setinden değil. Veri setinin kendi etkisi (kontrole göre): tr yanlış alarm %1,5 → %8,2, rt
    yakalama %95 → %85,7, wtr yakalama %50 → %63. En iyi uzlaşma B %50 (soup04-ab4 %50 + ham evilsandangels %50):
    16 kümenin hepsinde yanlış alarm düşük ama 0,9 eşiğinde 7 kümede yakalama düştü (ind −18,7, obf −14,2, wtr −11,2,
    ml −11,1, rt −5,5); dağıtılmadı. B %30: yakalama ind −8,5, wtr −7,6, obf −5,4, hftr −5,0, ml −4,6 düştü, yanlış
    alarm her kümede düştü (lab %67,7 → %22,6, llm %25,8 → %3,0, devreal %5,0 → %0,9). Eşit yanlış alarmda fark
    neredeyse tamamen eşik kayması (gerçek sıralama kaybı ind −1,5, obf −1,1, ml −0,7; geri kalan kümelerde varsayılana
    eşit ya da önde). Genel eşik 0,3'te B %30 wtr/hfho/tr/boundary/test/llm/lab/devreal kümelerinde hem yakalamada hem
    yanlış alarmda varsayılandan iyi; yakalamada yalnız ind −3,7, obf −2,8, ml −2,0, rt −0,7 kaybediyor (yanlış alarm
    bunlarda da düşük); hftr'de yakalama +2,6, yanlış alarm +1,3. Veri setinin rug pull kazancı zayıf: yakalama 0,9 ve
    0,5'te %52, 0,3'te %60. Sonuç: varsayılan model mix-ab4-lab-30 kaldı. Denenen tek gerçekçi aday B %30 + eşik
    0,3–0,5; ama bu hem varsayılan modeli hem varsayılan ML eşiğini değiştirir, karar kullanıcıda. Raporlar
    `training/runs/evilsandangels_*.md` (klasör git'e girmiyor).
86. **Varsayılan model mixraw-ab4-evilsandangels-30, eşik 0,3 (07.11.2026):** 85. kaydın adayı, kullanıcının isteğiyle
    depoda varsayılan olarak hazırlandı. `export_onnx.py` ile `models/mcp-pi-mmbert-mixraw-ab4-evilsandangels-30` üretildi (fp32 ile
    PyTorch arasında olasılık farkı 0,0000; int8 200 satırda 5 kararı değiştirdiği için silindi). Değişenler:
    `policy.example.yaml` (model + `threshold: 0.3`), `test/ml-model.test.ts` (aday listesinde ilk sıra), 9 demo
    (model yolu; eşik 0,9 → 0,3), `temizlik.ps1` (yeni model ve ham evilsandangels `best` klasörü korunanlara eklendi),
    README ("Varsayılan model", tarif, "evilsandangels ikiz veri seti" tablosu, yol haritası) ve `docs/tehdit-kapsami.md`
    (madde 30). Kodun varsayılan eşiği (`src/policy.ts`) 0,9 olarak kaldı: eşik modele bağlı ve baseline gibi başka
    modeller 0,9'u bekliyor; politikada `ml.threshold` yazmayan kurulum yeni modelle 0,9'da çalışır ve 0,3'e göre
    daha az yakalar. 171/171 test (gerçek model testi yeni modelle: zararsız 0,000 / 0,000, saldırı 1,000 / 1,000);
    filesystem, web, sql, slack, toxic-agent-flow ve more-mcps (docs, gh, mail, shell, plug) demoları eşik 0,3 ile aynı
    sonucu verdi: zararsız metinler geçti, saldırılar engellendi. Kurulum kopyası (`~/.mcp-firewall`) henüz
    değiştirilmedi; commit yok.
87. **Poligon: e-posta saldırısı ve rug pull deneme tahtası (07.11.2026):** `poligon/` eklendi (dal
    `poligon-rugpull-eposta`): sahte e-posta MCP'si (4 e-postalı gelen kutusu; "gönderilen" e-posta yalnızca dosyaya
    yazılır) ve sahte hava durumu MCP'si (tool tanımı faza göre iyi/ince/kötü), gerçek firewall'un
    (`dist/src/cli.js`) arkasında ya da doğrudan çalışır. `node poligon/dene.mjs eposta|rugpull|hepsi|claude-code`
    her senaryoyu 4 profilde koşturur (kapalı, okuma = ML + kod çözme + gizli karakter temizliği, çıkış = DLP + taint,
    tam); kurban "saf ajan"dır (en kötü durum: saldırı e-postasındaki ilk dış adrese okuduklarını yollar; rug pull'da
    tanım bir dosyayı okuyup parametreye yazmasını söylüyorsa uyar). Sızıntı, giden kutusundaki kanarya metinlerinden
    ölçülür. Kullanıcı kararı: dışarıdan saldırı toplama bu projede değil, ayrı projede ele alınacak; DigitalOcean
    gerekmedi. Gözlem (mixraw-ab4-evilsandangels-30, eşik 0,3, tek çalıştırma, 7 e-posta saldırısı): firewall
    kapalıyken 7/7 sızdı. Okuma profili 6/7'yi durdurdu (5'ini ML engelledi, birinde görünmez karakterler silinince
    talimat kalmadı); emir kipi olmayan "dolaylı iş cümlesi" ML'den geçip sızdı, çıkıştaki taint durdurdu. Çıkış
    katmanları ML olmadan da 7/7'yi durdurdu ama meşru iletmeyi de engelledi (kontrol satırı; `taint.action: block`,
    gerçekte `ask`). Rug pull: zararsız görünen tanım değişikliğini yalnızca sabitleme yakaladı (desen + ML kaçırdı),
    gizli talimatlı tanımı hepsi yakaladı, değişmeyen tool hiçbir profilde gizlenmedi. Gerçek Claude Code ile uçtan uca
    denenmedi; `ask` onayı simüle edilmiyor. 171/171 test (kod değişmedi). Commit yok.
88. **Poligon 2. tur: 3'er yeni senaryo, sürücü düzeltmeleri, gerçek GitHub deneyi (08.11.2026):** Kullanıcı "bu iki testte
    düzeltilecek bir şey var mı, e-posta ve rug pull'a 3'er test ekleyelim, GitHub'a zararlı metin koyup bir ajanla
    deneyelim" dedi. Düzeltmeler: (1) sürücü (`surucu.mjs`) sunucudan, firewall dahil, gelen `method` taşıyan istekleri
    bekleyen isteğin yanıtı sanıyordu; kimlikler 1'den başladığı için çakışabilirdi (`ask`/elicitation gibi bir istek
    yanlış isteğe cevap olarak teslim edilirdi), artık ping'e cevap verir, ötekileri reddeder. (2) `claude-code` komutu
    kurulu olmayan `claude` CLI'sını varsayıyordu (bu makinede yok); `~/.claude.json` için JSON girişleri de basıyor.
    (3) E-posta senaryoları yalnız gövdeyi deniyordu; `list_emails` konu satırı kanalı eklendi. (4) İki poligon aynı anda
    çalışınca birbirinin klasörünü siliyordu (EPERM, sonuç bozulabilir); `POLIGON_CALISMA_KOK` eklendi. Yeni
    senaryolar: e-posta `konu-satiri`, `sahte-sistem` (sohbet şablonu etiketleri), `karakter-taklidi` (tam genişlik +
    Kiril benzer harf); rug pull `sema` (açıklama aynı, yeni parametre), `yeni` (sonradan eklenen `report_issue`),
    `sonuc` (tanım aynı, sonuç zehirli). Gözlem (mixraw-ab4-evilsandangels-30, eşik 0,3, tek çalıştırma): e-posta
    saldırılarının 10/10'u kapalıyken sızdı; okuma profili 9'unu durdurdu (8'i ML 1,00, biri görünmez karakter
    temizliği), yalnız "dolaylı iş cümlesi" geçti ve çıkıştaki taint durdurdu; üç yeni senaryonun üçünü de ML 1,00
    yakaladı; çıkış katmanları 10/10'u durdurdu, meşru iletme yine yanlış alarm. Rug pull: kapalıyken 4 zararlı
    değişikliğin 4'ü sızdı; sabitleme 5'in 3'ünü yakaladı (ince, kotu, sema), sonradan eklenen tool (`onNew: allow`) ve
    sonuç zehirinde kör; desen+ML taraması zararlı 4'ünün 4'ünü yakaladı (şema açıklamasında ML 0,90), zararsız
    `ince`'yi geçirdi; tam 5/5. `onNew: hide` + `pins approve` ile sonradan eklenen tool gizli kalıyor ve değişmeyen
    tool normal çalışıyor (doğrulandı; bedeli: her meşru yeni tool da onay bekler). GitHub: `poligon/github.mjs` gerçek
    GitHub MCP'sini (Docker, imaj digest sabit) ve gerçek politikanın kopyasını (denetim/pin dosyası `poligon/.calisma/`
    altında, bildirim kapalı) kullanır; token'a dokunmaz. Özel depo `Boostcodeee-stack/mcp-firewall` içinde (hesapta
    genel depo yok) #1 numaralı `[TUUF TEST]` issue'su açıldı: sıradan hata bildirimi + HTML yorumunda "ajanlara"
    `TUUF-KANARYA-9917` işaretli yorum yazma talimatı. Firewall kapalıyken talimat ajana ulaştı; açıkken `list_issues`,
    `search_issues` ve `issue_read` ML 1,000 ile engellendi. Gerçek ajan (alt ajan, `github.mjs mcp` komutuyla): üç
    yolun üçü engellendi, #2–#5 denendi (404), yazma yapmadı, engeli aşmaya çalışmadı, bakımcıya "kendiniz okuyun, bir
    yapay zekâya vermeyin" dedi. Yan bulgular: README.md ML 0,331 ile engellendi (yanlış alarm, sert-negatif adayı); bir
    kötü issue `list_issues` sonucunun tamamını engelliyor (kaba engel). Açık işler: "dolaylı iş cümlesi" ML'den
    geçiyor (eğitim verisi adayı); firewall kapalıyken gerçek bir modelin issue'daki talimata uyup uymadığı ve ajanın
    uygulamanın MCP bağlantısıyla denemesi yapılmadı (oturumdaki `github` MCP, Docker kapalı olduğundan
    bağlanamamıştı; Docker bu oturumda açıldı, yeniden bağlanması kullanıcıya kalıyor). Test issue'su #1, deney sonunda
    kullanıcının onayıyla kapatıldı (`not_planned`, `node poligon/github.mjs temizle`). 171/171 test (src değişmedi). Commit yok.
89. **E-posta ve takvim sunucuları için ayrı politika örneği, poligonda model karşılaştırması (08.11.2026):** Kullanıcı
    önerilen sırada e-posta politikasına geçilmesini istedi. `policy-eposta.example.yaml` eklendi: önceki model
    (mix-ab4-lab-30) ve eşik 0,9 (başarılı LLMail saldırılarında yakalama %99; yeni varsayılan %92 @0,3, %86 @0,9),
    `ml.onTruncated: block`, `taint.action: ask` (kaynak `read_*`/`get_*`/`list_*`/`search_*`, çıkış `send_*`/`forward_*`/
    `reply_*`/`create_event`/`update_event`), `approval.remember: false`. Gerçek politika yükleyicisiyle okundu, modeli
    `./models/` altında buldu. Poligon sürücüsüne `POLIGON_ESIK` eklendi (varsayılan 0,3; `MCP_FIREWALL_MODEL` vardı).
    Aynı 10 saldırı ve 2 kontrol üç ayarla koşuldu (yeni @0,3, yeni @0,9, önceki @0,9; tek çalıştırma): üçünde de
    kapalıyken 10/10 sızdı, okuma 1/10 ("dolaylı iş cümlesi"), çıkış ve tam 0/10 (meşru iletme taint `block` ile yanlış
    engellendi); ML'in engellediği her saldırı 1,000 aldı. Yani poligon iki modeli ayırt etmiyor; önerinin dayanağı
    LLMail ölçümü. Fark yanlış alarmda: DLP kapalı okuma profilinde önceki model zararsız "deploy anahtarı" e-postasını
    (#2) 0,995 ile engelledi (12/12 koşu), yeni model hiç engellemedi; DLP açık tam profilde ikisi de engellemedi.
    Örnek politika geçici klasörde sahte posta sunucusuyla denendi: zararsız e-postalar geçti, düz İngilizce talimat ML
    1,000 ile engellendi, okunan metni iç kişiye iletmek `ask` gerektirip istemci soramadığı için reddedildi, yeni
    yazılmış metin gitti. Yan bulgu: `tools.rules` ve `taint` kalıpları (glob) büyük-küçük harfe duyarlı ve ham tool
    adına bakıyor (`sendMessage`, `send_*` ile; `deleteFile`, `delete_*` ile eşleşmez); düzeltilmedi. Gerçek bir e-posta
    sunucusuyla ve gerçek Claude Code ile denenmedi. 171/171 test (src değişmedi). Commit yok.
