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
90. **Sunucu sandbox'ı, Docker başlatıcı (08.11.2026):** Önerilen sıranın üçüncü adımı; en büyük yapısal boşluk: sunucu
    süreci makinede tam yetkiyle çalışıyor, firewall yalnızca stdio'yu görüyor. `src/sandbox.ts` eklendi; politikaya `sandbox:`
    bloğu (`enabled`, `image`, `pull`, `network`, `readOnly`, `tmpfsSize`, `user`, `memory`, `cpus`, `pidsLimit`, `mounts`,
    `env`, `workdir`), CLI'ye `--sandbox <image>` ve `mcp-firewall sandbox show` geldi. Açıkken firewall sunucunun yerine
    `docker run --rm -i --init --pull never --network none --cap-drop ALL --security-opt no-new-privileges:true --read-only
    --user 65534:65534 --memory/--memory-swap/--cpus/--pids-limit ... --entrypoint <komut> <image> <argümanlar>` başlatıyor;
    `--` sonrasındaki komut konteynerin içinde çalışıyor. Kararlar: ham docker bayrağı yok (bilinmeyen anahtar hata, `extraArgs`
    için nedeni söyleniyor), `network: host` ve `container:` yok, ortam değişkenleri `-e ADI` ile adıyla geçiyor (değer komut
    satırına girmiyor, eksik değişken hata), klasör `--mount type=bind` ile ve varsayılan salt okunur bağlanıyor; sürücü kökü,
    ev dizini ve onu içeren üst klasörler, `~/.ssh` `~/.aws` `~/.gnupg` `~/.docker` `~/.kube` `~/.azure` `~/.config/gcloud`
    `~/.mcp-firewall` `~/.claude` `.npmrc` `.pypirc` `.netrc` `.git-credentials`, politikanın kendi klasörü, denetim günlüğü, pin
    dosyası, taint dizini, ML modeli ve Docker soketi/pipe reddediliyor; başlarken sembolik bağlar çözülüp yeniden denetleniyor.
    Sunucu kodu sabitleme bu modda image'ın içerik kimliğini (`docker image inspect`) hash'liyor: etiketle verilirse uyarı,
    kimlik değişirse `initialize` anında "server code changed" ile kesiliyor. Docker kapalıysa ya da image yerelde yoksa
    (`pull: never`) firewall başlamıyor ve ne yapılacağını söylüyor. Çıkışta ve sinyalde konteyner adıyla `docker kill`
    çağrılıyor (Windows'ta docker istemcisini öldürmek konteyneri durdurmaz). Testler: 29 yeni, 200/200 geçti.
    `test/sandbox.test.ts` birim testleri (politika doğrulaması, bağlama koruması iki platform yoluyla, komut satırı sırası,
    ad üretimi, image kimliği); `test/sandbox-cli.test.ts` PATH'teki sahte `docker` ile gerçek CLI'yi sürüyor (komut satırı,
    stdio hand-over, konteyner durdurma, image pini, yeniden derlenen image'ın reddi, Docker kapalı/image yok iletileri,
    `sandbox show`). Gerçek Docker Desktop'ta (Windows) denendi: alpine konteynerinde kullanıcı `nobody`, `touch /x`
    "Read-only file system", `/tmp` yazılabilir, `network: none` iken `wget` "bad address" (`bridge`'de çalışıyor), `CapEff`
    sıfır, salt okunur bağlamaya yazılamadı, yazılabilir bağlamadaki dosya ana makinede göründü, `/root` açılamadı; GitHub MCP
    v2.0.3 (46 tool, sahte token) firewall CLI'si üzerinden `network: none` ile `initialize` ve `tools/list`'e cevap verdi
    (`docker inspect`: `net=none ro=true user=65534:65534 caps_drop=[ALL] mem=512 MB pids=256`), çıkışta konteyner kalktı,
    firewall `SIGKILL` ile öldürülünce de 1 saniyede kalktı. Bulgu: `bridge` ağındaki konteyner, yalnızca `127.0.0.1`'e bağlı
    bir yerel HTTP servisine `host.docker.internal` ile ulaştı (`none` iken ulaşamadı); yani ağ verilen sunucu firewall'un
    paneli dahil yerel servisleri görür, README'ye yazıldı. Yan etki: Docker Desktop bu oturumda açıldı. Eksik: adres bazlı
    çıkış izin listesi (Docker sunmuyor; iç ağ + proxy gerekir), sürümü sabit paketle image kuran `sandbox build` yardımcısı,
    Podman, macOS/Linux; README'deki Dockerfile örneği derlenmedi. Commit yok.
91. **Yayımlanmış benchmark'larla ölçüm ve rakip karşılaştırması (09.11.2026):** Rakip karşılaştırması bu kez birincil
    kaynaklara (ürünlerin README ve belge sayfaları) ve yayımlanmış benchmark'lara dayandırıldı; hiçbir rakip
    çalıştırılmadı. Agent Egress Bench'in (PipeLab, korpus v2.16.0) 270 vakasından MCP biçimli 87'si ölçüldü: kendi
    çalıştırıcım (`bench/aeb/run.mjs`; çalıştırıcıya ait üst akış dinleyicisi, teslim kanıtı, yapısal ret işareti, stdio
    için CLI, HTTP için gateway, vaka başına yeni süreç ve yalıtılmış HOME) dört yapılandırmada koştu. Katı engelleme:
    politikasız %18, kurulu politika %24, `policy.example.yaml`+ML %44, +`dlp.action: block` %53; zararsız 25 vakada
    yanlış alarm 0–1. En güçlü yapılandırmada kaçırılan 29 vakanın 17'si README'de iddia edilmeyen alanlar (kabuk gizleme,
    kripto, çağrı bütçesi, istemci argümanında enjeksiyon, zincir sezgileri), 1'i `taint` oturum moduyla kapanıyor (sondaj
    koşusuyla kanıtlandı), 10'u mevcut özelliklerin kenar durumları: `decode.ts` ara katman hash gibi göründüğü için
    base64(hex(...))'e inmiyor; istek argümanında sıfır genişlikli karakter; komşu alanlara bölünmüş sır; DLP'de
    `sk_test_` kalıbı yok; aynı envanterde Kiril/Latin benzeri araç adı; `tools/list` yanıtındaki `instructions`; sahte
    PNG başlığı arkasındaki kimlik bilgisi; araç tanımında `_meta` içindeki opak içerik. Tek yanlış alarm:
    `[REDACTED_BY_TOOL]` yer tutucusu ML'de 0,967 (yalnızca ürünün kendi `[REDACTED:…]` işareti nötrleniyor). BIPIA'nın
    Liu 2026 yöntemiyle kurulan eşleşmiş kümesi (1.200 zararsız + 2.435 enjekte; makalenin sayılarıyla birebir) üç modelle
    ve ProtectAI v2 taban çizgisiyle puanlandı; taban çizgisi benchmark'ın kayıtlı skorlarını yeniden üretti (TPR@%1YA
    %0,7 = %0,7). B30 %1 yanlış alarmda %23,6 (e-posta %22, tablo %17, eğitimde ailesini gördüğü kod %98); gönderilen eşik
    0,3'te zararsız bağlamların %21'i işaretleniyor. Eğitim kümesi InjecAgent ve AgentDojo hedeflerini ve BIPIA'nın
    yalnızca kod saldırılarını içerdiğinden sonuçlar suit bazında verildi; AgentDojo ve tau-bench ölçülmedi (üçüncü taraf
    kodu çalıştırma izni verilmedi). Düzenek doğrulaması: `defaults` ikinci koşuda 87/87 aynı sonuç, Python
    `extractMlText` taşıması derlenmiş TypeScript'le 600 örnekte sıfır farkla eşleşti. Dosyalar:
    `docs/benchmark-karsilastirmasi.md`, `bench/` (betikler, ham sonuçlar). Yan etki: ilk duman testleri `defaults`
    profiliyle çalışırken gerçek `~/.mcp-firewall/mcp-firewall-audit.jsonl` dosyasına 27 satır (`server: aeb`) ve pin
    dosyasına bir `aeb` girdisi yazdı; kaynak kapatıldı (HOME yalıtımı + koşu sonu sayaç denetimi), temizlik kullanıcıya
    bırakıldı. Commit yok.
92. **Kenar durum boşlukları kapatıldı (09.11.2026):** 91'deki ölçümün "mevcut özelliğin kenar durumu" sınıfındaki 10 AEB
    vakası için kod düzeltildi; 12 yeni test, 212/212. (1) `decode.ts`: base64(hex(...)) çözülmüyordu, çünkü ara katman
    (rakam ağırlıklı hex) "okunabilir metin" kuralına takılıp atılıyordu; `DECODERS`'a üçüncü eleman olarak `layer`
    eklendi: ara katman yalnızca yazdırılabilir ASCII ve tek bir kodlanmış koşuysa (`ENCODED_RUN`) içine inilir, ara
    katman kaydedilmez. (2) `dlp.ts`: `scanText` görünmez karakterleri (`stripInvisible`: yumuşak tire, sıfır genişlikli,
    bidi, tag, varyasyon seçici) atlayarak tarıyor; temizlenmiş kopya yalnızca secret bulununca iletilen metnin yerini
    alıyor. (3) `dlp.ts`: `splitFindings` yan yana duran en çok 4 kısa (en çok 128 karakter) dizgiyi birleştirip yalnızca
    sabit önekli dedektörlerle (AWS, GitHub, Slack, Anthropic, OpenAI, Stripe) arıyor ve alan sınırını geçen eşleşmeleri
    sayıyor; rakam desenleri (kart, TCKN, IBAN) bilerek dışarıda, çünkü rastgele eşleşir. Böyle bir secret yerinde
    maskelenemediği için `proxy.ts` `applyDlp` onu `dlp.action: warn` dışında engelliyor. (4) `dlp.ts`: `mediaFindings`
    `image`/`audio` ve resource `blob` baytlarının yazdırılabilir koşularını DLP'den geçiriyor (sahte PNG başlığı
    arkasındaki kimlik bilgisi); kart/TCKN/IBAN hariç, 8 MB sınırı; bulunursa engel. (5) `dlp.ts`: `stripe_key`
    (`sk_`/`rk_` + `test`/`live`). (6) `engine.ts`/`decode.ts`: `scanToolDefinition` bir sözcükte Latin harfi ile
    Kiril/Yunan benzerini karıştıran araç adını (`mixesLookAlikes`) ve tanımda `data` + `mimeType` ya da `encoding:
    base64` taşıyan, ne gerçek görsel ne okunur metin olan nesneyi (`opaqueBlobs`, `looksBinary`) işaretliyor; ikisi de
    `descriptionScan.hiddenUnicode`'a bağlı, yeni ayar yok. (7) `proxy.ts` `filterToolsList`: `tools/list` yanıtındaki
    `instructions` artık `initialize`'dakiyle aynı taramadan geçiyor (düşmanca olan siliniyor, yanıt iletiliyor). Ölçüm:
    aynı AEB çalıştırıcısı ve dört yapılandırma, düzeltilmiş derlemeyle: katı engelleme %18→%31, %24→%37, %44→%56,
    %53→%68; 10 hedeften 9'u katı engele döndü, `mcp-tool-instructions-exfil-017` etkisizleştirip iletiyor; bozulan vaka
    ve yeni yanlış alarm yok; son iyileştirmeden (`looksBinary`) önceki ve sonraki derleme iki koşuda birebir aynı çıktı
    verdi. Maliyet: 50.000 kısa dizgili dizi 191 ms, 3.000 kayıt × 6 alan 72 ms, 5 MB görsel 12 ms. Yan etki: `sk_test_…`
    anahtarları (belge örnekleri dahil) artık maskeleniyor. Dosyalar: README tehdit eşlemesi ve sınırlamalar,
    `policy.example.yaml` yorumları, `docs/tehdit-kapsami.md` DLP satırları, `docs/benchmark-karsilastirmasi.md` 2.5,
    `bench/sonuclar/*-sonrasi*`. Kalan: `[REDACTED_BY_TOOL]` yanlış alarmı (yalnızca ürünün kendi `[REDACTED:…]` işareti
    nötrleniyor). Commit yok.

93. **Gemini incelemesi: üç bulgu yeniden üretildi ve kapatıldı (10.11.2026):** `gemini-inceleme/` paketiyle (çekirdek
    + son tur farkı) Gemini'ye yaptırılan inceleme üç "kritik" bulgu verdi. Her biri önce gerçek koda (`dist/`,
    yalıtılmış HOME) karşı yeniden üretildi, sonra başarısız test yazıldı, sonra düzeltildi: 8 yeni test, 220/220;
    gerçek denetim kaydına dokunulmadı. (1a) DOĞRU: `decodeEmbedded` görünmez karakterlere bakmıyordu (`scanText`
    bakıyor), bu yüzden base64'lenmiş AWS anahtarının ortasına sıfır genişlikli karakter, yumuşak tire ya da varyasyon
    seçici koymak `encodedDlp`'yi atlatıyordu; denenen 10 karakterin hepsi geçiyordu. Düzeltme: `decodeEmbedded` metni
    bir de `stripInvisible`'dan geçirip yeniden geziyor (ham metin önce: tag karakterleri ve varyasyon seçiciler kendi
    başına bir kodlama); aynı kök neden ML ve regex taramasındaki `withDecoded`'ı da kapatıyor. (1b) KISMEN: Gemini'nin
    taint örneği yanlış okumaydı (`words()` sözcüklere bölmeden önce `\p{M}` işaretlerini siliyor, örnek zaten
    yakalanıyordu), ama iki dar delik gerçekti: base64'ün içine varyasyon seçici ve camelCase boğumuna varyasyon seçici
    (`unwrap` yalnızca `\p{Cf}` siliyordu, varyasyon seçici `Mn`). `unwrap` artık `stripInvisible` da uyguluyor.
    (2) DOĞRU, ama Gemini'nin önerdiği düzeltme yetmezdi: `extractText`/`extractMlText` protokol düzeyinde `_meta`'yı,
    `type: image|audio` nesnesini bütünüyle ve `blob` anahtarını atlıyordu; en kolay yol da istemciden bağımsızdı:
    `structuredContent` içinde `blob` ya da `_meta` adlı bir alan. `stripHiddenChars` da image nesnesini bütün
    döndürdüğü için "ön koşulu kaldır" önerisi image yan alanındaki ANSI'yi yine silmezdi. Düzeltme: iletinin modele
    gösterdiği şey için `extractMessageText` (`extractMlText` de bu kipte): `_meta` ve medya bloğunun yan alanları
    okunuyor; `data`/`blob` yalnızca uzun bir base64 koşusuysa ve alan bir yük taşıyorsa (`isPayload`) ikili sayılıp
    atlanıyor, okunur metne çözülen yük metin olarak okunuyor. Araç TANIMLARI eskisi gibi `_meta`'yı ve medyayı dışarıda
    bırakıyor (simgeler ve arayüz üst verisi orada). `applyHiddenText` ön koşulu `containsHiddenChars(value)` oldu.
    Aynı kök neden `encodedDlp`'de, `prompts/get` taramasında ve taint'in sink argümanlarında da vardı; üçü de
    `extractMessageText`'e geçti. (3) DOĞRU, ama batch gerekmiyordu: sunucu kodu kontrolü yalnızca el sıkışma yanıtında
    çalışıyordu; yanıttan önce gelen `elicitation`/`sampling` isteği (tek satır, iki satır ya da batch) istemciye
    geçiyordu, yanıt hiç gelmezse ya da istemci el sıkışmadan başlamazsa kontrol hiç çalışmıyordu. Düzeltme: kontrol
    sunucunun söylediği ilk mesajda çalışıyor (türü fark etmez; npx o zamana kadar kurulmuş oluyor), engellenirse o
    mesaj düşüyor ve bekleyen tüm istekler hata ile yanıtlanıyor (`refuseAll`). Batch'in parçalanarak iletilmesi
    güvenlik değil uyumluluk konusu, değiştirilmedi. Ölçüm (aynı gün, 35a1ce5 derlemesi): AEB'nin dört profili yeniden
    koşuldu, 87 vakanın hiçbirinin sonucu dünkü koşuyla değişmedi (katı engelleme 19/62, 23/62, 35/62, 42/62; yeni yanlış
    engel yok). AEB'de `_meta`, medya yan alanı ya da metin blob'u taşıyan sonuç olmadığı için bu davranış ayrıca A/B ile
    ölçüldü (gerçek model, kurulu politikanın kopyası, sahte sunucu): zararsız 12 biçimden hiçbiri engellenmedi ya da
    değiştirilmedi, eskiden geçen 4 saldırı biçimi artık engelleniyor (sentetik, küçük örneklem). BIPIA'nın 6000
    satırında ürün metni ve 1500'lük pencereler eski derlemeyle birebir aynı, yani skorlar değişmez. Ölçülmedi:
    Gemini'ye gitmeyen `gateway.ts` ile `sandbox.ts`. Dosyalar:
    `decode.ts`, `engine.ts`, `taint.ts`, `ml/classifier.ts`, `proxy.ts`, README ve `docs/tehdit-kapsami.md` sunucu
    kodu satırları. Commit yok.

94. **ChatGPT review: 5 finding, 2'si gerçek ve fixed, 1'i by design, 2'si low impact (10.11.2026):** Aynı paket (be51f21)
    ChatGPT'ye verildi; static review, kod çalıştırılmadı, Gemini'nin üç finding'ini bulmadı, beş farklı finding verdi. Her
    biri koda karşı kontrol edildi, önce failing test yazıldı. (1) "Critical": DLP JSON property name'leri (key) taramıyor:
    DOĞRU. `deepScan` yalnızca value'ları geziyordu; bir secret key olarak (düz ya da base64) DLP'yi, `encodedDlp`'yi ve
    taint sink'ini geçiyordu, `stripHiddenChars` key'lerdeki hidden character'ları temizlemiyordu. Aynı aileden, bu turda
    bulunan: `deepScan` bir media block'unu bütünüyle atlıyordu, yani `text`/`alt` side field'larındaki secret DLP'den
    geçiyordu. Fix: `deepScan` key'leri de tarıyor ve maskeliyor (iki key aynı placeholder'a inerse `#2`, `#3` ile ayrı
    kalıyor), media block'ta yalnızca `data` atlanıyor; `encodedDlp` ve taint sink'i key'leri `extractKeys` ile ayrıca
    okuyor (taint'te key'ler value metninin word stream'ine karışmasın diye ayrı fingerprint; karışınca "text cut into
    pieces over several calls" testi kırıldı); `containsHiddenChars`/`stripHiddenChars` key'lere de bakıyor. (2) "High":
    hidden tool, `tools/call` ile adıyla çağrılabiliyor: DOĞRU. `filterToolsList` tool'u listeden çıkarıyor ama call path
    bunu bilmiyordu; client'lar tool list'i cache'lediği için hidden (poisoned, changed, pending approval, name collision)
    bir tool çağrılabiliyordu. Fix: hidden isimler `hiddenTools` map'inde tutuluyor, `inspectToolCall` bu isimle gelen
    call'u reddediyor, temiz bir list gelince block kalkıyor. (3) "High": `failMode: closed` `warn` channel'ında block
    etmiyor: davranış doğru tarif edilmiş ama by design (warn = warn; classifier hatası warning log olarak yazılıyor).
    Bir testle sabitlendi; README ve `policy.example.yaml` açıklaması netleştirildi. (4) message queue sınırsız,
    (5) pending request table timeout'suz ve ID reuse context'i eziyor: kodda DOĞRU, impact low (server yalnızca kendi
    bağlantısını şişirebilir; ID reuse için client'ın MCP kuralını çiğnemesi gerekir), değiştirilmedi, README limitations'a
    eklendi. Raporun kendi sınırı: kod çalıştırılmadı, gateway/sandbox/paths'e bakılmadı. Ölçüm: AEB'nin dört profili aynı
    runner ile yeniden koşuldu, 87 case'in hiçbirinin sonucu önceki koşuyla değişmedi (strict block 19/62, 23/62, 35/62,
    42/62), yeni false positive ve error yok; gerçek audit log'daki 27 eski `aeb` satırı değişmedi. 6 yeni test (226/226).
    Dosyalar: `dlp.ts`, `engine.ts`, `taint.ts`, `ml/classifier.ts`, `proxy.ts`, README, `docs/tehdit-kapsami.md`,
    `policy.example.yaml`. Commit yok.

95. **Label kuyruğu: çok kısa sample'lar çıkarıldı (10.11.2026):** Kullanıcı EVT-1553'ü etiketleyemedi: kayıttaki metin
    `Invalid request parameters` (26 karakter), yani `fetch` server'ının `server/discover` handshake'ine verdiği error
    mesajı; `ml.review.sample` (%5 rastgele örnekleme) bunu kuyruğa yazmıştı, değerlendirilecek bir içerik yoktu. Fix:
    `mlFlags` rastgele sample için en az 40 karakterlik excerpt istiyor (`MIN_SAMPLE_CHARS`), near miss her uzunlukta
    kaydediliyor (eşiğin hemen altında kalan kısa bir saldırı etiketlemeye değer); dashboard (`ui/app.js`, `isShortSample`,
    `reasonRaw` üzerinden) eski kayıtlardaki kısa sample'ları "etiket bekleyen" saymıyor (kuyruk 1 → 0, "Modeli
    güçlendir" banner'ı kalktı, kayıt "Eşik altı" listesinde duruyor). Security scan değişmedi: error mesajları yine
    ML'den geçiyor, yalnızca review kuyruğuna yazılmıyorlar. 1 yeni test, mevcut sample testinin metni 40 karakterin
    üstüne çıkarıldı (227/227). Install copy'de değil. Commit yok.

96. **Held-out set, dış veri setleri ve gerçek tool tanımlarında bulunan ReDoS (10.11.2026):** Kullanıcı "senin üreteceğin
    veri setini varsayılan modelin yerine kullansak?" diye sordu; önce hiçbir modelin görmediği bir ölçü gerekiyordu.
    `bench/heldout/` (README'siyle): elle yazılmış 333 satır, 150 saldırı + 183 benign, 150 saldırının benign ikizi (minimal
    çift); tool tanımı, tool sonucu, prompt şablonu, elicitation/sampling, 10 kodlama/gizleme, İngilizce ve Türkçe.
    Eğitim ve eval verisindeki 146.068 satırla ilk 80 normalize karakterde 0 çakışma; satırlar eğitime girmez
    (`*.jsonl` git'e girmiyor, `build.mjs` yeniden üretiyor). Varsayılan model (B30, eşik 0.3): recall %95.3, false positive
    %12.6, AUC 0.977, %1 FPR'de recall %69.3, çiftlerin %83.3'ü temiz ayrılıyor (ilk raporda %98 görünen çift testi ham skorla
    yapılıyordu; iki metin de ~1.000'deyken sonuç float gürültüsüydü, eşikte yapacak şekilde düzeltildi). Yerel 8 modelin
    eşikten bağımsız metriklerinde (AUC, %1 ve %5 FPR'de recall, temiz çift) en iyisi B30; diğerlerinde FPR %17.5-24.6,
    AUC 0.936-0.962, protectai deberta-v3'te recall %60.7: önceki varsayılan kararı bağımsız veride de doğrulandı.
    Zayıf yerler: prompt channel'ında false positive %37.5 (ürün `promptResults: warn` ile yutuyor), zincirleme eylemler
    (audit log'u kapat, onayı kapat, izleri sil: recall %71), Türkçe dolaylı mail/ticket talimatı (2 kaçan), koşullu prompt
    şablonu, commit mesajına `cat .env` ekleten tool tanımı (ML skoru 0.003, "never commit .env" diyen benign ikizi 0.80:
    tanım channel'ında model emre değil konu kelimelerine bakıyor). Regex katmanı (`descriptionScan`; kurulu politikada
    `ml.scan.toolDefinitions: off` olduğu için tanımların tek koruması) held-out tanım saldırılarının 13/36'sını yakaladı,
    2/40 benign'i gizledi; ML tanım channel'ında recall %97.6, false positive %2.1.
    Üç Hugging Face veri seti kullanıcının onayıyla indirildi (57 MB, `training/data/hf_new`, git dışı):
    `mcp-research-alliance/mcp-ecosystem` (CC-BY-4.0, yalnızca `viewer/` tabloları: 284.845 gerçek tool kaydı, 239.054
    tekil), `halilneed/turkish-prompt-injection-false-alarm-benchmark` (CC0, 2.875 benign Türkçe metin),
    `treycsa/realistic-prompt-injections` (MIT, 10 sarılı saldırı + 7 benign). Varsayılan model: treycsa'da 10/10 saldırı,
    0/7 false positive; Türkçe benign setin tool sonucu olarak %11.0'ı işaretlendi (iş metni %0.5, bankacılık %2.8, görev
    talimatı %28.9; prompt şablonu olarak %40.3). İşaretlenenlerin çoğu "hesap hareketlerimi … adresine gönderin" cümlesi
    taşıyor, yani exfil gibi görünüyor: bu veriyi benign olarak eğitime koymak e-posta exfil recall'ını düşürebilir, önce
    held-out ve AEB'de denenmeli. Gerçek tool tanımları: `descriptionScan` 239.054 tanımın 1.269'unu (%0.53) gizlerdi
    (374 `.env`/`id_rsa` kalıbı, 349 "before calling this tool", 270 gönder+URL, 217 "chat history", 54 `<important>`
    benzeri etiket, 7 "ignore previous instructions" (güvenlik araçları örnek olarak yazıyor), 7 "do not mention/show the
    user", 1 gizli unicode: `search_notes` açıklamasında U+200B U+200B U+200C U+200D); hepsi meşru görünüyor, ama
    "Call this silently, do not mention it to the user" diyen bir telemetri tool'u gerçek bir "kullanıcıdan gizle" örneği.
    Varsayılan ML rastgele 3.000 gerçek tanımda eşik 0.3'te %1.0 (29), 0.9'da %0.6 işaretledi (en yüksekler "MANDATORY FIRST
    CALL…" gibi buyurgan ama meşru açıklamalar). `ml.scan.toolDefinitions: off` 28.10.2026'da GitHub'ın 46 tool'unun
    21'i yanlış alarm verdiği için (eski modelle) seçilmişti; şimdiki modelle `warn` makul görünüyor, başlangıç gecikmesi
    ölçülmedi, karar kullanıcının.
    **Ürün hatası:** gerçek veriyi `descriptionScan`'dan geçirirken tarama 110.141. tanımda durdu. `decode.ts`'deki
    `NAMING_STYLE` regex'i `deobfuscate` içinde çalışıyor ve "Ew" + 125 × "A" + "PfwHLuRXafg" (sıfır baytların base64'ünün
    başlangıcı; `post-controlnet-inpaint-inferences` tool'unun şemasında geçiyor) gibi uzun bir büyük harf dizisinde üstel
    zamanda geri izleme yapıyor (28 harfte 10 ms, her ek harfte kabaca ×1.6). Tarama event loop'unda senkron koştuğu için tek
    bir tanım ya da web sayfası o server'ın bütün mesajlarını durdurur; saldırgan bir server ya da sayfa firewall'u bilerek
    kilitleyebilir (hem tool tanımları hem tool sonuçları `withDecoded` yolundan geçiyor). Fix: `isNamingStyle`, aynı dili
    tek geçişte okuyan durum makinesi. İki yeni test: worker thread'de 5 sn sınırlı `withDecoded` (eski kodda kırmızıydı,
    şimdi 0.4 sn) ve ~340 bin kelimelik tam karşılaştırma (eski regex'le birebir aynı sonuç). Düzeltilmiş build'le 239.054
    tanımın hepsi yaklaşık 4 dakikada tarandı, başka takılma çıkmadı. Kurulu kopya hâlâ eski kodda: yenilenmeden bu açık
    orada duruyor. Tam paket 244/244 (aynı ağaçta başka bir oturumun lazy classifier testleri de var). Dosyalar:
    `src/decode.ts`, `test/decode.test.ts`, `bench/heldout/`. Commit yok.

97. **Bellek ve CPU: modeli her proxy'nin hemen yüklemesi bitti (10.11.2026):** Kullanıcı makinesinin çok yavaşladığını
    söyledi. Ölçüm (15 GB RAM, 16 çekirdek): commit 42/55 GB, pagefile'da 21-30 GB gerçek veri. Her Claude Code oturumu
    9 firewall süreci başlatıyor ve her proxy handshake'ten hemen sonra 1,17 GB'lık fp32 modeli yüklüyordu
    (`proxy.ts`); bir oturumun alt süreçleri 12-16 GB tutuyordu. Üç sebep bulundu ve ölçülerek kapatıldı. (1) Model,
    sunucu hiç çağrılmasa da yükleniyordu: yeni `lazyClassifier` (`src/ml/lazy.ts`) ağırlıkları ilk ihtiyaçta okuyor;
    model dosyaları (`describeModel`) başlangıçta yine kontrol ediliyor, yani bozuk model sunucudan önce durdurmaya devam
    ediyor. (2) Tanımlar (tools/prompts/resources, instructions) her oturumda yeniden taranıyordu: `ScoreCache`
    (`src/ml/scorecache.ts`) (model parmak izi, metin) için skoru hatırlıyor; dosyaya yalnızca hash ve skor yazılıyor,
    metin yazılmıyor; yalnızca `definition` kanalı (`ScoreHint.stable`) önbelleğe giriyor; kayıtlı skor güncel eşikle
    karşılaştırılıyor, yani karar modelin vereceğiyle aynı. (3) ONNX'in bellek arena'sı ve memory pattern'i her taramanın
    en büyük buffer'ını tutuyordu (tek uzun sonuçtan sonra 3,6 GB): `session_options` (`enableCpuMemArena` ve
    `enableMemPattern` kapalı) ve `batchSize` 8 → 2. Yeni policy anahtarları: `ml.lazyLoad`, `ml.cacheDefinitions`,
    `ml.cacheFile` (sandbox mount'u bu dosyayı da reddediyor), `ml.batchSize`, `ml.threads`, `ml.memoryArena`. Ölçüm
    (README "Bellek ve CPU kullanımı"): tanımları önbellekte olan, çağrılmayan sunucunun firewall'ı ~2,0 GB → 37 MB;
    60.000 karakterlik sonuçtan sonra 4,8 GB → 2,3-2,6 GB; aynı iş yükünde tarama süresi 54 sn → 53 sn, ama token yoğun
    çok uzun bir metinde 55 sn → 70 sn (arena'yı kapatmanın bedeli); held-out v1'in 333 skoru birebir aynı (en büyük
    fark 0,00000). Model ve eşik davranışı değişmedi. Sınırlar: önbellek firewall'ın durum dosyası, yazabilen biri bir
    tanımı temiz gösterebilir (pin dosyasıyla aynı güven sınırı); `threads`'in etkisi ölçülmedi, varsayılan 0; q8 model
    ve tüm proxy'lerin paylaştığı tek scorer yapılmadı. 15 yeni test (244/244, gerçek ONNX testi dahil) ve gerçek CLI ile
    iki oturumluk uçtan uca deneme. Kurulu kopya aynı gün yenilendi (yedekler `src.yedek-2026-11-10c` ve
    `ui.yedek-2026-11-10`; kurulu kopya repo build'iyle birebir): gerçek beş sunucu kopyalar üzerinde yeni build'den
    geçti (14/9/25/1/12 araç, block/warn/hide yok, pin ve gerçek denetim dosyaları değişmedi, orphan süreç yok,
    `filesystem` ve `git` okuma çağrıları geçti). Kurulu iki politikada (`policy-genel.yaml`, `policy.yaml`)
    `scan.toolDefinitions: off` olduğundan skor önbelleği bu kurulumda devrede değil, kazanç `lazyLoad`'dan geliyor:
    çağrılmayan sunucunun firewall'ı 37-38 MB. Bedeli, ilk tool sonucunun modelin yüklenmesini beklemesi (`git` 4,8 sn;
    bellek tükenmişken `filesystem` 19,6 sn). Tanım taraması açıkken önbellek gerçek tanımlarla çalışıyor (`git` 12,
    `memory` 9 tanım): soğuk 4,6 / 3,8 sn ve 2,4 / 2,8 GB, sıcak 18 / 17 ms ve 38 / 39 MB, araç listesi ve kararlar aynı.
    Eski build bu kez karşılaştırma için çalıştırılmadı (boş RAM 0,0 GB, 10 firewall süreci 18,9 GB tutuyordu): yeni
    build pinlere ve önceki ölçüme karşı kontrol edildi. GitHub sunucusu Docker kapalı olduğu için gerçek kapsayıcıyla
    denenmedi; `policy.yaml` kopyası kurulu build'de sahte sunucuya karşı yüklendi, `delete_*` kuralı çalıştı. Çalışan
    süreçler eski kodla kalıyor: etkisi için Claude Code'un yeniden başlatılması gerekiyor. Dosyalar: `src/ml/{lazy,scorecache,transformers,classifier}.ts`, `src/{cli,policy,proxy}.ts`,
    `test/ml-lazy.test.ts`, `test/ml.test.ts`, README, `policy.example.yaml`. Commit yok.

98. **ReDoS taraması: ürünün çalıştırdığı 215 regex ölçüldü, iki gerçek bulgu kapatıldı (11.11.2026):** 96'daki
    `NAMING_STYLE` donması tek tek bakarak bulunmuştu; bu kez hepsi ölçüldü. `scripts/redos-collect.mjs` bir preload:
    `RegExp.prototype.exec`'i sararak test paketinin ve bir taramanın gerçekten çalıştırdığı her regex'i (run time'da
    kurulan DLP, glob ve policy pattern'leri dahil) kaynağıyla kaydediyor: 215 tekil regex (decode 49, engine 22,
    sandbox 22, taint 19, paths 17, dashboard 16, dlp 15 ...). `scripts/redos-audit.mjs` her regex için pattern'in kendi
    karakterlerinden tekrarlı girdiler kurup (prefix + pump x n + suffix) süreyi timeout'lu bir vm içinde ölçüyor ve
    lineerden hızlı büyüyenleri bildiriyor; `scripts/redos-shapes.mjs` aynı listeyi 43 tekdüze uzun girdiyle (tek harf,
    "ACGT", boşluk, "a@", "%4" ...) ölçüyor. Arama, kanıt değil: temiz sonuç yalnız bu biçimlerin zarar vermediğini
    söyler. Bulgu 1: `deobfuscate` içindeki `/\S+@\S+\.\w+/g` (e-posta adreslerini l33t sayımından ayırma) kübikti:
    "@" x 1000 = 241 ms, x 2000 = 1,5 sn, x 3000 = 7,7 sn; 10 kB'lık bir sonuç dakikalarca event loop'u tutardı. Yerine
    lineer `withoutEmailLike` (boşluksuz run başına tek geçiş); eski regex'le eşdeğerliği 4 ve 8 karakterlik alfabelerin
    9 ve 6 uzunluğa kadar bütün dizilişlerinde test ediliyor. Bulgu 2: ROT13 adayı regex'i
    `\p{L}[\p{L}']*(?:[ \t,;:"'()-]+\p{L}[\p{L}']*){2,}` quadratic'ti: aramayı uzun bir kelimenin her harfinde yeniden
    başlatıyor ve apostrof iki sınıfta da olduğu için bir apostrof dizisinin her bölünüşünü deniyordu. Saldırgan girdi
    gerekmiyor: 64.000 harf (bir base64 blob'u, bir DNA dizisi) `withDecoded`'da 7,1 sn, 16.000 harf 0,4 sn. Yeni hâli
    yalnız kelime başında başlıyor (`(?<!\p{L})`) ve apostrofu yalnız iki harf arasında kelimeye sayıyor: aynı girdi
    14 ms, 256.000 karakter 51 ms; denenen 14 biçimin hepsi lineer. Davranış farkı: `a''b` artık bir değil iki kelime
    sayılıyor; kelime içi apostrof, tırnak içindeki cümle ve Türkçe örnekler aynı çözülüyor (testte). Yanlış alarmlar:
    audit'in işaretlediği diğer dört regex (percent, `.ssh`, sandbox, paths) 1 ms altındaki sürelerin gürültüsüydü;
    percent regex'i 128.000 karakterde 27 ms. Düzeltmeden sonra shapes taramasında 12.000 karakterde 40 ms'yi aşan
    yalnız bu iki regex'in eski hâli. 3 yeni test, 247/247. Kurulu kopya yenilenmedi: üç ReDoS düzeltmesi de (96 ve bu
    ikisi) yalnız repoda. Dosyalar: `src/decode.ts`, `test/decode.test.ts`, `scripts/redos-{collect,audit,shapes}.mjs`.

99. **Boşluk verisiyle eğitim: `gap` adayları, rakip modeller ve sandbox'ın yeniden denenmesi (11.11.2026):** 96'da
    held-out sette görünen zayıflıklar (zincirleme eylem, Türkçe dolaylı mail talimatı, prompt channel'ında false alarm)
    için `training/gap_data.py` ile bağımsız yazılmış 2.120 eğitim satırı ve default modelin 0,3'ün altında skorladığı
    2.000 gerçek tool tanımı (benign) eklendi. İki tarif denendi: `gapcont` (ham evilsandangels modelinden 2 epoch'luk
    devam; boşluk + gerçek tool + 12.000 satır replay, 16.120 satır) ve `gap` (mmBERT tabanından tam eğitim, v12eva +
    boşluk + gerçek tool = 72.950 satır, 2 saat 12 dk); ikisi de `soup04-ab4` ile karıştırıldı. Sonuç (eşik 0,3;
    tablolar `bench/heldout/adaylar/*.md`):
    held-out recall / FPR / AUC: B30 95,3 / 12,6 / 0,977; `gapcont-50` 96,7 / 8,2 / 0,988; `gap-30` 94,7 / 9,3 / 0,987;
    `gap-40` 95,3 / 7,7 / 0,991; `gap-50` 97,3 / 4,4 / 0,994. Türkçe false-alarm seti (2.875 benign): 11,0 → 10,4 / 7,4 /
    6,3 / 5,6. Gerçek tool tanımı (3.000): %1,0 → %0,4-0,5. 17 standart kümenin toplamı (recall / FPR): B30 83,7 / 11,1;
    `gap-30` 84,9 / 11,2; `gap-40` 84,0 / 10,3; `gapcont-50` 80,1 / 9,2; `gapcont-30` 84,0 / 10,9. `gapcont-50` aday
    değil: bağımsız kümede recall 91,2 → 80,4, obfuscated'da 95,3 → 87,2, çok dilli kümede 95,8 → 90,1. `gap-40`
    B30'la aynı toplam recall'da FPR'yi çoğu kümede düşürüyor (rt 4,9 → 3,7; tr 7,4 → 5,2; eva 11,0 → 6,5 ve recall
    90,4 → 100; panel etiketleri 45,2 → 22,6; boundary recall 74,0 → 84,2), bedeli: tr recall 91,5 → 89,3, wtr 73,3 →
    71,9, hfho FPR 9,2 → 13,3. `gap-50` standart kümelerde ölçülmedi. Sınırlar: boşluk verisi held-out'taki zayıflıklara
    bakılarak yazıldı (satırlar bağımsız, 7 kelimelik ortak dizi taşıyanlar atıldı), yani held-out artık bu adaylar için
    bir dev seti gibi; karar standart kümelerle verilmeli. Eşit FPR'de karşılaştırma yapılmadı. gap-dev'de (görülmemiş
    şablon aileleri) `gap_def_plain` recall'u karışımlarda %50'de kaldı (ham `gap` %100): tanım channel'ındaki düz
    talimatlar karışımda kayboluyor. Default model DEĞİŞMEDİ (B30); öneri `gap-40`, karar kullanıcıda.
    Rakipler, held-out v1, her model kendi eşiğinde (`bench/heldout/rakip/karsilastirma.md`): B30 95,3 / 12,6 / AUC 0,977;
    ProtectAI v2 60,7 / 18,6 / 0,792; Prompt Guard 2 86M 22,0 / 1,6 / 0,855; TestSavant 88,7 / 33,9 / 0,840; deepset
    100 / 98,9; Arch-Guard 44,0 / 9,8; Qwen3Guard-Gen 0.6B 41,3 / 1,6 / 0,884. Uyarı: seti biz yazdık ve rakipler MCP
    taşıyıcılarına göre eğitilmedi. Sandbox (90) güncel build'le gerçek Docker 29.8.2'de yeniden denendi: izolasyon
    (nobody, read-only root, CapEff 0, `network: none`'da ağ yok, ro mount'a yazılamıyor), firewall öldürülünce
    container 1 sn içinde yok, GitHub MCP image'ı `network none` altında 46 tool listeliyor ve çıkışta container
    siliniyor. GitHub'a bağlanan test kullanıcının isteğiyle yapılmadı. AEB dört profilde aynı (katı 19/23/35/42 / 62).

100. **`gap-40` dört farklı testle denendi: ayırma gücü aynı ya da daha iyi, ama eşik kayıyor (11.11.2026):** Kullanıcı
    adayın başka testlerle de denenmesini istedi. (1) Eşit FPR (`bench/heldout/adaylar/gap40-esit-fpr-tablo.md`): her
    standart kümede B30'un 0,3'teki FPR'sine eşitlenince `gap-40`'ın recall'u 16 kümenin 13'ünde eşit ya da yüksek
    (havuz 83,7 → 85,3; %1 FPR'de 31,3 → 34,8); geride: hfho 78,3 → 74,4, hftr %1 FPR'de 26,9 → 14,9. (2) BIPIA
    eşleşmiş kümesi (3.635 satır, ham görünüm): AUROC 0,702 → 0,708, recall @%1 FPR 23,6 → 26,2; %5 ve %10 FPR'de
    aynı (30,6 / 31,6; 37,3 / 37,4). Ama 0,3 eşiğinde FPR %21,7 → %0,7 ve recall %48,7 → %25,2: `gap-40` uzun
    belgelerde çok daha düşük skor veriyor, B30'un 0,3'üne denk gelen eşik burada yaklaşık 0,06. Yani ROC aynı,
    kalibrasyon farklı; model değişirse eşik yeniden seçilmeli ve bu kümede 0,3 fiilen daha sıkı bir eşik. (3) AEB,
    ML'li iki profil (`AEB_MODEL` ile aday model; `bench/aeb/run.mjs`'e eklendi): katı tespit aynı (35/62 ve 42/62),
    benign 24/25 → 25/25 (B30'un tek false block'u kalktı), hata 0. (4) Poligon (`node poligon/dene.mjs hepsi`, iki
    model art arda): e-posta senaryoları aynı; rug pull'da "yeni parametre (açıklama aynı)" senaryosunu ML tek başına
    artık yakalamıyor (pinning yakalıyor), tarama katmanında fark edilmeyen değişiklik 1/5 → 2/5. ONNX export:
    fp32 1.174 MB, PyTorch'la en büyük olasılık farkı 0,0000; int8 yine atıldı (200 satırda 5 karar değişti). Gerçek
    audit log bu koşularda değişmedi (1786 satır önce/sonra). Değerlendirme: `gap-40` B30'dan kötü bir sıralayıcı
    değil, çoğu yerde biraz iyi; kazancın büyük kısmı daha temkinli skorlamadan geliyor ve bunun bedeli uzun belgede
    dolaylı injection ile tanım değişikliklerinde daha az yakalama. Default DEĞİŞMEDİ. `bench/bipia/report_bipia.py`
    raporuna `gap40` eklendi.

101. **"Parametre kibarca veri istiyor" saldırısı iki modelin de zayıf noktası (11.11.2026):** Poligonda `gap-40`'ın
    ML'le kaçırdığı tek rug pull senaryosu ("yeni parametre, açıklama aynı") için kullanıcı yeniden eğitim önerdi; önce
    ölçüldü. `bench/heldout/ek-parametre-veri-istegi.mjs`: elle yazılmış 37 minimal pair (74 satır; 27 İngilizce, 10
    Türkçe). Tool açıklaması iki satırda da temiz; saldırı satırında bir parametre açıklaması emir ya da gizli etiket
    olmadan, ürün diliyle konuşmayı, credential'ı, yerel dosyayı, system prompt'u, ortam değişkenlerini, başka
    tool'ların çıktısını ya da kişisel veriyi istiyor; ikizinde aynı parametre meşru bir şey istiyor (servisin kendi
    API key'i dahil). Ürün yolundan (`score.mjs --rows`) 0,3 eşiğinde: B30 15/37, `gap-40` 10/37; ikisinde de false
    alarm 0/37. `gap-40`'ın kaçırıp B30'un yakaladığı 5 satır var, tersi yok; 22 satırı ikisi de kaçırıyor (ortam
    değişkeni 0/4, kişisel veri 0/3, dosya 1/7). Sıralama ise sağlam: AUROC 0,950 / 0,962 ve 37 çiftin 37'sinde
    saldırı ikizinden yüksek skor alıyor; sorun skorların çok düşük olması (medyan saldırı skoru 0,001). Regex katmanı
    74 satırdan yalnız 3'ünü gizliyor (`.env`, `.ssh`, `.aws/credentials` deseni). Sonuç: zayıflık `gap-40`'a özgü
    değil, sınıfın kendisi eğitim verisinde yok; hedefli bir veri turu gerekçeli. Bu küme held-out'tur, eğitime
    girmez; poligonun cümlesi bilerek kullanılmadı. Rug pull'un kendisini (tanımın değişmesi) yine pinning yakalıyor.

102. **`gap2`: parametre-veri-isteği verisiyle eğitim (11-12.11.2026):** `training/param_ask_data.py` 1.280 minimal pair
    (2.560 satır; 900 EN, 380 TR çift) ve eğitimde geçmeyen tool/kalıp/gerekçelerden 120 çiftlik dev kümesi üretir;
    held-out satırlarıyla 7 kelimelik ortak dizi yok. Reçete `gap` ile aynı (mmBERT tabanı, v12gap + param = 75.306
    satır, 2 saat 25 dk), `soup04-ab4` ile %30/40/50 karışım. Eşik 0,3. Held-out eki (37 saldırı) / dev (120 saldırı),
    false alarm hepsinde 0: B30 15 / 49; `gap-40` 10 / 41; ham `gap2` 32 / 95; `gap2-30` 18 / 56; `gap2-40` 21 / 63;
    `gap2-50` 26 / 68. Eski held-out recall / FP: B30 143/150, 23/183; `gap2-40` 143, 10; `gap2-50` 144, 7; ham 142, 4.
    17 standart küme toplamı recall / FPR [eşit FP'de recall]: B30 83,7 / 11,1 [83,9]; `gap-40` 84,0 / 10,3 [84,6];
    `gap2-30` 83,9 / 10,3 [84,5]; `gap2-40` 82,3 / 9,1 [84,7]; `gap2-50` 80,8 / 8,1 [83,9]. `gap2-40/50` 0,3 eşiğinde
    ind (91,2 → 86,3 / 82,3), obf (95,3 → 91,9 / 88,7) ve wtr'de (73,3 → 68,9 / 66,6) recall kaybediyor; eşit FP'de
    fark küçülüyor (kalibrasyon kayması). Karışım yeni sınıfı seyreltiyor. Ham `gap2` standart kümelerde ÖLÇÜLMEDİ;
    poligon, BIPIA, AEB ve ONNX export yapılmadı. Default DEĞİŞMEDİ (B30).

103. **`gap2` ham model ve eşik taraması (12.11.2026):** Ham `gap2` 17 standart kümede 0,3 eşiğinde 75,4 / 7,5
    (B30 83,7 / 11,1), eşit FP'de recall 79,4 (B30 83,9). Kayıp gerçek, eşik kayması değil: ind 91,2 → 69,3,
    obf 95,3 → 78,4, ml 95,8 → 80,0, wtr 73,3 → 65,0 (eşit FP'de 81,3 / 82,7 / 79,5 / 69,9). Kazandığı yerler:
    eva 100 / 0, lab 94,1 / 0, boundary 83,2, devvoice 100, hfho eşit FP'de 89,1. Yani ham model default olamaz.
    Eşik taraması (0,3 → 0,05): skorlar iki uçta toplandığı için eşik düşürmek az şey değiştiriyor; `gap2-50`
    0,05'te bile obf 92 / ind 86. `gap2-40` 0,05'te 84,7 / 10,6, ind 90, obf 95, ek 25/37, FP 0 — ama 0,05 kırılgan
    bir eşik. Sonuç: yeni sınıftaki kazanç ham modelin ağırlığıyla orantılı, obf/ind/ml kaybı da öyle; soup bu
    ikisini ayıramıyor. Kayıpsız tek aday `gap2-30` (83,9 / 10,3; ek 18/37; held-out FP 14) ama eva'da `gap-40`'ın
    gerisinde (87,6 / 12,9'a karşı 100 / 6,5). `gap2` adaylarıyla poligon, BIPIA, AEB, ONNX export YAPILMADI.
    Default DEĞİŞMEDİ (B30).

104. **`gap3`: parametre verisi 800 satıra indirildi — olumsuz sonuç (12.11.2026):** Varsayım: 2.356 parametre satırı
    ham `gap2`'yi obf/ind/ml'den uzaklaştırdı. Deney: `data/v12gap3` = v12gap + 400 çift (800 satır; 277 EN, 123 TR;
    val'e 35 çift), aynı reçete, `soup04-ab4` ile %30/40/50. Varsayım YANLIŞ: ham `gap3` 17 standart kümede
    75,6 / 8,3 (ham `gap2` 75,4 / 7,5), ind 72,6, obf 80,1, ml 81,4 — kayıp aynı. Kayıp parametre verisinden değil,
    ham tek-eğitim modelinin kendisinden geliyor; soup bunu `soup04-ab4` ağırlığıyla kapatıyor. Yeni sınıf: ek
    32/37 (aynı), dev 84/120 (`gap2` 95). Soup'lar `gap2` karşılıklarından biraz kötü: `gap3-30` 82,7 / 10,3, ek 17,
    dev 44; `gap3-40` 80,6 / 9,2, ek 20, dev 49; `gap3-50` 78,6 / 8,4, ek 23, dev 58. Eşit FP'de recall: B30 83,9,
    `gap2-30` 84,5, `gap3-30` 84,2, `gap3-40` 84,1, `gap3-50` 82,8, ham `gap3` 79,6. Sonuç: satır sayısını azaltmak
    işe yaramadı; `gap2-30` hâlâ kayıpsız tek aday. Default DEĞİŞMEDİ (B30).

105. **`gap2-30` BIPIA, AEB ve poligonda denendi (12.11.2026):** ONNX export: fp32 1.174 MB, PyTorch'la en büyük
    olasılık farkı 0,0000; int8 atıldı (200 satırda 5 karar değişti). (1) BIPIA eşleşmiş kümesi (3.635 satır, ham
    görünüm): AUROC B30 0,702 / `gap-40` 0,708 / `gap2-30` 0,688; recall @%1 FPR 23,6 / 26,2 / 18,0; 0,3 eşiğinde
    recall / FPR 48,7 / 21,7 — 25,2 / 0,7 — 63,0 / 39,2. `gap2-30` uzun belgelerde B30'dan yüksek skor veriyor:
    false alarm neredeyse iki katı, sıralama gücü de düşük. (2) AEB, ML'li iki profil: katı tespit 35/62 → 34/62 ve
    42/62 → 41/62 (kaçan vaka `mcp-tool-shadow-003`), benign 24/25 → 25/25 (`fp-mcp-tool-result-credential-
    placeholder-019` artık geçiyor), hata 0. (3) Poligon: çıktı B30 ile satır satır aynı; `gap-40`'ın ML'le kaçırdığı
    "yeni parametre (açıklama aynı)" rug pull'unu `gap2-30` yakalıyor (tarama katmanında fark edilmeyen 1/5). Koşular
    yalıtılmış HOME ile yapıldı; gerçek audit log 1841 satır önce/sonra. Değerlendirme: `gap2-30` standart kümelerde
    kayıpsız ama BIPIA'da belirgin geride ve AEB'de bir vaka kaybediyor; yeni sınıftaki kazancı (15 → 18 / 37) bunu
    karşılamıyor. Default DEĞİŞMEDİ (B30). `bench/bipia/report_bipia.py` raporuna `gap2_30` eklendi.

106. **"Veri isteği" kuralı denemesi ve kanal bulgusu (12.11.2026):** (1) Kural: tool tanımında ajanın elindeki veriyi
    (konuşma, system prompt, başka servislerin credential'ı, yerel credential dosyaları, ortam değişkenleri, diğer
    tool'ların sonuçları, kart/kimlik bilgisi) isteyen ifadeler için EN+TR 14 regex (`bench/heldout/dataask-deneme/`,
    ürüne BAĞLANMADI). Eğitim çiftlerinde geliştirildi, sonra sınandı: eğitim 692/1178 (FP 1/1178), dev 31/120
    (FP 0), held-out eki 34/37 (FP 0; bu kümeyi kuralı yazmadan önce görmüştüm, sayı iyimser), 239.054 gerçek tool
    tanımında 644 false alarm (%0,27; çoğu "full transcript", `~/.aws/config`, "user's token"). Dev'de B30'un (49/120)
    bile gerisinde: ifade çeşitliliği regex'le kapanmıyor, gevşetmek false alarmı artırır. Olumsuz sonuç; bilinen
    hata: env-var deseni büyük/küçük harf ayırmadığı için `page_token`'a takılıyor. (2) Kanal bulgusu: ham `gap2`'nin
    kaybı tool sonucu kümelerinde (ind, obf, ml); TANIM kanalında B30 kadar iyi ya da daha iyi. Held-out v1 tanım
    satırları: B30 41/42, FP 1/47; ham `gap2` 41/42, FP 0/47. Gerçek tool tanımı (3.000): %1,0 → %0,3. Tanım
    ağırlıklı standart kümeler: test 98,5 / 2,7 → 97,7 / 0,3; devsyn 99,0 / 1,8 → 97,9 / 0,6; devreal FP 2,2 → 2,5.
    Yeni sınıf: ek 15 → 32 / 37, dev 49 → 95 / 120. Yani "tanımlarda ham `gap2`, geri kalanında B30" ölçülen hiçbir
    kümede kayıp vermeden yeni sınıfı kapatıyor. Bedeli: ikinci 1,17 GB model (tanım taraması açıksa yüklenir) ve
    `ml.definitionModel` gibi bir policy alanı. Ürüne EKLENMEDİ; AEB ve poligonda bu düzenle ölçüm yapılmadı.
    Default DEĞİŞMEDİ (B30).

107. **Üçlü soup (`tri`): `soup04-ab4` + ham `gap` + ham `gap2` (12.11.2026):** Soru: iki gap modelini birlikte
    karıştırmak, tek tek karıştırmanın veremediği "yeni sınıfta kazanç, standart kümelerde kayıpsız" dengesini verir
    mi? Altı oran denendi (hepsi `mixraw` soup'larının yeniden karıştırılmasıyla): `tri-g40-g250-50`, `tri-g40-g230-50`,
    `tri-g40-g2raw-30`, `tri-b` (ab4/gap/gap2 = .53/.12/.35), `tri-c` (.57/.28/.15), `tri-d` (.50/.25/.25).
    (1) 16 standart küme, B30'un FP sayısında (2.132) toplam hata: B30 3.725; `tri-g40-g250-50` 3.369 (−%9,6),
    `tri-b` −%9,1, `tri-d` −%8,7, `gap-40` −%8,6, `tri-g40-g2raw-30` −%8,5, `tri-c` −%8,3, `tri-g40-g230-50` −%7,6,
    `gap2-30` −%6,3. Ama en iyi adayın eşit-FP eşiği 0,034 (kırılgan); ürünün 0,3 eşiğinde kazanç yalnız −%2,6 ve
    kayıp tool sonucu kümelerinde: recall / FPR 83,7 / 11,1 → 82,2 / 9,1; ind 91 → 87, obf 95 → 92, ml 96 → 93,
    wtr 73 → 69 (boundary 74 → 82). (2) False alarm tarafı 0,3'te belirgin iyi: held-out v1 FP 23 → 8 (yakalama
    143/150 aynı), Türkçe false alarm kümesi 316 → 158 / 2.875, gerçek tool tanımı 29 → 10 / 3.000. (3) Yeni sınıf
    neredeyse kıpırdamadı: ek 15 → 16 / 37, paramdev 49 → 53 / 120, gapdev 112 → 103 / 240; en iyisi `tri-b` ek 19,
    paramdev 63 (ham `gap2` 32 / 95). (4) BIPIA (ham görünüm): AUROC 0,702 → 0,689, recall @%1 FPR 23,6 → 19,4;
    0,3'te recall / FPR 48,7 / 21,7 → 35,0 / 11,0. (5) ONNX export fp32 1.174 MB, PyTorch farkı 0,0000; int8 atıldı
    (200 satırda 2 karar değişti). AEB, ML'li iki profil: 35/62 → 34/62 ve 42/62 → 41/62 (kaçan `mcp-tool-shadow-003`),
    benign 24/25 → 25/25 — `gap2-30` ile aynı iki vaka. Poligon: çıktı B30 ve `gap2-30` ile satır satır aynı. Koşular
    yalıtılmış HOME ile; gerçek audit log 1857 satır önce/sonra. Değerlendirme: üçlü soup yeni bir denge noktası
    vermiyor; `tri-g40-g250-50` aslında "daha az false alarm, daha az yakalama" yönünde bir eşik kaydırması gibi
    davranıyor ve yeni sınıfı kapatmıyor. Default DEĞİŞMEDİ (B30). Yeni sınıf için ölçülen tek kayıpsız yol hâlâ
    madde 106'daki "tanımlarda ham `gap2`" düzeni. `bench/bipia/report_bipia.py` raporuna `tri_g250_50` eklendi.
