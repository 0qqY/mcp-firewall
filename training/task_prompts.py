"""Benign task instructions written to an AI next to the data they act on (mask personal data, summarise,
translate, classify, extract fields, rewrite, draft a reply), in Turkish and English, with matched
injected copies.

mmBERT soup05 flagged 71% of the Turkish benchmark's "task instruction" texts (its v4 component alone 93%):
our training data had no benign text where an instruction to the model sits next to customer data, and
scope rules such as "only X", "leave Y untouched" read like an override. Everything here comes from our own
templates and fake values (checksummed but invented IDs, IBANs and card numbers); the benchmark stays
evaluation only, and no generated text may start like one of its rows.

Instruction and message templates are split by index (i % 10: 0 test, 1 val, rest train), so a test
row pairs an instruction and a message the model never saw. Half the rows get an attack from the same pools
as benign_corpus (Turkish rows mostly from the Turkish sets' train/val attacks), placed in the message or
after the instruction, so "instruction + personal data" alone does not mean safe either.
"""

import json
import random

from benign_corpus import _insert, _split, attack_pools
from benign_prompts import _eval_prefixes, _norm
from turkish_data import attacks as tr_attacks

MAX_ATTACK = 350  # keeps injected twins in the length range of the benign rows

TR_FIRST = ["Ayşe", "Fatma", "Zeynep", "Elif", "Merve", "Büşra", "Esra", "Derya", "Selin", "Ceren", "Gizem", "Tuğba",
            "Sibel", "Melike", "Aslı", "Ebru", "Pınar", "Nur", "Mehmet", "Mustafa", "Ahmet", "Ali", "Hasan", "İbrahim",
            "Murat", "Emre", "Burak", "Can", "Kerem", "Onur", "Serkan", "Tolga", "Volkan", "Oğuz", "Barış", "Umut"]
TR_LAST = ["Yılmaz", "Kaya", "Demir", "Şahin", "Çelik", "Yıldız", "Öztürk", "Aydın", "Özdemir", "Arslan", "Doğan",
           "Kılıç", "Çetin", "Kara", "Koç", "Kurt", "Özkan", "Şimşek", "Polat", "Korkmaz", "Güneş", "Aksoy", "Tekin",
           "Bulut", "Uçar", "Karaca", "Bozkurt", "Ateş", "Erdem", "Sarı"]
TR_PLACES = [("İstanbul", "Kadıköy"), ("Ankara", "Çankaya"), ("İzmir", "Bornova"), ("Bursa", "Nilüfer"),
             ("Antalya", "Muratpaşa"), ("Konya", "Selçuklu"), ("Eskişehir", "Odunpazarı"), ("Kayseri", "Melikgazi"),
             ("Trabzon", "Ortahisar"), ("Mersin", "Yenişehir"), ("Gaziantep", "Şahinbey"), ("Samsun", "Atakum")]
TR_STREETS = ["Lale", "Menekşe", "Gül", "Çınar", "Ihlamur", "Papatya", "Zambak", "Akasya", "Söğüt", "Defne"]
TR_HOODS = ["Cumhuriyet", "Bahçelievler", "Gazi", "Fatih", "Barış", "Çamlık", "Esentepe", "Yıldıztepe", "Güzelyalı"]
EN_FIRST = ["Emma", "Olivia", "Sophie", "Grace", "Hannah", "Chloe", "Laura", "Megan", "James", "Oliver", "Daniel",
            "Thomas", "Ryan", "Lucas", "Nathan", "Adam", "Priya", "Arjun", "Mateo", "Lena", "Jonas", "Amir", "Yuki", "Kofi"]
EN_LAST = ["Smith", "Johnson", "Brown", "Taylor", "Wilson", "Clarke", "Walker", "Hughes", "Patel", "Murphy", "Evans",
           "Turner", "Fischer", "Novak", "Rossi", "Garcia", "Okafor", "Tanaka", "Kowalski", "Nguyen"]
EN_PLACES = [("Leeds", "LS6 2AB"), ("Bristol", "BS1 4DJ"), ("Manchester", "M14 5RT"), ("Cardiff", "CF10 3AT"),
             ("Glasgow", "G12 8QQ"), ("Dublin", "D04 V1W8"), ("Austin, TX", "78701"), ("Denver, CO", "80202")]
EN_STREETS = ["Oak Street", "Mill Lane", "Station Road", "Park Avenue", "Church Road", "Victoria Street", "Elm Close"]
TR_DIGITS = ["sıfır", "bir", "iki", "üç", "dört", "beş", "altı", "yedi", "sekiz", "dokuz"]
ASCII = str.maketrans("çğıöşüÇĞİÖŞÜ", "cgiosuCGIOSU")


def _digits(rng: random.Random, n: int) -> str:
    return "".join(str(rng.randint(0, 9)) for _ in range(n))


def _tckn(rng: random.Random) -> str:
    d = [rng.randint(1, 9)] + [rng.randint(0, 9) for _ in range(8)]
    d.append((sum(d[0:9:2]) * 7 - sum(d[1:8:2])) % 10)
    d.append(sum(d) % 10)
    return "".join(map(str, d))


def _iban(rng: random.Random, country: str, bban: str) -> str:
    check = 98 - int("".join(str(int(c, 36)) for c in bban + country + "00")) % 97
    raw = f"{country}{check:02d}{bban}"
    return " ".join(raw[i : i + 4] for i in range(0, len(raw), 4)) if rng.random() < 0.5 else raw


def _card(rng: random.Random) -> str:
    body = [4] + [rng.randint(0, 9) for _ in range(14)] if rng.random() < 0.5 else [5, rng.randint(1, 5)] + [rng.randint(0, 9) for _ in range(13)]
    total = sum(d if i % 2 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(reversed(body)))
    digits = "".join(map(str, body + [(10 - total % 10) % 10]))
    return rng.choice(["-", " ", ""]).join(digits[i : i + 4] for i in range(0, 16, 4))


def _values(rng: random.Random, lang: str) -> dict[str, str]:
    """One person's worth of fake data; every key is available to every message template."""
    tr = lang == "tr"
    first, last = (TR_FIRST, TR_LAST) if tr else (EN_FIRST, EN_LAST)
    name, other = f"{rng.choice(first)} {rng.choice(last)}", f"{rng.choice(first)} {rng.choice(last)}"
    login = name.translate(ASCII).lower().replace(" ", rng.choice([".", "_", ""]))
    mail = f"{login}{rng.choice(['', str(rng.randint(1, 99))])}@{rng.choice(['ornekposta.com', 'example.com.tr', 'posta.example', 'firma.example'] if tr else ['example.com', 'mail.example', 'example.org'])}"
    if tr:
        city, district = rng.choice(TR_PLACES)
        phone = rng.choice(["05{a}{b} {c} {d} {e}", "+90 5{a}{b} {c} {d} {e}", "(5{a}{b}) {c} {d} {e}", "05{a}{b}{c}{d}{e}"]).format(
            a=rng.choice("345"), b=rng.randint(0, 9), c=_digits(rng, 3), d=_digits(rng, 2), e=_digits(rng, 2))
        address = f"{rng.choice(TR_HOODS)} Mah. {rng.choice(TR_STREETS)} Sok. No:{rng.randint(1, 80)} Daire:{rng.randint(1, 20)} {district}/{city}"
        iban = _iban(rng, "TR", _digits(rng, 5) + "0" + _digits(rng, 16))
        amount = f"{rng.randint(1, 48)}.{rng.randint(0, 999):03d},{rng.choice(['00', '50', '90'])} TL" if rng.random() < 0.5 else f"{rng.randint(40, 990)} TL"
        plate = f"{rng.randint(1, 81):02d} {''.join(rng.choice('ABCDEFGHJKLMNPRSTUVYZ') for _ in range(rng.randint(1, 3)))} {rng.randint(10, 9999)}"
    else:
        city, postcode = rng.choice(EN_PLACES)
        phone = rng.choice(["+44 7700 900{a}", "07700 900{a}", "(555) 01{b}-{c}", "+1 555 01{b} {c}"]).format(
            a=_digits(rng, 3), b=_digits(rng, 1), c=_digits(rng, 4))
        address = f"{rng.randint(1, 240)} {rng.choice(EN_STREETS)}, {city} {postcode}"
        iban = _iban(rng, "GB", rng.choice(["NWBK", "BARC", "LOYD", "MIDL"]) + _digits(rng, 14)) if rng.random() < 0.6 else _iban(rng, "DE", _digits(rng, 18))
        amount = rng.choice(["£", "$", "€"]) + f"{rng.randint(5, 2400)}.{rng.choice(['00', '50', '99'])}"
        plate = f"{''.join(rng.choice('ABCDEFGHJKLMNPRSTVWXY') for _ in range(2))}{rng.randint(10, 74)} {''.join(rng.choice('ABCDEFGHJKLMNPRSTVWXY') for _ in range(3))}"
    card = _card(rng)
    return {
        "ad": name, "ad2": other, "kadi": login + str(rng.randint(1, 99)), "eposta": mail, "tel": phone, "adres": address,
        "il": city, "iban": iban, "tutar": amount, "plaka": plate, "kart": card, "son4": card[-4:], "tckn": _tckn(rng),
        "dogum": f"{rng.randint(1, 28):02d}.{rng.randint(1, 12):02d}.{rng.randint(1950, 2006)}",
        "tarih": f"{rng.randint(1, 28):02d}.{rng.randint(1, 12):02d}.2026",
        "pasaport": rng.choice("UABSZ") + _digits(rng, 8), "police": f"{rng.choice(['POL', 'KSK', 'TSS'])}-{_digits(rng, 7)}",
        "siparis": f"{rng.choice(['SP', 'ORD', 'KRG'])}-{_digits(rng, 8)}", "musteri": _digits(rng, rng.choice([7, 8, 10])),
        "vergi": _digits(rng, 10), "ip": f"{rng.choice([85, 88, 176, 212, 78])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
        "mac": ":".join(f"{rng.randint(0, 255):02X}" for _ in range(6)),
        "sifre": f"{rng.choice(['Kedi', 'Deniz', 'Mavi', 'Sunny', 'Tiger', 'Lemon'])}{rng.choice(['_', '.', '!', '-'])}{_digits(rng, 4)}{rng.choice(['', '!', '*'])}",
        "nhs": f"{_digits(rng, 3)} {_digits(rng, 3)} {_digits(rng, 4)}",
    }


def _spoken(text: str) -> str:
    return " ".join(TR_DIGITS[int(c)] for c in text if c.isdigit())


# Customer messages, notes and records that carry personal data.
TR_MESSAGES = [
    "Merhaba, ben {ad}. {siparis} numaralı siparişim hâlâ gelmedi, bana {tel} numarasından ulaşabilirsiniz.",
    "{iban} hesabıma yatması gereken {tutar} iade henüz görünmüyor, kontrol edebilir misiniz?",
    "Kimlik numaram {tckn}, doğum tarihim {dogum}. Online bankacılık şifremi sıfırlamak istiyorum.",
    "Kargo adresimi {adres} olarak güncellemek istiyorum. Teşekkürler, {ad}",
    "Kartımdan ({kart}) dün gece iki kez çekim yapılmış, toplam {tutar}. Lütfen birini iptal edin.",
    "Aracımın plakası {plaka}, ruhsat sahibi {ad}. Kasko poliçe numaram {police}, hasar kaydı açtırmak istiyorum.",
    "Sanırım şifremi unuttum; hesap {kadi}, en son {sifre} yazmıştım ama sistem kabul etmiyor.",
    "Müşteri no: {musteri} | Ad: {ad} | Tel: {tel} | Not: fatura adresi değişecek.",
    "{tarih} tarihinde {il} şubesine gittim, {ad2} isimli görevli yardımcı oldu. Bana {eposta} adresinden dönebilirsiniz.",
    "Yurt dışına çıkacağım, pasaport numaram {pasaport}. Kartımın yurt dışında kullanılmasına izin verir misiniz?",
    "Modemim sürekli kopuyor. IP adresim {ip}, cihazın MAC adresi {mac}. Abone numaram {musteri}.",
    "Annem {ad2} adına kayıtlı hattı kendi üzerime almak istiyorum. Benim TC kimlik numaram {tckn}.",
    "Kira ödemesini her ayın beşinde {iban} hesabına {tutar} olarak yapıyorum, otomatik talimat verebilir miyim?",
    "Faturamda tanımadığım bir ek ücret var ({tutar}). Abone no {musteri}, iletişim için {eposta}.",
    "Çağrı notu: Arayan {ad}, doğum tarihi {dogum}, adres {adres}. Kredi kartı limit artışı istedi.",
    "Sağlık poliçemi ({police}) yenilemek istiyorum ama telefonum değişti, yeni numaram {tel}.",
    "Merhaba, kızım {ad2} için okul servisi ayarlamıştık. Adres: {adres}. Servis bu sabah gelmedi.",
    "Kurye {tel} numarasını aramadı, paket geri gitmiş. Takip no {siparis}, alıcı {ad}.",
    "Hesabımdan {tarih} günü {tutar} çekilmiş, ben yapmadım. Kartımın son dört hanesi {son4}.",
    "Randevumu ertelemek istiyorum. Hasta adı {ad}, TC {tckn}, randevu {tarih} saat 14.30.",
    "İşyeri adresimiz {adres}. Fatura {ad} adına kesilsin, vergi numarası {vergi}.",
    "E-posta adresim {eposta} yanlış kaydedilmiş, düzeltilmesini rica ederim. Müşteri numaram {musteri}.",
    "{plaka} plakalı aracın sahibi {ad}. Otopark aboneliği {tarih} tarihinde bitiyor, uzatmak istiyoruz.",
    "Kredi başvurum ne durumda? Başvuruda {tel} ve {eposta} bilgilerimi vermiştim.",
    "Sipariş {siparis}: ürün kırık geldi, fotoğrafları {eposta} adresinden gönderdim. İade {iban} hesabına yapılsın.",
    "Dün akşam {ip} adresinden hesabıma tanımadığım bir giriş olmuş. Kullanıcı adım {kadi}, şifremi değiştirmek istiyorum.",
    "Müşteri: IBAN numaram {iban_sozlu}. Temsilci: Teşekkürler, iadenizi başlatıyorum.",
    "Temsilci: Size ulaşabileceğimiz numara nedir? Müşteri: {tel_sozlu}. Temsilci: Kaydınız açıldı.",
    "{il} şubesinden {ad2} ile görüştüm, kart aidatımın {tutar} olarak iade edileceği söylendi. Adım {ad}.",
    "Hasta yakını {ad2}, telefon {tel}. {ad} için epikriz raporunun bir kopyası isteniyor.",
    "Kullanıcı {kadi} ({eposta}) üyeliğini iptal etmek istiyor, son ödeme tarihi {tarih}.",
    "Bordro hatası: {ad}, sicil {musteri}, IBAN {iban}. Ekim maaşı eksik yatmış, fark {tutar}.",
    "Yeni aboneyim. Kurulum adresi {adres}, uygun gün {tarih}. Tel: {tel}",
    "Teslimat {ad} adına {adres} adresine yapılacak, kapıda ödeme {tutar}.",
    "Mağazadan aldığım telefonun faturası {eposta} adresine gelmedi. Fatura {ad} adına olmalıydı.",
    "Kimlik kartımı kaybettim (TCKN {tckn}). Yeni kartla şubeye gelmem gerekiyor mu?",
    "{tarih} tarihli toplantı notunu {eposta} adresine iletir misiniz? {ad} katılamayacak.",
    "Öğrenci no {musteri}, {ad}. Burs ödemesi {iban} hesabına yatırılacakmış, ne zaman yatar?",
    "Kartımın şifresini üç kez yanlış girdim, kart bloke oldu. Kart {kart}, telefon {tel}.",
    "Merhabalar, {plaka} plakalı aracımın HGS bakiyesi {tutar} görünüyor ama geçişte uyarı veriyor.",
]
EN_MESSAGES = [
    "Hi, this is {ad}. Order {siparis} still hasn't arrived; you can reach me on {tel}.",
    "The refund of {tutar} to my account {iban} is still not showing. Could you check?",
    "My card ending {son4} was charged twice on {tarih} ({tutar} each). Please reverse one of them.",
    "Please update my delivery address to {adres}. Thanks, {ad}",
    "Customer ID: {musteri} | Name: {ad} | Phone: {tel} | Note: wants paper invoices stopped.",
    "I can't log in. My username is {kadi} and I think the last password I set was {sifre}.",
    "Call note: caller {ad}, DOB {dogum}, address {adres}. Asked about raising the overdraft limit.",
    "I'm travelling abroad next week, passport {pasaport}. Can you make sure my card {kart} works there?",
    "Router keeps dropping. Public IP {ip}, device MAC {mac}, account {musteri}.",
    "Policy {police}: I'd like to renew, but my phone number changed to {tel}.",
    "Please book a follow-up for {ad}, NHS number {nhs}, any morning after {tarih}.",
    "My email {eposta} was entered wrongly on the account, please correct it. Customer no. {musteri}.",
    "Invoice should be addressed to {ad}, {adres}. VAT number {vergi}.",
    "Someone signed in to my account from {ip} last night. Username {kadi}; I want to reset my password.",
    "Parcel {siparis} came back to the depot. The courier never called {tel}. Recipient: {ad}.",
    "Payroll issue: {ad}, staff no. {musteri}, paid into {iban}. October salary is short by {tutar}.",
    "Item from order {siparis} arrived broken; photos sent from {eposta}. Please refund to card {kart}.",
    "Hello, I spoke with {ad2} at the {il} branch about my annual fee refund of {tutar}. My name is {ad}.",
    "Vehicle {plaka}, registered keeper {ad}. Parking permit expires on {tarih}; we want to extend it.",
    "New customer. Installation address {adres}, preferred date {tarih}. Phone: {tel}",
    "Agent: Can I take a contact number? Caller: {tel}. Agent: Thanks, the ticket is open.",
    "My daughter {ad2} needs her school bus pick-up moved to {adres} from {tarih}.",
    "Please forward the minutes of the {tarih} meeting to {eposta}; {ad} could not attend.",
    "Card {kart} is blocked after three wrong PINs. Contact me on {tel}.",
    "Student {ad}, ID {musteri}: the bursary is supposed to go to {iban}. When will it be paid?",
]

# Instructions to the model about the data next to them. {alan}/{alan2} are field names, {etiket} a label
# for the first one, {dil} a target language.
TR_INSTRUCTIONS = {
    "mask": [
        "Müşteri mesajındaki {alan} ve {alan2} bilgilerini {etiket} gibi etiketlerle değiştir, geri kalanı aynen bırak.",
        "Lütfen şu kaydı anonimleştir: isimler, telefonlar ve adresler etiketlensin; tutarlar ve tarihler olduğu gibi kalsın.",
        "Yalnızca {alan} gizlensin. Diğer alanlara dokunma.",
        "{alan} dışında tüm kişisel bilgileri yıldızla (***) kapat.",
        "Sadece {alan} alanını maskele; metnin geri kalanını değiştirme.",
        "Raporlamadan önce notu kişisel verilerden arındır, {alan} açık kalabilir.",
        "Destek kaydını paylaşmadan önce ad, soyad ve iletişim bilgilerini {etiket} biçimindeki etiketlerle değiştir.",
        "Anonimleştirme kuralı: kimlik numarası, IBAN ve kart numarası etiketlenecek; ürün adları ve tutarlar kalacak.",
        "Şu çağrı dökümünde sesli okunan numaralar dahil bütün kişisel verileri maskele.",
        "6698 sayılı kanuna uygun olsun diye mesajdaki kişisel verileri gizle ama şikâyetin konusunu bozma.",
        "Veri minimizasyonu uygula: işlem için gerekmeyen {alan} ve {alan2} bilgilerini çıkar.",
        "Mesajı eğitim setine eklemeden önce isimleri ve numaraları {etiket} benzeri etiketlerle değiştir; yazım hatalarını düzeltme.",
        "{alan} maskelenmesin, onun dışındaki hassas bilgileri etiketle.",
        "Kart numarasının yalnızca son dört hanesi görünsün, kalan haneleri X ile kapat.",
        "Telefon numaralarını kısmen gizle (örneğin 05** *** ** 12); isimleri olduğu gibi bırak.",
        "Bu kayıt şirket içinde kalacağı için sadece {alan} kapatılsın, ad soyad açık kalabilir.",
        "Giriş bilgilerini (kullanıcı adı ve şifre) mutlaka gizle, diğer her şeyi olduğu gibi bırak.",
        "Mesajda sağlık bilgisi geçiyorsa onu da etiketle; diğer kişisel verilere bu adımda dokunma.",
        "Rapora eklenecek bu satırda kişiyi tanımlamaya yarayan her bilgiyi [GİZLİ] ile değiştir.",
        "Kişisel verileri maskelerken etiket adlarını büyük harfle yaz, örneğin {etiket}.",
    ],
    "summarize": [
        "Müşterinin sorununu tek cümleyle özetle.",
        "Aşağıdaki notu üç madde halinde özetle; kişisel bilgileri özete taşıma.",
        "Bu şikâyeti yöneticiye iletilecek şekilde kısalt, en fazla 40 kelime olsun.",
        "Talebin ne olduğunu ve hangi birime gitmesi gerektiğini kısaca yaz.",
        "Görüşme kaydını özetle; müşterinin istediği işlemi ve varsa tarihi belirt.",
        "Mesajın özünü çıkar, selamlaşma ve teşekkür kısımlarını at.",
        "Kaydı vardiya devri notu olarak iki cümleye indir.",
        "Metni kısalt ama tutarları ve tarihleri koru.",
        "Kısa bir özet çıkar: kim, ne istiyor, ne zamana kadar.",
        "Bu mesajdaki asıl talebi bul ve tek satırda yaz.",
    ],
    "translate": [
        "Mesajı {dil} çevir; isimleri ve numaraları çevirme.",
        "Metni {dil} çevir, resmi bir dil kullan.",
        "Notu {dil} aktar, kişisel verileri {etiket} gibi etiketlerle değiştirerek çevir.",
        "Müşteri mesajını {dil} çevir ve sonuna kısa bir özet ekle.",
        "Şunu {dil} tercüme et, tarih biçimini değiştirme.",
        "Aşağıdaki kaydı {dil} çevir; tablo düzenini koru.",
        "Bu metnin {dil} çevirisini yap, birimleri ve tutarları olduğu gibi bırak.",
        "Mesajı önce {dil} çevir, sonra çeviride geçen kişisel bilgileri maskele.",
        "Yurt dışı ekibi için bu notu {dil} çevir, teknik terimleri açıklama.",
        "Metni kelimesi kelimesine değil, anlamını koruyarak {dil} çevir.",
    ],
    "classify": [
        "Mesajı şu kategorilerden birine ata: şikâyet, talep, bilgi, iptal. Yalnızca kategori adını yaz.",
        "Bu talebin aciliyetini düşük, orta veya yüksek olarak işaretle ve nedenini bir cümleyle yaz.",
        "Müşterinin duygu durumunu olumlu, olumsuz ya da nötr olarak sınıflandır.",
        "Kayıt hangi departmanı ilgilendiriyor? Sadece departman adıyla cevap ver.",
        "Mesajda dolandırıcılık şüphesi var mı? Evet ya da hayır yaz.",
        "Talebi ürün, ödeme, teslimat veya hesap başlıklarından birine yerleştir.",
        "Bu kayıtta kişisel veri geçiyor mu? Geçiyorsa hangi türlerin geçtiğini listele, değerleri yazma.",
        "Mesajı ilk temas mı yoksa tekrar eden şikâyet mi diye etiketle.",
        "Bu talep çağrı merkezinde çözülebilir mi, yoksa şubeye mi yönlendirilmeli? Tek kelimeyle yanıtla.",
        "Mesajın dilini ve konusunu belirle, iki alanlı bir satır olarak yaz.",
    ],
    "extract": [
        "Mesajdan ad, telefon ve sipariş numarasını çıkarıp JSON olarak döndür.",
        "Metinde geçen tüm tarihleri GG.AA.YYYY biçiminde listele.",
        "Talep edilen tutarı ve para birimini bul; başka bir şey yazma.",
        "Adres bilgisini il, ilçe ve mahalle olarak ayrı alanlara böl.",
        "Kayıttaki {alan} değerini bul ve yalnızca onu yaz; yoksa \"yok\" yaz.",
        "Mesajda geçen bütün numaraları türleriyle birlikte tablo halinde ver.",
        "Müşterinin istediği işlemi ve bunun için verdiği bilgileri madde madde çıkar.",
        "CRM'e girilecek alanları doldur: ad_soyad, telefon, e_posta, konu.",
        "Metinden {alan} ve {alan2} alanlarını çek, bulunamayanları boş bırak.",
        "Bu kayıttan teslimat bilgilerini çıkar, ödeme bilgilerini dahil etme.",
    ],
    "rewrite": [
        "Yazım ve noktalama hatalarını düzelt, anlamı değiştirme.",
        "Mesajı resmi bir dille yeniden yaz; içerikteki bilgileri değiştirme.",
        "Bu metni daha kısa ve anlaşılır cümlelerle yeniden yaz.",
        "Bir önceki isteğimde maddeli liste istemiştim; bu sefer düz bir paragraf olarak yaz.",
        "Metindeki argo ve kısaltmaları düzelt, büyük-küçük harf kullanımını standart hale getir.",
        "Notu üçüncü tekil şahısla yeniden yaz, kişisel verileri {etiket} gibi etiketlerle değiştir.",
        "Bu kaydı sistemdeki şablona uygun hale getir: önce konu, sonra açıklama.",
        "Cümleleri sadeleştir ama sayılara ve tarihlere dokunma.",
        "Az önce resmi bir üslup istemiştim, onun yerine daha samimi bir dil kullan.",
        "Mesajı tek paragrafa indir, tekrar eden ifadeleri çıkar.",
    ],
    "reply": [
        "Bu müşteriye talebinin alındığını bildiren kısa bir yanıt yaz; kişisel verilerini yanıtta tekrar etme.",
        "Müşteriye özür dileyen ve çözüm süresini belirten nazik bir cevap taslağı hazırla.",
        "Mesaja kurumsal bir dille yanıt yaz, en fazla üç cümle olsun.",
        "Müşteriden eksik bilgiyi isteyen kibar bir dönüş e-postası yaz.",
        "Bu şikâyete verilecek yanıtta kampanya ya da ürün önerme, sadece sorunu ele al.",
        "Yanıt taslağı yaz ve müşterinin numaralarını yanıtta maskeli göster.",
        "Talebin şubede tamamlanması gerektiğini açıklayan kısa bir cevap yaz.",
        "Müşteriye işlemin yapıldığını ve ne zaman yansıyacağını bildiren bir mesaj hazırla.",
        "Mesajı yanıtlarken kişisel bilgileri tekrar yazma, sadece talep numarasını ver.",
        "SMS uzunluğunda (160 karakteri geçmeyen) bir bilgilendirme yanıtı yaz.",
    ],
}
EN_INSTRUCTIONS = {
    "mask": [
        "Replace the {alan} and {alan2} in this message with labels like {etiket}; leave everything else as it is.",
        "Anonymise the record below: names, phone numbers and addresses get labels, amounts and dates stay.",
        "Redact only the {alan}. Do not touch any other field.",
        "Mask every piece of personal data except the {alan}.",
        "Before this ticket goes into the shared tracker, replace names and contact details with {etiket}-style tags.",
        "Show only the last four digits of any card number; replace the rest with X.",
        "Strip login details (username and password) from the note and keep everything else verbatim.",
        "Redaction rule for this batch: IDs, IBANs and card numbers are masked, product names and totals are kept.",
        "For GDPR purposes, remove personal data from the message but keep the complaint itself intact.",
        "Only the {alan} needs hiding this time; the customer's name can stay because the note is internal.",
    ],
    "summarize": [
        "Summarise the customer's problem in one sentence.",
        "Summarise the note below in three bullet points without carrying personal details over.",
        "Shorten this complaint for a manager, 40 words at most.",
        "Write what the customer wants and which team should handle it.",
        "Give a handover summary in two sentences.",
        "Pull out the main request and write it on one line.",
        "Summarise the call: who called, what they need, and any deadline.",
        "Condense the message, but keep amounts and dates exact.",
        "Drop the greetings and thanks and keep only the actual request.",
        "Write a short case summary suitable for the CRM notes field.",
    ],
    "translate": [
        "Translate the message into {dil}; do not translate names or numbers.",
        "Translate this into formal {dil}.",
        "Translate the note into {dil} and replace personal data with tags like {etiket} as you go.",
        "Give a {dil} translation of the text below, keeping the date format unchanged.",
        "Translate for the overseas team into {dil}; keep the table layout.",
        "Translate the record into {dil} and add a one-line summary at the end.",
        "Render this message in {dil}, keeping units and amounts as they are.",
        "Translate into {dil} by meaning rather than word for word.",
        "First translate into {dil}, then mask any personal details in the translation.",
        "Provide the {dil} version of this customer note.",
    ],
    "classify": [
        "Assign the message to one category: complaint, request, information, cancellation. Reply with the category only.",
        "Rate the urgency as low, medium or high and give a one-sentence reason.",
        "Classify the sentiment as positive, negative or neutral.",
        "Which department does this concern? Answer with the department name only.",
        "Does this message look like fraud? Answer yes or no.",
        "Tag the request as product, payment, delivery or account.",
        "Does the record contain personal data? If so, list the types present, not the values.",
        "Label this as a first contact or a repeat complaint.",
        "Can the contact centre resolve this, or does it need a branch visit? One word.",
        "Detect the language and topic of the message and return them on one line.",
    ],
    "extract": [
        "Extract name, phone and order number from the message and return them as JSON.",
        "List every date in the text in YYYY-MM-DD format.",
        "Find the amount requested and its currency; write nothing else.",
        "Split the address into street, city and postcode fields.",
        "Return only the {alan} from the record, or \"none\" if it is missing.",
        "Put every number in the message into a table with its type.",
        "List the action the customer wants and the details they gave for it.",
        "Fill in the CRM fields: full_name, phone, email, subject.",
        "Pull the {alan} and {alan2} out of the text; leave missing ones blank.",
        "Extract the delivery details only, without the payment details.",
    ],
    "rewrite": [
        "Fix spelling and punctuation without changing the meaning.",
        "Rewrite the message in a formal tone; do not change any of the facts.",
        "Rewrite this in shorter, plainer sentences.",
        "Earlier I asked for bullet points; this time write it as one paragraph.",
        "Rewrite the note in the third person and replace personal data with tags like {etiket}.",
        "Reformat the record to our template: subject first, then description.",
        "Simplify the wording but leave numbers and dates untouched.",
        "I asked for a formal style before; use a friendlier tone instead.",
        "Merge this into one paragraph and remove repeated phrases.",
        "Correct the capitalisation and expand the abbreviations.",
    ],
}
TR_FIELDS = [("telefon numarası", "TELEFON"), ("e-posta adresi", "E_POSTA"), ("IBAN", "IBAN"), ("T.C. kimlik numarası", "TCKN"),
             ("adres", "ADRES"), ("ad soyad", "AD_SOYAD"), ("doğum tarihi", "DOGUM_TARIHI"), ("kart numarası", "KART_NO"),
             ("plaka", "PLAKA"), ("pasaport numarası", "PASAPORT_NO"), ("şifre", "SIFRE"), ("kullanıcı adı", "KULLANICI_ADI"),
             ("IP adresi", "IP_ADRESI"), ("müşteri numarası", "MUSTERI_NO"), ("poliçe numarası", "POLICE_NO")]
EN_FIELDS = [("phone number", "PHONE"), ("email address", "EMAIL"), ("IBAN", "IBAN"), ("address", "ADDRESS"), ("full name", "NAME"),
             ("date of birth", "DOB"), ("card number", "CARD"), ("passport number", "PASSPORT"), ("password", "PASSWORD"),
             ("username", "USERNAME"), ("IP address", "IP"), ("customer number", "CUSTOMER_ID"), ("policy number", "POLICY_NO")]
TR_LANGS = ["İngilizceye", "Almancaya", "Fransızcaya", "İspanyolcaya", "Arapçaya", "Rusçaya"]
EN_LANGS = ["German", "French", "Spanish", "Turkish", "Polish", "Italian"]
LABEL_STYLES = ["[{}]", "<{}>", "[[{}]]", "{{{{{}}}}}", "#{}#"]
TR_LAYOUTS = ["{ins}\n\n{data}", "{ins}\n{data}", "Talimat: {ins}\nMetin: {data}", "{data}\n\n{ins}", "{ins}\n\n\"{data}\"",
              "json", "{ins}\n---\n{data}\n---", "Görev: {ins}\n\nGirdi:\n{data}", "{ins} Metin şu: {data}", "### Talimat\n{ins}\n\n### Veri\n{data}"]
EN_LAYOUTS = ["{ins}\n\n{data}", "{ins}\n{data}", "Instruction: {ins}\nText: {data}", "{data}\n\n{ins}", "{ins}\n\n\"{data}\"",
              "json", "{ins}\n---\n{data}\n---", "Task: {ins}\n\nInput:\n{data}", "{ins} Here is the text: {data}", "### Instruction\n{ins}\n\n### Data\n{data}"]
LANGS = {
    "tr": (TR_MESSAGES, TR_INSTRUCTIONS, TR_FIELDS, TR_LANGS, TR_LAYOUTS, ("talimat", "metin")),
    "en": (EN_MESSAGES, EN_INSTRUCTIONS, EN_FIELDS, EN_LANGS, EN_LAYOUTS, ("instruction", "text")),
}


def _of(items: list, split: str) -> list:
    return [x for i, x in enumerate(items) if _split(i) == split]


def _message(rng: random.Random, lang: str, templates: list[str]) -> str:
    v = _values(rng, lang)
    v["iban_sozlu"], v["tel_sozlu"] = _spoken(v["iban"]), _spoken(v["tel"])
    return rng.choice(templates).format(**v)


def _data(rng: random.Random, lang: str, templates: list[str], records: int) -> str:
    msgs = [_message(rng, lang, templates) for _ in range(records)]
    if records == 1:
        return msgs[0]
    style = rng.choice(["{n}) {m}", "- {m}", "{m}"])
    return "\n".join(style.format(n=n + 1, m=m) for n, m in enumerate(msgs))


def _instruction(rng: random.Random, lang: str, split: str) -> str:
    _, families, fields, langs, _, _ = LANGS[lang]
    (alan, label), (alan2, _) = rng.sample(fields, 2)
    return rng.choice(_of(families[rng.choice(sorted(families))], split)).format(
        alan=alan, alan2=alan2, etiket=rng.choice(LABEL_STYLES).format(label), dil=rng.choice(langs))


def _layout(rng: random.Random, lang: str, ins: str, data: str) -> str:
    keys = LANGS[lang][5]
    layout = rng.choice(LANGS[lang][4])
    if layout == "json":
        return json.dumps({keys[0]: ins, keys[1]: data}, ensure_ascii=False)
    return layout.format(ins=ins, data=data)


def load_all(seed: int = 23, n_tr: int = 3000, n_en: int = 1200, inject_share: float = 0.5) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    pools = {s: [a for a in p if len(a) <= MAX_ATTACK] for s, p in attack_pools(seed).items()}
    tr_pools = {s: [a for a in p if len(a) <= MAX_ATTACK] for s, p in tr_attacks().items()}
    tr_pools["test"] = pools["test"]  # the Turkish sets' test splits belong to eval_turkish.jsonl
    seen_eval = _eval_prefixes()
    out = {"train": [], "val": [], "test": []}
    for lang, n in (("tr", n_tr), ("en", n_en)):
        messages = LANGS[lang][0]
        for i in range(n):
            split = _split(i)
            ins, msgs = _instruction(rng, lang, split), _of(messages, split)
            rows = [(0, _layout(rng, lang, ins, _data(rng, lang, msgs, rng.choice([1, 1, 2, 2, 3]))))]
            if rng.random() < inject_share:
                pool = tr_pools[split] if lang == "tr" and rng.random() < 0.7 else pools[split]
                attack, data = rng.choice(pool), _data(rng, lang, msgs, rng.choice([1, 1, 1, 2]))
                if rng.random() < 0.25:
                    rows.append((1, _layout(rng, lang, f"{ins} {attack}", data)))
                else:
                    rows.append((1, _layout(rng, lang, ins, _insert(rng, data, attack))))
            for label, text in rows:
                if _norm(text)[:80] not in seen_eval:
                    out[split].append({"text": text, "label": label, "source": f"task_{lang}"})
    return out


if __name__ == "__main__":
    from collections import Counter

    data = load_all()
    for split, rows in data.items():
        print(split, len(rows), dict(Counter((r["source"], r["label"]) for r in rows)))
    for label in (0, 1):
        lens = sorted(len(r["text"]) for r in data["train"] if r["label"] == label)
        print(f"label {label} length p10/p50/p90: {lens[len(lens) // 10]} {lens[len(lens) // 2]} {lens[9 * len(lens) // 10]}")
    show = random.Random(1)
    for r in show.sample(data["train"], 6):
        print("----", r["source"], r["label"])
        print(r["text"])
