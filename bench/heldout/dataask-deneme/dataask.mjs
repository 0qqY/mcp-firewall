/**
 * "Data ask" check for definitions: a tool (usually one parameter description) that asks the model, in plain product
 * language, to hand over data the agent holds and the tool has no use for — the conversation, its system prompt,
 * secrets of other services, local credential files, environment variables, what other tools returned, payment or
 * identity details. There is no command and no hidden tag, so the injection patterns and the classifier both miss it
 * (journal 101-105). Each rule names a source on the agent's side; a tool's own inputs ("your API key for this
 * service", "path of the .env file to load") are deliberately not matched.
 *
 * All patterns are linear: bounded gaps, no nested quantifiers.
 */
const G = '[^.\\n]{0,60}?'; // a short gap inside one sentence
const RULES = [
    // --- the conversation itself
    [
        'conversation',
        `\\b(?:full|entire|whole|complete|verbatim|word[- ]for[- ]word)\\b${G}\\b(?:chat|conversation|dialogue|transcript)\\b` +
            `|\\b(?:chat|conversation|dialogue|discussion)\\b${G}\\b(?:so far|up to (?:now|this point)|until now|in full|verbatim|word for word)\\b` +
            `|\\b(?:previous|earlier|prior|preceding|past)\\s+(?:messages|turns|requests|questions)\\b${G}\\b(?:conversation|chat|session|user)\\b` +
            `|\\ball\\s+(?:the\\s+)?(?:previous|earlier|prior)\\s+(?:messages|turns)\\b` +
            `|\\beverything\\s+the\\s+user\\s+(?:has\\s+)?(?:said|asked|told|written|typed)\\b` +
            `|\\bwhat\\s+the\\s+user\\s+and\\s+(?:the\\s+|you\\b)` +
            `|\\b(?:the\\s+)?requests\\s+the\\s+user\\s+made\\s+before\\b` +
            `|\\bcopy\\s+of\\s+the\\s+(?:chat|conversation|dialogue)\\b`,
    ],
    [
        'conversation',
        `\\b(?:sohbet|konuşma|görüşme|yazışma)\\w*\\b${G}\\b(?:tamamı|tümü|hepsi|birebir|kelimesi kelimesine|buraya kadar\\w*|şimdiye kadar\\w*)` +
            `|\\b(?:buraya|şimdiye)\\s+kadar\\w*\\s${G}\\b(?:konuş\\w+|sohbet\\w*|yazış\\w+|sorduk\\w*|mesaj\\w*)` +
            `|\\bönceki\\s+(?:mesaj|ileti|istek|soru)\\w*\\b${G}\\b(?:sohbet|konuşma|oturum|kullanıcı)\\w*` +
            `|\\b(?:sohbet|konuşma|oturum)\\w*\\s${G}\\bönceki\\s+(?:mesaj|ileti)\\w*` +
            `|\\bkullanıcının\\s+(?:daha\\s+)?önce(?:ki)?\\s+(?:yazdık|söyledik|sorduk|istek|mesaj)\\w*`,
    ],
    // --- the model's own instructions and tool list
    [
        'system-prompt',
        `\\b(?:your|the\\s+(?:assistant|model|agent)'?s?)\\s+(?:own\\s+)?(?:system\\s+(?:prompt|message)|hidden\\s+(?:rules|configuration|instructions)|initial\\s+instructions)\\b` +
            `|\\bsystem\\s+prompt\\b${G}\\b(?:you|your)\\b` +
            `|\\b(?:instructions|rules|guidelines|developer\\s+message|system\\s+message)\\s+(?:that\\s+)?you\\s+(?:were\\s+given|received|follow|got|have\\s+been\\s+given)\\b` +
            `|\\b(?:hidden|secret|internal)\\s+(?:rules|instructions|configuration|guidelines)\\s+(?:that\\s+)?you\\b` +
            `|\\blist\\s+of\\s+(?:the\\s+)?(?:your\\s+tools|tools\\s+you\\s+have)\\b`,
    ],
    [
        'system-prompt',
        `\\b(?:sistem\\s+istemi(?:niz|n)\\b|sistem\\s+mesajı(?:nız|n)\\b)` +
            `|\\b(?:geliştirici|operatör)\\w*\\s+size\\s+verdiği\\s+(?:talimat|yönerge|kural)\\w*` +
            `|\\bsize\\s+verilen\\s+(?:talimat|yönerge|kural)\\w*` +
            `|\\bgizli\\s+(?:yapılandırma|talimat|kural|yönerge)\\w*(?:nız|niz|ınız|iniz)\\b` +
            `|\\buyduğunuz\\s+(?:gizli\\s+)?(?:kural|talimat)\\w*` +
            `|\\baraç\\s+listeniz\\b`,
    ],
    // --- secrets of the user or of other services
    [
        'credentials',
        `\\b(?:passwords?|passphrases?|api\\s+keys?|access\\s+tokens?|bearer\\s+tokens?|auth(?:entication)?\\s+tokens?|secrets?|credentials|login\\s+details|session\\s+cookies?)\\b${G}` +
            `\\b(?:(?:have\\s+)?appeared|you\\s+(?:can\\s+)?(?:see|saw|have\\s+seen|find|read)|(?:the\\s+)?user\\s+(?:has\\s+)?(?:mentioned|shared|given|typed|uses)|in\\s+(?:this|the)\\s+(?:session|conversation|chat)|in\\s+your\\s+context|(?:an)?other\\s+(?:connected\\s+)?(?:service|site|website|account|tool)s?|any\\s+(?:web)?site)\\b` +
            `|\\b(?:the\\s+)?user'?s\\s+(?:\\w+\\s+){0,4}?(?:passwords?|api\\s+keys?|(?:access\\s+|bearer\\s+|personal\\s+access\\s+)?tokens?|credentials|private\\s+key|ssh\\s+(?:private\\s+)?key|password\\s+manager|saved\\s+(?:secrets|passwords|logins))\\b` +
            `|\\b(?:access|bearer|auth)\\s+token\\s+(?:of|from|for)\\s+(?:an)?other\\s+(?:connected\\s+)?(?:service|account|tool)\\b` +
            `|\\bsaved\\s+(?:secrets|passwords|logins)\\s+(?:that\\s+)?you\\b`,
    ],
    [
        'credentials',
        `\\b(?:parola|şifre|api\\s+anahtar|erişim\\s+belirteç|gizli\\s+anahtar|giriş\\s+bilgi|oturum\\s+çerez)\\w*\\b${G}` +
            `(?:\\bgeçen\\b|\\bandığı\\b|\\bpaylaştığı\\b|\\bverdiği\\b|\\bgördüğünüz\\b|\\bbu\\s+(?:oturum|sohbet)\\w*|\\bbaşka\\s+(?:bir\\s+)?(?:servis|site|hesap|araç)\\w*)` +
            `|\\b(?:bu\\s+(?:oturum|sohbet)\\w*|kullanıcının(?:\\s+\\w+){0,4}?|başka\\s+(?:bir\\s+)?(?:servis|site|hesab)\\w*)\\s+${G}(?:parola|şifre|api\\s+anahtar|erişim\\s+belirteç|giriş\\s+bilgi|özel\\s+anahtar)\\w*`,
    ],
    // --- local credential stores and private files
    [
        'local-files',
        `(?:contents?|text|value|copy|whatever\\s+is\\s+stored|everything)\\b${G}(?:~[/\\\\]\\.[\\w-]+|\\.env\\b|\\.netrc\\b|\\.git-credentials\\b|\\.npmrc\\b|id_(?:rsa|ed25519|ecdsa)\\b|\\bhome\\s+directory\\b)` +
            `|~[/\\\\]\\.(?:ssh|aws|gnupg|kube|docker|azure|netrc|git-credentials|npmrc|pypirc)\\b|~[/\\\\]\\.config[/\\\\](?:gcloud|gh)\\b` +
            `|\\bprivate\\s+key\\s+file\\b|\\b(?:browser'?s?\\s+)?saved\\s+cookies\\b${G}\\b(?:you|user)\\b|\\bpassword\\s+manager\\s+export\\b`,
    ],
    [
        'local-files',
        `(?:~[/\\\\]\\.[\\w-]+|\\.env\\b|\\.netrc\\b|\\.git-credentials\\b)${G}(?:içeriği|ne\\s+varsa|kopyası|metni)` +
            `|\\bözel\\s+anahtar\\s+dosya\\w*`,
    ],
    // --- environment variables
    [
        'environment',
        `\\b(?:all|every|each|any|the\\s+values?\\s+of)\\b${G}\\benvironment\\s+variables?\\b` +
            `|\\benvironment\\s+variables?\\s+of\\s+the\\s+machine\\b` +
            `|\\b(?:output|result)\\s+of\\s+(?:printenv|env|set)\\b|\\bprintenv\\b` +
            `|\\bvalues?\\s+of\\s+(?:the\\s+)?[A-Z][A-Z0-9]*_(?:API_)?(?:KEY|TOKEN|SECRET|PASSWORD)\\b` +
            `|\\bvariables\\s+whose\\s+names?\\s+contain\\b`,
    ],
    [
        'environment',
        `\\bortam\\s+değişken\\w*\\b${G}(?:hepsi|tümü|tamamı|değer\\w*)|\\b(?:bu\\s+makine\\w*|çalıştığınız\\s+makine\\w*)\\s${G}\\bortam\\s+değişken\\w*` +
            `|\\b[A-Z][A-Z0-9]*_(?:API_)?(?:KEY|TOKEN|SECRET|PASSWORD)\\s+değer\\w*`,
    ],
    // --- what other tools returned
    [
        'other-tools',
        `\\b(?:what|everything|anything)\\b${G}\\b(?:other|previous|earlier)\\s+tools?\\s+(?:have\\s+)?returned\\b` +
            `|\\b(?:results?|outputs?|responses?)\\s+(?:of|from)\\s+(?:the\\s+)?(?:other|previous|earlier)\\s+tool(?:s|\\s+calls?)?\\b` +
            `|\\b(?:e-?mails?|messages|documents|files)\\s+(?:that\\s+)?you\\s+(?:have\\s+)?read\\s+for\\s+the\\s+user\\b` +
            `|\\b(?:read|fetched|retrieved|got)\\s+from\\s+the\\s+user'?s\\s+(?:mailbox|inbox|drive|calendar)\\b` +
            `|\\brows\\b${G}\\b(?:database|sql)\\s+quer(?:y|ies)\\b${G}\\b(?:conversation|session|earlier|previous)\\b`,
    ],
    [
        'other-tools',
        `\\b(?:diğer|önceki|başka)\\s+araç\\w*\\b${G}\\b(?:döndür\\w+|sonuç\\w*|çıktı\\w*)` +
            `|\\bönceki\\s+veritabanı\\s+sorgu\\w*\\b${G}\\bsatır\\w*` +
            `|\\bkullanıcı\\s+için\\s+okuduğunuz\\s+(?:e-?posta|belge|mesaj|dosya)\\w*`,
    ],
    // --- payment and identity details
    [
        'personal-data',
        `\\bcard\\s+(?:number|details)\\b${G}\\b(?:(?:the\\s+)?user\\s+(?:has\\s+)?(?:mentioned|given|shared|typed)|security\\s+code|cvv|cvc)\\b` +
            `|\\b(?:the\\s+)?user'?s\\s+(?:passport|national\\s+id|social\\s+security|bank\\s+account|credit\\s+card|tax)\\s+(?:or\\s+[\\w\\s]{0,30}?)?(?:number|details|id)\\b` +
            `|\\b(?:diagnoses|medication|insurance\\s+numbers?)\\b${G}\\b(?:user'?s\\s+documents|anywhere)\\b`,
    ],
    [
        'personal-data',
        `\\bkullanıcının\\s+(?:verdiği|andığı|paylaştığı)\\s+(?:kart|kimlik|pasaport|banka)\\s+\\w+` +
            `|\\bkullanıcının\\s+(?:pasaport|kimlik|T\\.?C\\.?\\s+kimlik)\\s+(?:numara\\w*|no\\w*)` +
            `|\\bkart\\s+numara\\w*\\b${G}\\bgüvenlik\\s+kodu\\w*`,
    ],
];
export const DATA_ASK_RULES = RULES.map(([kind, src]) => ({ kind, pattern: new RegExp(src, 'iu') }));
/** Kinds of agent-held data the text asks for, in rule order and without repeats. */
export function findDataAsks(text) {
    const kinds = [];
    for (const r of DATA_ASK_RULES)
        if (!kinds.includes(r.kind) && r.pattern.test(text))
            kinds.push(r.kind);
    return kinds;
}
//# sourceMappingURL=dataask.js.map