"""Benign security-engineering text that talks about prompt injection without being one: commit messages,
changelog lines, README and docs paragraphs, test names, code comments, log and audit lines, and tool
results whose secrets a DLP layer replaced with [REDACTED:...] markers. English and Turkish, with matched
injected copies.

soup05-ab2 flagged a commit subject such as "Add prompt template pinning" at 0.996 and masked tool results
("... the key is [REDACTED:github_token]") near 1.0: our benign data had almost no text that names attacks,
instructions, system prompts or secrets in a developer's voice. Everything here comes from our own
templates; attack phrases appear only quoted or described, never addressed to the reader.

Templates are split by index (i % 10: 0 test, 1 val, rest train) like task_prompts.py, so a test row comes
from a template the model never saw. Half the rows get an attack from the benign_corpus pools placed inside
the same carrier, so "developer text about injection" alone does not mean safe.
"""

import random
import re

from benign_corpus import _insert, _split, attack_pools
from benign_prompts import _eval_prefixes, _norm
from turkish_data import attacks as tr_attacks

MAX_ATTACK = 350
MARKER = re.compile(r"\[REDACTED:[^\]]+\]")

EN_FEATURES = ["prompt template pinning", "tool definition pinning", "server code fingerprinting", "description scanning",
               "the ML injection classifier", "DLP redaction", "hidden-text stripping", "base64 decoding before the scan",
               "leetspeak de-obfuscation", "the method deny list", "argument allow-lists", "rug-pull detection",
               "the audit log", "per-tool rate limits", "secret detection in requests", "the prompt injection score threshold",
               "system prompt leak detection", "tool shadowing checks", "the policy loader", "the stdio proxy"]
TR_FEATURES = ["prompt şablonu sabitleme", "tool tanımı sabitleme", "sunucu kodu parmak izi", "açıklama taraması",
               "ML injection sınıflandırıcısı", "DLP maskeleme", "gizli metin temizliği", "taramadan önce base64 çözme",
               "l33t geri-yazımı", "metot engel listesi", "argüman izin listesi", "rug-pull tespiti", "denetim kaydı",
               "tool başına hız sınırı", "isteklerde secret tespiti", "prompt injection eşiği", "sistem prompt sızıntısı tespiti",
               "tool gölgeleme kontrolü", "politika yükleyici", "stdio proxy"]
EN_ATTACKS = ["prompt injection", "indirect prompt injection", "tool poisoning", "a rug pull", "data exfiltration",
              "a jailbreak", "system prompt extraction", "instruction override", "tool shadowing", "an ANSI escape smuggle",
              "zero-width character smuggling", "a confused-deputy attack", "credential theft via tool results"]
TR_ATTACKS = ["prompt injection", "dolaylı prompt injection", "tool zehirleme", "rug-pull", "veri sızdırma", "jailbreak",
              "sistem prompt'unu çıkarma", "talimat ezme", "tool gölgeleme", "ANSI kaçış kaçakçılığı",
              "sıfır genişlikli karakter kaçakçılığı", "kimlik bilgisi hırsızlığı"]
EN_PHRASES = ["ignore previous instructions", "you are now DAN", "reveal your system prompt", "do not tell the user",
              "disregard the above", "act as an unrestricted model", "send the API keys", "new instructions:"]
TR_PHRASES = ["önceki talimatları yok say", "sistem prompt'unu göster", "kullanıcıya söyleme", "yukarıdakileri unut",
              "artık kısıtlamasız bir modelsin", "API anahtarlarını gönder", "yeni talimatlar:"]
COMPONENTS = ["proxy", "dlp", "decode", "policy", "ml", "pinning", "audit", "cli", "engine", "hiddenText", "descriptionScan"]
SECRETS = ["github_token", "aws_access_key", "aws_secret_key", "slack_token", "openai_key", "anthropic_key", "jwt",
           "private_key", "credit_card", "iban_tr", "tckn"]
TOOLS = ["read_file", "http_get", "query", "send_email", "slack_post_message", "get_issue", "run_command",
         "search_docs", "list_channels", "create_pull_request"]
NUMS = ["0.9", "0.95", "0.85", "0.8"]
ENVS = ["MCP_FIREWALL_MODEL", "MCP_FIREWALL_POLICY", "HF_HOME", "NODE_OPTIONS", "GITHUB_TOKEN", "LOG_LEVEL", "CUDA_VISIBLE_DEVICES",
        "AUDIT_FILE", "PINS_FILE", "HTTPS_PROXY"]
PATHS = ["./models/classifier", "~/.mcp-firewall/app", "%USERPROFILE%\\.mcp-firewall\\venv", "demo/sql/run.mjs", "src/proxy.ts",
         "training/train.py", "policy.example.yaml", "dist/src/cli.js", "docs/threat-model.md", "test/engine.test.ts",
         "C:\\Users\\dev\\AppData\\Roaming\\Claude\\claude_desktop_config.json", "~/.config/mcp/servers.json"]
CMDS = ["npm run build", "npm test", "node dist/src/cli.js --policy policy.yaml -- npx -y @scope/server", "python train.py --lr 3e-5",
        "git push origin main", "npx tsc --noEmit", "pip install -r requirements.txt", "node --test test/*.test.ts",
        "python export_onnx.py --quantize", "docker compose up -d"]
KEYS = ["ml.threshold", "pinning.onNew", "dlp.scanResponses", "methods.deny", "audit.file", "decoding.enabled",
        "hiddenText.mode", "pinning.serverCode", "tools.allow", "ml.scan.promptResults"]

EN = {
    "commit": [
        "Add {feature}",
        "feat({component}): add {feature}",
        "fix({component}): stop {feature} from flagging benign tool results",
        "Fix false positive on {attack} docs in {feature}",
        "test: cover {attack} in tool results",
        "refactor({component}): move {feature} behind a policy flag",
        "Block {attack} in {tool} results; warn only on prompts/get",
        "docs: explain how {feature} stops {attack}",
        "chore: bump threshold for {feature} to {num}",
        "Revert \"Disable {feature} by default\"",
        "fix: neutralise [REDACTED:{secret}] markers before the ML scan",
        "perf({component}): cache scores for repeated {tool} results",
        "Handle escaped newlines in {feature}",
        "feat: detect \"{phrase}\" style overrides in tool descriptions",
        "Merge pull request #{n} from dev/{component}-{n2}",
    ],
    "changelog": [
        "- {feature}: now blocks {attack} hidden in {tool} results.",
        "### Fixed\n- {feature} no longer flags commit messages that mention {attack}.",
        "v0.{n2}.0 — adds {feature}, documents {attack}, and lowers the default threshold to {num}.",
        "* Breaking: {feature} is on by default. Set `enabled: false` in policy.yaml to keep the old behaviour.",
        "Release notes: {feature} is faster, and secrets in {tool} arguments are masked as [REDACTED:{secret}].",
        "### Security\n- Closed a gap where {attack} could reach the host through {tool}.",
        "Known issue: {feature} may warn on README files that quote \"{phrase}\".",
    ],
    "docs": [
        "{feature} protects against {attack}. When a tool result tries to override the assistant's instructions, the firewall blocks it and writes an audit entry.",
        "## How {feature} works\nThe proxy sits between the MCP host and the server. Every {tool} result is scanned before the model sees it.",
        "Attackers often hide phrases like \"{phrase}\" in web pages or issue comments. {feature} catches these before they reach the model.",
        "To test {feature}, run the demo: it starts a mock server that returns a poisoned {tool} result and shows the block in the audit log.",
        "Threat model: we assume the MCP server may be malicious or compromised. {attack} is the main risk, and {feature} is one layer against it.",
        "Note: {feature} is a defence-in-depth measure, not a guarantee. Keep tool permissions minimal and review the audit log.",
        "If a legitimate result is blocked, lower the threshold (currently {num}) or add the tool to `ml.allowTools`.",
        "Example policy:\n```yaml\nml:\n  enabled: true\n  threshold: {num}\ntools:\n  deny: [{tool}]\n```",
        "The classifier was trained on public {attack} datasets plus synthetic MCP tool results. Scores above {num} are treated as injections.",
        "Why pin tool definitions? A server can change a tool's description after you approved it ({attack}). Pinning detects the change and hides the tool.",
        "Secrets found in results are replaced with markers such as [REDACTED:{secret}] so the model never sees the raw value.",
        "FAQ: Does {feature} send data anywhere? No. Everything runs locally; the model is loaded from disk.",
    ],
    "test": [
        "test('{feature} blocks {attack} in {tool} results')",
        "it('does not flag a README that quotes \"{phrase}\"', async () => {{",
        "test('a DLP marker [REDACTED:{secret}] does not trip the ML scan')",
        "describe('{component}: {attack}', () => {{",
        "✔ {feature} hides a tool whose description changed ({n}ms)",
        "# Subtest: {tool} result with {attack} is blocked\nok {n2} - {tool} result with {attack} is blocked",
        "def test_{component}_rejects_{tool}_with_override():\n    \"\"\"A result that says '{phrase}' must be flagged.\"\"\"",
        "assert.equal(reply.result.isError, true); // {attack} must be blocked",
    ],
    "comment": [
        "// {feature}: the server may rewrite a description after approval, so compare against the pinned hash.",
        "# Strip zero-width characters first; otherwise \"{phrase}\" can be split to dodge the pattern scan.",
        "/* Scores below {num} pass. The classifier sees decoded text, so base64-wrapped {attack} is still caught. */",
        "// TODO: {feature} still warns on docs that quote \"{phrase}\"; add hard negatives to the training set.",
        "// Do not log raw arguments: they may contain secrets. Log the [REDACTED:{secret}] form instead.",
        "# This regex matches common {attack} phrasings; the ML layer handles the rest.",
    ],
    "log": [
        "[{time}] {component}: blocked {tool} result (score {score}, {attack})",
        "[{time}] dlp: redacted 1 secret in {tool} response ([REDACTED:{secret}])",
        "{{\"ts\":\"2026-10-{d}T{time}Z\",\"event\":\"result_blocked\",\"tool\":\"{tool}\",\"reason\":\"ml score {score} >= {num}\"}}",
        "{{\"ts\":\"2026-10-{d}T{time}Z\",\"event\":\"tool_hidden\",\"tool\":\"{tool}\",\"reason\":\"pinned definition changed\"}}",
        "WARN {component} prompts/get result scored {score}; delivered with a warning (mode: warn)",
        "INFO pinning: {n} tools pinned for server '{component}-mock'",
    ],
    "redacted": [
        "Loaded configuration from .env: GITHUB_TOKEN=[REDACTED:{secret}], LOG_LEVEL=debug, PORT=8080.",
        "The deploy key is [REDACTED:{secret}]; rotate it after the migration.",
        "Here is the file you asked for:\naws_access_key_id = [REDACTED:aws_access_key]\nregion = eu-central-1",
        "Message from #ops: the new token is [REDACTED:{secret}], please update the CI secret.",
        "Query returned 3 rows: alice (card [REDACTED:credit_card]), bob (card [REDACTED:credit_card]), carol (no card).",
        "Commit {sha} removed a hard-coded key ([REDACTED:{secret}]) from config.js.",
        "Customer record: name Jane Doe, IBAN [REDACTED:iban_tr], status active.",
        "Build log: using token [REDACTED:{secret}] for registry auth... done in {n}s.",
    ],
    "setup": [
        "The model is not stored in the repository; pass its path with `{env}` (default `{path}`).",
        "## Installation\nRun `{cmd}`, then point your MCP client at `{path}`. No network access is needed after the first run.",
        "Set `{key}` to `false` if you only want monitoring. The firewall then logs `would_block` entries instead of blocking.",
        "Tip: start a new server in `mode: monitor`, review the audit log for a day, tune the rules, then switch to `enforce`.",
        "Requirements: Node 20+, about {n2} GB of disk for the model, and optionally a CUDA GPU for training.",
        "The environment is created under `{path}` because deep folders push CUDA DLL paths past Windows' 260-character limit.",
        "1. Clone the repo.\n2. Run `{cmd}`.\n3. Copy `policy.example.yaml` to `policy.yaml` and adjust `{key}`.\n4. Restart the client.",
        "Configuration lives in `{path}`. Every key has a default, so an empty file is valid; `{key}` is the one most people change.",
        "Troubleshooting: if the client shows no tools, check stderr. The firewall writes its own messages there, and audit records go to `{env}`.",
        "Limitations: the first version seen is trusted, so a package that was malicious from day one is not caught by pinning alone.",
        "Measured with the default model at threshold {num}, 1500-character chunks, and the firewall's decoding steps enabled.",
        "The dashboard binds to 127.0.0.1 only and rejects foreign `Host`/`Origin` headers, since audit text is attacker-controlled.",
        "### Reading side\nEverything the server sends is untrusted: tool definitions, results, prompt templates and server instructions.",
    ],
}
TR = {
    "commit": [
        "{feature} eklendi",
        "{component}: {feature} eklendi",
        "{component}: {feature} zararsız tool sonuçlarını bloklamasın",
        "{attack} anlatan dokümanlarda {feature} yanlış alarmı düzeltildi",
        "test: tool sonuçlarında {attack} senaryosu eklendi",
        "{tool} sonuçlarında {attack} engellenir; prompts/get yalnızca uyarır",
        "docs: {feature} {attack} saldırısını nasıl durduruyor",
        "{feature} eşiği {num} yapıldı",
        "ML: [REDACTED:{secret}] işaretini skorlamadan önce nötrle",
        "Açıklamalarda \"{phrase}\" tarzı talimat ezmeleri yakalanıyor",
        "{n}. madde: {feature} için demo eklendi",
    ],
    "changelog": [
        "- {feature}: artık {tool} sonuçlarında gizlenen {attack} saldırısını engelliyor.",
        "### Düzeltildi\n- {feature}, {attack} kelimesi geçen commit mesajlarını artık bloklamıyor.",
        "v0.{n2}.0 — {feature} eklendi, {attack} belgelendi, varsayılan eşik {num} oldu.",
        "* Kırıcı değişiklik: {feature} varsayılan olarak açık. Eski davranış için policy.yaml'da `enabled: false` yazın.",
        "Bilinen sorun: {feature}, \"{phrase}\" ifadesini alıntılayan README dosyalarında uyarı verebilir.",
    ],
    "docs": [
        "{feature}, {attack} saldırısına karşı korur. Bir tool sonucu asistanın talimatlarını ezmeye çalışırsa firewall onu engeller ve denetim kaydına yazar.",
        "## {feature} nasıl çalışır\nProxy, MCP istemcisi ile sunucu arasında durur. Her {tool} sonucu model görmeden önce taranır.",
        "Saldırganlar \"{phrase}\" gibi ifadeleri web sayfalarına veya issue yorumlarına gizler. {feature} bunları modele ulaşmadan yakalar.",
        "Tehdit modeli: MCP sunucusunun kötü niyetli ya da ele geçirilmiş olabileceğini varsayıyoruz. Ana risk {attack}; {feature} buna karşı katmanlardan biri.",
        "Not: {feature} derinlemesine savunmanın bir parçasıdır, garanti değildir. Tool izinlerini dar tutun ve denetim kaydını inceleyin.",
        "Meşru bir sonuç bloklanırsa eşiği düşürün (şu an {num}) ya da tool'u `ml.allowTools` listesine ekleyin.",
        "Sonuçlarda bulunan secret'lar [REDACTED:{secret}] gibi işaretlerle değiştirilir; model ham değeri hiç görmez.",
        "SSS: {feature} veriyi bir yere gönderiyor mu? Hayır. Her şey yerelde çalışır, model diskten yüklenir.",
        "Neden tool tanımları sabitlenir? Sunucu onayladığınız bir açıklamayı sonradan değiştirebilir ({attack}). Sabitleme bunu fark eder ve tool'u gizler.",
    ],
    "test": [
        "test('{feature} {tool} sonucundaki {attack} saldırısını engeller')",
        "test('\"{phrase}\" alıntılayan README bloklanmaz')",
        "✔ açıklaması değişen tool gizlenir ({n}ms)",
        "// {attack} engellenmeli\nassert.equal(reply.result.isError, true);",
    ],
    "comment": [
        "// {feature}: sunucu açıklamayı onaydan sonra değiştirebilir, bu yüzden sabitlenmiş hash ile karşılaştır.",
        "# Önce sıfır genişlikli karakterleri at; yoksa \"{phrase}\" bölünerek desen taramasından kaçabilir.",
        "// YAPILACAK: {feature}, \"{phrase}\" alıntılayan dokümanlarda hâlâ uyarıyor; eğitime sert negatif ekle.",
        "// Ham argümanları loglama, secret içerebilir. [REDACTED:{secret}] biçimini logla.",
    ],
    "log": [
        "[{time}] {component}: {tool} sonucu engellendi (skor {score}, {attack})",
        "[{time}] dlp: {tool} yanıtında 1 secret maskelendi ([REDACTED:{secret}])",
        "UYARI {component}: prompts/get sonucu {score} aldı; uyarıyla iletildi (mod: warn)",
    ],
    "redacted": [
        ".env dosyası yüklendi: GITHUB_TOKEN=[REDACTED:{secret}], LOG_LEVEL=debug, PORT=8080.",
        "Deploy anahtarı [REDACTED:{secret}]; geçişten sonra yenileyin.",
        "#ops kanalından mesaj: yeni token [REDACTED:{secret}], lütfen CI secret'ını güncelleyin.",
        "Sorgu 3 satır döndürdü: Ayşe (kart [REDACTED:credit_card]), Mehmet (kart [REDACTED:credit_card]), Can (kart yok).",
        "Müşteri kaydı: Elif Yılmaz, TCKN [REDACTED:tckn], IBAN [REDACTED:iban_tr], durum aktif.",
        "Derleme kaydı: kayıt defteri için [REDACTED:{secret}] token'ı kullanılıyor... {n} sn'de bitti.",
    ],
    "setup": [
        "Önbellek klasörünü değiştirmek için `{env}` değişkenini ayarlayın; boş bırakılırsa `{path}` kullanılır.",
        "## Kurulum\nÖnce `{cmd}` çalıştırın, ardından MCP istemcinizi `{path}` dosyasına yönlendirin. İlk çalıştırmadan sonra ağ gerekmez.",
        "Yalnızca izlemek istiyorsanız `{key}` değerini `false` yapın; firewall o zaman engellemek yerine `would_block` kaydı yazar.",
        "**Uyarı:** `{cmd}` komutu yönetici yetkisi istemez; hata alırsanız önce `{path}` dosyasının izinlerini kontrol edin.",
        "Gereksinimler: Node 20+, model için yaklaşık {n2} GB disk ve eğitim için isteğe bağlı bir CUDA GPU.",
        "Testler `{path}` altında; tek bir dosyayı çalıştırmak için `{cmd}` yazmanız yeterli, model gerektiren testler {n2} saniye kadar sürer.",
        "1. Depoyu klonlayın.\n2. `{cmd}` komutunu çalıştırın.\n3. `policy.example.yaml` dosyasını `policy.yaml` olarak kopyalayıp `{key}` ayarını düzenleyin.\n4. İstemciyi yeniden başlatın.",
        "Yapılandırma `{path}` dosyasındadır. Her anahtarın varsayılanı vardır, boş dosya da geçerlidir; en sık değiştirilen `{key}`.",
        "Sorun giderme: istemci hiç tool göstermiyorsa stderr'e bakın. Firewall kendi mesajlarını oraya, denetim kayıtlarını `{env}` ile verilen dosyaya yazar.",
        "Bilinen kısıt: Windows'ta yol {n} karakteri geçerse `{cmd}` başarısız olabilir; projeyi daha kısa bir klasöre taşıyın.",
        "Tablodaki sayılar {n2} çalıştırmanın ortalamasıdır; eşik {num} ve varsayılan politika ile alınmıştır.",
        "Sürüm {n2}.{n} ile `{key}` anahtarı yeniden adlandırıldı; eski ad bir sürüm daha okunur ve uyarı verir.",
        "**Yazma tarafı** (istemciden giden istekler): argümanlar `{key}` kurallarına göre denetlenir, secret'lar maskelenir.",
        "{n}. **`{key}` (varsayılan `{num}`):** {feature} bu ayarla açılıp kapanır. Değişiklik bir sonraki çağrıda geçerli olur.",
        "Docker kullanmak isterseniz `{cmd}` yeterli; konteyner `{path}` dosyasını salt okunur bağlar.",
        "Bu belge {feature} için tasarım notlarını içerir. Değişiklik geçmişi için `{path}`, kullanım için README'ye bakın.",
    ],
}
LANGS = {"en": (EN, EN_FEATURES, EN_ATTACKS, EN_PHRASES), "tr": (TR, TR_FEATURES, TR_ATTACKS, TR_PHRASES)}


def _of(items: list, split: str) -> list:
    return [x for i, x in enumerate(items) if _split(i) == split]


def _fill(rng: random.Random, lang: str, template: str) -> str:
    _, features, attacks, phrases = LANGS[lang]
    return template.format(
        feature=rng.choice(features), attack=rng.choice(attacks), phrase=rng.choice(phrases), component=rng.choice(COMPONENTS),
        secret=rng.choice(SECRETS), tool=rng.choice(TOOLS), num=rng.choice(NUMS), env=rng.choice(ENVS), path=rng.choice(PATHS),
        cmd=rng.choice(CMDS), key=rng.choice(KEYS), n=rng.randint(2, 400), n2=rng.randint(1, 40),
        score=f"{rng.uniform(0.9, 1.0):.3f}", time=f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}",
        d=f"{rng.randint(1, 28):02d}", sha="".join(rng.choice("0123456789abcdef") for _ in range(7)))


def _text(rng: random.Random, lang: str, split: str) -> str:
    """One to four snippets from different kinds, so commit lists, changelogs and mixed pages show up too."""
    families = LANGS[lang][0]
    parts = [_fill(rng, lang, rng.choice(_of(families[k], split))) for k in rng.sample(sorted(families), rng.choice([1, 1, 2, 3, 4]))]
    return rng.choice(["\n", "\n\n", " "]).join(parts)


def load_all(seed: int = 31, n_en: int = 2500, n_tr: int = 2500, inject_share: float = 0.5) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    pools = {s: [a for a in p if len(a) <= MAX_ATTACK] for s, p in attack_pools(seed).items()}
    tr_pools = {s: [a for a in p if len(a) <= MAX_ATTACK] for s, p in tr_attacks().items()}
    tr_pools["test"] = pools["test"]  # the Turkish sets' test splits belong to eval_turkish.jsonl
    seen_eval = _eval_prefixes()
    out = {"train": [], "val": [], "test": []}
    for lang, n in (("en", n_en), ("tr", n_tr)):
        for i in range(n):
            split = _split(i)
            text = _text(rng, lang, split)
            rows = [(0, text)]
            if rng.random() < inject_share:
                pool = tr_pools[split] if lang == "tr" and rng.random() < 0.7 else pools[split]
                rows.append((1, _insert(rng, _text(rng, lang, split), rng.choice(pool))))
            for label, t in rows:
                if rng.random() < 0.5:  # the firewall scans "redacted" in place of a DLP marker (proxy.ts mlFlags)
                    t = MARKER.sub("redacted", t)
                if _norm(t)[:80] not in seen_eval:
                    out[split].append({"text": t, "label": label, "source": f"dev_{lang}"})
    return out


if __name__ == "__main__":
    from collections import Counter

    data = load_all()
    for split, rows in data.items():
        print(split, len(rows), dict(Counter((r["source"], r["label"]) for r in rows)))
    show = random.Random(1)
    for r in show.sample(data["train"], 6):
        print("----", r["source"], r["label"])
        print(r["text"])
