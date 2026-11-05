# Projede artık kullanılmayan büyük dosyaları siler: eski DeBERTa eğitimleri, ara checkpoint'ler, eski ONNX
# modelleri ve gerekmeyen Hugging Face önbellekleri. Önce listeyi ve boyutları gösterir, onay ister.
#   powershell -ExecutionPolicy Bypass -File temizlik.ps1          # listele, onaylanırsa sil
#   powershell -ExecutionPolicy Bypass -File temizlik.ps1 -Liste   # yalnızca listele
#
# Kalanlar: models/mcp-pi-mmbert-mix-ab4-llm6-30 (varsayılan model), models/mcp-pi-mmbert-soup04-ab4,
# models/mcp-pi-mmbert-soup05-ab2 ve models/mcp-pi-mmbert-soup05 (önceki varsayılanlar, geri dönmek için), models/protectai-deberta-v3-pi-v2 (hazır baseline, test yedeği), training/runs altında iki
# soup'un ve bileşenlerinin best klasörleri (yeniden karıştırma ve değerlendirme için), görev talimatı
# denemelerinin best klasörleri, training/runs/mcp-pi-v9 (gerekirse v9'a dönmek için), eğitim verisi, loglar,
# eğitim ortamı (venv) ve mmBERT-base önbelleği.
param([switch]$Liste)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$runs = Join-Path $root 'training\runs'
$hub = Join-Path $env:USERPROFILE '.cache\huggingface\hub'

$targets = @()
# Eski DeBERTa eğitimleri ve denemeler (sonuçları README'de duruyor)
foreach ($r in 'mcp-pi', 'mcp-pi-v2', 'mcp-pi-v3', 'mcp-pi-v3b', 'mcp-pi-v4', 'mcp-pi-v5', 'mcp-pi-v6', 'mcp-pi-v7', 'mcp-pi-v8',
               'mcp-pi-v10', 'mcp-pi-v11', 'mcp-pi-v12', 'mcp-pi-v12-soup05', 'mcp-pi-v12-soup06', 'mcp-pi-mmbert-soup06',
               'smoke', 'smoke-bf16', 'smoke-fp32') {
    $targets += Join-Path $runs $r
}
# Sert-negatif turunun denenip seçilmeyen soup'ları (bileşenlerden combine.py ile saniyeler içinde yeniden üretilir)
foreach ($r in 'mcp-pi-mmbert-soup05-ab3', 'mcp-pi-mmbert-soup05-a4b3', 'mcp-pi-mmbert-soup05-ab4', 'mcp-pi-mmbert-soup03-ab4',
               'mcp-pi-mmbert-b2b4', 'mcp-pi-mmbert-soup05-ab24', 'mcp-pi-mmbert-soup06-ab24', 'mcp-pi-mmbert-soup05-ab5',
               'mcp-pi-mmbert-soup04-ab5') {
    $targets += Join-Path $runs $r
}
# mmBERT eğitimlerinin ara checkpoint'leri (best klasörleri kalıyor)
foreach ($r in 'mcp-pi-mmbert', 'mcp-pi-mmbert-v4', 'mcp-pi-mmbert-task', 'mcp-pi-mmbert-v4task', 'mcp-pi-mmbert-v4nomask',
               'mcp-pi-mmbert-dev', 'mcp-pi-mmbert-v4dev', 'mcp-pi-mmbert-dev2', 'mcp-pi-mmbert-dev3') {
    $targets += @(Get-ChildItem (Join-Path $runs $r) -Directory -Filter 'checkpoint-*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
}
# Eski ONNX modelleri (v9 gerekirse training/runs/mcp-pi-v9/best'ten export_onnx.py ile yeniden üretilir)
foreach ($m in 'mcp-pi-v1', 'mcp-pi-v2', 'mcp-pi-v7', 'mcp-pi-v9', 'mcp-pi-mmbert-soup05-ab3') {
    $targets += Join-Path $root "models\$m"
}
# Artık gerekmeyen Hugging Face önbellekleri (gerekirse ilk kullanımda yeniden iner)
foreach ($h in 'models--answerdotai--ModernBERT-base', 'models--microsoft--deberta-v3-base',
               'models--protectai--deberta-v3-base-prompt-injection-v2', 'models--Helsinki-NLP--opus-mt-en-de',
               'models--Helsinki-NLP--opus-mt-en-es', 'models--Helsinki-NLP--opus-mt-en-fr',
               'models--Helsinki-NLP--opus-mt-en-ru', 'models--Helsinki-NLP--opus-mt-tc-big-en-tr') {
    $targets += Join-Path $hub $h
}

$keep = @((Join-Path $root 'models\mcp-pi-mmbert-mix-ab4-llm6-30'), (Join-Path $runs 'mcp-pi-mmbert-mix-ab4-llm6-30'),
          (Join-Path $runs 'mcp-pi-mmbert-soup04-llm6'), (Join-Path $root 'models\mcp-pi-mmbert-soup04-ab4'), (Join-Path $root 'models\mcp-pi-mmbert-soup05-ab2'),
          (Join-Path $root 'models\mcp-pi-mmbert-soup05'),
          (Join-Path $runs 'mcp-pi-mmbert-soup04-ab4'), (Join-Path $runs 'mcp-pi-mmbert-soup05-ab2'), (Join-Path $runs 'mcp-pi-mmbert-soup05'),
          (Join-Path $runs 'mcp-pi-mmbert\best'), (Join-Path $runs 'mcp-pi-mmbert-v4\best'), (Join-Path $runs 'mcp-pi-mmbert-task\best'),
          (Join-Path $runs 'mcp-pi-mmbert-dev2\best'))
foreach ($k in $keep) {
    if ($targets -contains $k) { throw "liste korunması gereken bir klasörü içeriyor: $k" }
}

$rows = foreach ($t in $targets | Where-Object { Test-Path $_ }) {
    $bytes = (Get-ChildItem $t -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    [pscustomobject]@{ Yol = $t.Replace($root, '.').Replace($env:USERPROFILE, '~'); GB = [Math]::Round([double]$bytes / 1GB, 2); Tam = $t }
}
if (-not $rows) { 'Silinecek bir şey kalmamış.'; return }
$rows | Format-Table Yol, GB -AutoSize | Out-String -Width 200
$total = [Math]::Round(($rows | Measure-Object GB -Sum).Sum, 1)
"Toplam: $total GB, $(@($rows).Count) klasör"
if ($Liste) { return }

if ((Read-Host 'Bunlar kalıcı olarak silinsin mi? (e/h)') -ne 'e') { 'İptal edildi.'; return }
foreach ($r in $rows) { Remove-Item -LiteralPath $r.Tam -Recurse -Force }
"Silindi: $total GB."
if (-not (Test-Path (Join-Path $root 'models\mcp-pi-mmbert-mix-ab4-llm6-30\onnx\model.onnx'))) { throw 'varsayılan model bulunamadı!' }
'Varsayılan model yerinde: models\mcp-pi-mmbert-mix-ab4-llm6-30'
