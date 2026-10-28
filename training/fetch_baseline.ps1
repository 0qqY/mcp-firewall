# Downloads the ProtectAI prompt-injection baseline (Apache-2.0) in the layout transformers.js expects,
# pinned to a commit and verified against the published SHA-256 of the ONNX weights.
param([string]$Dest = (Join-Path $PSScriptRoot '..\models\protectai-deberta-v3-pi-v2'))

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$commit = '90c9989b1a342275dd0d1a95aad283c04e075671'
$onnxSha256 = 'f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c'
$base = "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/$commit/onnx"

New-Item -ItemType Directory -Force (Join-Path $Dest 'onnx') | Out-Null
foreach ($file in 'config.json', 'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json', 'added_tokens.json', 'spm.model') {
    Invoke-WebRequest "$base/$file" -OutFile (Join-Path $Dest $file)
}

$model = Join-Path $Dest 'onnx\model.onnx'
Write-Host 'Downloading onnx/model.onnx (~704 MB)...'
Invoke-WebRequest "$base/model.onnx" -OutFile $model

$actual = (Get-FileHash $model -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $onnxSha256) {
    Remove-Item $model
    throw "SHA-256 mismatch for model.onnx: expected $onnxSha256, got $actual"
}
Write-Host "Baseline ready in $((Resolve-Path $Dest).Path) (sha256 verified)"
