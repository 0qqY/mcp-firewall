# Downloads the public injection datasets used by public_data.py, pinned to exact commits/versions.
#   InjecAgent  (MIT)  uiuc-kang-lab/InjecAgent @ f19c9f2
#   BIPIA       (MIT)  microsoft/BIPIA @ a004b69 - code attack instructions only
#   AgentDojo   (MIT)  agentdojo==0.1.35 from PyPI (data ships inside the package)
#   MCPTox      (no licence; authors' permission)  zhiqiangwang4/MCPTox-Benchmark @ f85189f
param([string]$Python = (Join-Path $env:USERPROFILE '.mcp-firewall\venv\Scripts\python.exe'))

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ext = Join-Path $PSScriptRoot 'data\external'
New-Item -ItemType Directory -Force (Join-Path $ext 'injecagent'), (Join-Path $ext 'bipia') | Out-Null

$ia = 'https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/f19c9f2c79a41046eb13c03c51a24c567a8ffa07/data'
foreach ($f in 'user_cases.jsonl', 'attacker_cases_dh.jsonl', 'attacker_cases_ds.jsonl') {
    Invoke-WebRequest "$ia/$f" -OutFile (Join-Path $ext "injecagent\$f")
}
$bp = 'https://raw.githubusercontent.com/microsoft/BIPIA/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/benchmark'
foreach ($f in 'code_attack_train.json', 'code_attack_test.json') {
    Invoke-WebRequest "$bp/$f" -OutFile (Join-Path $ext "bipia\$f")
}
# MCPTox has no licence file; used with the authors' permission (see public_data.py). Do not redistribute.
New-Item -ItemType Directory -Force (Join-Path $ext 'mcptox') | Out-Null
$mt = 'https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/f85189f9ad12504c197c7f920ab818a40657b1fa'
foreach ($f in 'pure_tool.json', 'response_all.json') {
    Invoke-WebRequest "$mt/$f" -OutFile (Join-Path $ext "mcptox\$f")
}
& $Python -m pip install --quiet 'agentdojo==0.1.35'
Write-Host "Public datasets ready in $ext"
