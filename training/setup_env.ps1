# Creates a Python venv with a CUDA build of PyTorch that supports RTX 50-series (Blackwell, sm_120).
# The venv lives on a short path by default: CUDA DLL paths inside it exceed Windows' 260-character
# limit when the project sits in a deeply nested folder.
param([string]$Venv = (Join-Path $env:USERPROFILE '.mcp-firewall\venv'))

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Test-Path $Venv)) { py -3.12 -m venv $Venv }
$py = Join-Path $Venv 'Scripts\python.exe'

& $py -m pip install --upgrade pip
# Blackwell GPUs need wheels built against CUDA 12.8 or newer; older CUDA builds fail with "no kernel image".
& $py -m pip install torch --index-url https://download.pytorch.org/whl/cu128
& $py -m pip install -r requirements.txt
& $py check_gpu.py
Write-Host "Python for training: $py"
