# Scores fp32 and the int8 variants (quant_probe.py build output in night/q8/graphs) on night/q8/texts.jsonl (score.mjs --dump of held-out v1), then writes the report. 15.11.2026.
cd "$(dirname "$0")/../../training"
PY="$USERPROFILE/.mcp-firewall/venv/Scripts/python.exe"; M=../models/mcp-pi-mmbert-mixraw-ab4-evilsandangels-30; W=../night/q8
for g in $M/onnx/model.onnx $W/graphs/*.onnx; do n=$(basename $g .onnx); [ $n = model ] && n=fp32
  [ -f $W/s_$n.json ] && continue
  "$PY" -I -X utf8 quant_probe.py score --model $M --graph $g --texts $W/texts.jsonl --out $W/s_$n.json --name $n 2>&1 | grep -v -i warn
done
"$PY" -I -X utf8 quant_probe.py report --rows ../bench/heldout/heldout-v1.jsonl --base $W/s_fp32.json --md $W/report.md $(ls $W/s_*.json | grep -v fp32)
echo ALLDONE
