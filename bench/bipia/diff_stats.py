import json, sys
from pathlib import Path
import numpy as np
B = Path(sys.argv[1])
ours = np.load(B / "scores" / "protectai_v2_bipia.npz")["probs"]
stored = np.array(json.load(open(B / "repo" / "results" / "normalized_probs_bipia.json"))["probs"]["protectai-deberta-v2/original"])
done = ~np.isnan(ours)
d = np.abs(ours[done] - stored[done])
print("satır:", int(done.sum()), "| |fark|>0.001:", int((d > 0.001).sum()), "| >0.01:", int((d > 0.01).sum()), "| >0.05:", int((d > 0.05).sum()), "| >0.5:", int((d > 0.5).sum()))
print("karar (>=0.5) uyuşmazlığı:", int(((ours[done] >= 0.5) != (stored[done] >= 0.5)).sum()), "satır")
