Eşik 0.3; 333 satır. `karar farkı`: fp32 ile eşikte farklı karar verilen satır sayısı.

| graph | dosya MB | peak working set MB | peak commit MB | yükleme sn | ms/pencere | recall | FPR | AUC | karar farkı | en büyük skor farkı | ortalama skor farkı |
|---|---|---|---|---|---|---|---|---|---|---|---|
| fp32 | 1174 | 2726 | 4135 | 3.2 | 62.8 | 95.3% | 12.6% | 0.977 | 0 | 0.000 | 0.0000 |
| int8-all-perchannel | 295 | 1279 | 2667 | 2.0 | 35.5 | 90.7% | 9.8% | 0.966 | 18 | 1.000 | 0.0505 |
| int8-all | 294 | 1274 | 2652 | 1.9 | 35.6 | 90.7% | 8.2% | 0.964 | 17 | 1.000 | 0.0549 |
| int8-embedding | 611 | 1590 | 2974 | 2.7 | 60.4 | 95.3% | 12.0% | 0.977 | 1 | 0.068 | 0.0010 |
| int8-matmul-perchannel | 857 | 2404 | 3803 | 2.7 | 35.9 | 90.7% | 9.8% | 0.969 | 14 | 1.000 | 0.0459 |
| int8-matmul | 857 | 2399 | 3792 | 3.2 | 36.6 | 88.7% | 8.2% | 0.967 | 22 | 0.998 | 0.0633 |
