# data branch

Generated files for [MTProxy_list](https://github.com/iwizard7/MTProxy_list).
This branch is written automatically by the `Update MTProto proxy list` workflow;
do not edit it by hand.

| File | Meaning |
|---|---|
| `proxies/all.txt` | every syntactically valid link discovered in the latest run (one per `host:port`) |
| `proxies/working.txt` | links that passed the MTProto health check in the latest run |
| `proxies/stable.txt` | verified within the last 24h, most stable first |
| `proxies/best.txt` | top 20 by success rate, then median RTT |
| `proxies/endpoints.json` | per-endpoint metadata, including ads status |
| `proxies/stats.json` | statistics of the latest run |
| `proxies/badge.json` | shields.io endpoint badge payload |
| `proxies/ads.json` | promoted-channel detection results (optional) |
| `proxies/state.json` | internal state between runs (history, DNS cache) |

Public URLs (GitHub Pages): <https://iwizard7.github.io/MTProxy_list/>

Raw URLs: `https://raw.githubusercontent.com/iwizard7/MTProxy_list/data/proxies/working.txt`
