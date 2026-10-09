# Data has moved

The generated proxy lists are no longer committed to `main`. They live in the
[`data` branch](https://github.com/iwizard7/MTProxy_list/tree/data) and are
served from GitHub Pages:

| File | URL |
|---|---|
| verified in the latest run | https://iwizard7.github.io/MTProxy_list/working.txt |
| verified within 24h | https://iwizard7.github.io/MTProxy_list/stable.txt |
| top 20 by stability | https://iwizard7.github.io/MTProxy_list/best.txt |
| all discovered links | https://iwizard7.github.io/MTProxy_list/all.txt |
| per-endpoint metadata | https://iwizard7.github.io/MTProxy_list/endpoints.json |
| run statistics | https://iwizard7.github.io/MTProxy_list/stats.json |
| machine-readable index (sha256) | https://iwizard7.github.io/MTProxy_list/manifest.json |

Raw URLs keep working through the data branch, e.g.
`https://raw.githubusercontent.com/iwizard7/MTProxy_list/data/working.txt`.

This directory is now used only for local runs (`python3 src/collector.py`
writes here) and is git-ignored apart from this note.
