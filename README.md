[![Update MTProto proxy list](https://github.com/iwizard7/MTProxy_list/actions/workflows/update.yml/badge.svg)](https://github.com/iwizard7/MTProxy_list/actions/workflows/update.yml)
![verified proxies](https://img.shields.io/endpoint?url=https%3A%2F%2Fiwizard7.github.io%2FMTProxy_list%2Fbadge.json)
# Mtproxy_list

Automatically refreshed list of publicly advertised Telegram MTProto proxy links.
Every published link is checked with a real MTProto relay health check
(obfuscated2 handshake + `req_pq_multi` + `resPQ` validation), not just a TCP
connect.

## Where the data lives

`main` contains **code only**. Generated data is committed to the
[`data` branch](https://github.com/iwizard7/MTProxy_list/tree/data) and served
from **GitHub Pages** (a stable, CDN-backed URL):

| File | Contents |
|---|---|
| [`working.txt`](https://iwizard7.github.io/MTProxy_list/working.txt) | links that passed the health check in the **latest run**. |
| [`stable.txt`](https://iwizard7.github.io/MTProxy_list/stable.txt) | links verified within the last 24 hours, most stable first. |
| [`best.txt`](https://iwizard7.github.io/MTProxy_list/best.txt) | top 20 endpoints by stability (success rate, then median RTT). |
| [`all.txt`](https://iwizard7.github.io/MTProxy_list/all.txt) | every syntactically valid, deduplicated link discovered (one per `host:port`). |
| [`endpoints.json`](https://iwizard7.github.io/MTProxy_list/endpoints.json) | per-endpoint metadata: verification, `rtt_ms`, `check_ms`, `median_rtt_ms`, `success_rate`, `rtt_trend`, engine, last error, ads status, upstream metadata. |
| [`stats.json`](https://iwizard7.github.io/MTProxy_list/stats.json) | run statistics: source health, rejected links, publish guard, DNS cache, thresholds. |
| [`badge.json`](https://iwizard7.github.io/MTProxy_list/badge.json) | [shields.io endpoint badge](https://shields.io/badges/endpoint-badge) with the current verified count (rendered above). |
| [`manifest.json`](https://iwizard7.github.io/MTProxy_list/manifest.json) | machine-readable index: sizes, line counts, sha256 of every published file, plus the code and data revisions that produced them. |
| [`ads.json`](https://iwizard7.github.io/MTProxy_list/ads.json) | optional promoted-channel results produced by `src/adcheck.py`. |
| [`index.html`](https://iwizard7.github.io/MTProxy_list/) | human-readable page with counts, usage and caveats. |

Raw URLs through the data branch work as well, e.g.
`https://raw.githubusercontent.com/iwizard7/MTProxy_list/data/working.txt`.
`state.json` (internal history: per-endpoint results, DNS cache, source
contribution) also lives in that branch and is deliberately not published on the
site.

> **Deprecated:** the old `https://raw.githubusercontent.com/iwizard7/MTProxy_list/main/proxies/…`
> URLs are no longer updated — the files moved to the data branch. Nothing else
> breaks: file names and formats are unchanged.

Schemas for every JSON file live in [`docs/schema/`](docs/schema) and are
enforced by the test suite, so published fields cannot be renamed silently.

**Important:** a successful handshake proves that the proxy currently relays to
Telegram — it does **not** vouch for the operator. Public proxies are run by
third parties: they see your connection metadata, can log which Telegram
endpoints you reach, may inject a sponsored channel (see
[Advertising](#advertising-promoted-channels)) and can disappear at any moment.
Do not treat them as trusted infrastructure, and do not route sensitive traffic
through a random proxy from any public list.

## Automation

GitHub Actions runs every 2 hours at minute 17 (`cron: "17 */2 * * *"`) and can
also be started manually from **Actions → Update MTProto proxy list → Run
workflow**.

The collector only extracts explicitly published proxy links from its configured
sources. It never scans arbitrary IP ranges or ports, and it refuses to connect
to non-public addresses (loopback, RFC1918, link-local, cloud metadata),
including host names that resolve to them. DNS answers — including negative ones
— are cached for a few hours to keep runs cheap.

**Publish guard:** if discovery or verification collapses (all sources dead, no
verified proxy, or a drop below 25% of the previous run), the run fails with
exit code `2` and the previously published lists are kept untouched. Nothing
degraded is ever committed.

## Configuration

Everything is environment-driven (see `src/collector.py::Config.from_env`):

| Variable | Default | Meaning |
|---|---|---|
| `PROXY_SOURCES` | built-in list | comma-separated list-source URLs |
| `PROXY_METADATA_SOURCES` | *(disabled)* | comma-separated JSON metadata sources (annotate only, never add proxies) |
| `MAX_CANDIDATES` | `400` | max endpoints to check per run (`0` = unlimited) |
| `MAX_WORKERS` | `20` | parallel checks |
| `CHECK_TIMEOUT` | `3` | connect/response timeout in seconds |
| `CHECK_DCS` | *(unset)* | Telegram DC ids to require, e.g. `2` or `2,4` |
| `MIN_DISCOVERED` | `10` | publish guard floor |
| `MIN_KEEP_RATIO` | `0.25` | publish guard: allowed drop vs the previous run |
| `STABLE_TTL_HOURS` | `24` | window used for `stable.txt` |
| `BEST_COUNT` | `20` | size of `best.txt` |
| `RTT_HISTORY` | `10` | RTT samples / results kept per endpoint |
| `KNOWN_GOOD_HOURS` | `6` | recently working endpoints get priority when capping |
| `DNS_CACHE_HOURS` | `6` | how long DNS answers (positive and negative) are reused |
| `GUARD_DNS` | `1` | resolve hosts and reject non-public addresses |
| `CHECK_ENGINE` | `auto` | `library` (in-process) or `cli` (subprocess) |
| `ALLOW_DEGRADED` | `0` | publish even when the guard trips (manual bootstrap) |
| `DATA_DIR` | `./proxies` | where generated files are read/written (CI: the data worktree) |

Useful local commands:

```bash
python3 -m unittest discover -s tests -v            # 127 unit tests, stdlib only
python3 src/collector.py --dry-run                  # parse sources, write nothing
python3 src/collector.py --limit 20                 # small live run into ./proxies
python3 src/collector.py --dcs 2,4                  # require specific Telegram DCs
python3 -m src.publish --data-dir proxies --site-dir public   # build the site
```

## GitHub Pages setup (once)

The workflow deploys the site with `actions/deploy-pages`, which needs Pages to
be available for the repository:

1. **Settings → Pages → Build and deployment → Source: GitHub Actions** (no
   branch or folder to pick — the workflow uploads the artifact).
2. Save. The first run creates the `github-pages` environment and publishes
   `https://iwizard7.github.io/MTProxy_list/`.

The workflow also passes `enablement: true` to `actions/configure-pages`, so a
missing Pages site is created automatically where the token allows it. If the
deploy step fails with *"Get Pages site failed"*, the data branch still updates —
only the site lags until step 1 is done.

The site is rebuilt on every run (including when the data itself did not change),
so `index.html`, `manifest.json` and the `generated_at`/commit fields stay fresh.
Pages serves through a CDN with roughly 10 minutes of caching; the shields.io
badge uses `cacheSeconds` for the same reason.

## Advertising (promoted channels)

Some MTProto proxies are configured by their operator with a Telegram ad tag:
when you connect through them, Telegram inserts a sponsored channel into your
chat list and pays the proxy operator. That tag is **server-side only** — it is
not part of the `tg://proxy?...` link, so it cannot be read from the list.

Detecting it therefore requires a real Telegram **user session** connected
*through* the proxy, followed by a `help.getPromoData` call: the response has a
`proxy` flag and a `peer` field naming the promoted channel. `src/adcheck.py`
does exactly this (optional, opt-in, needs your own API ID/hash and session) and
writes `ads.json` to the data branch, which the collector merges into
`endpoints.json` as `ads.status` = `present` / `none` / `unknown`.

Run it locally (`python3 src/adcheck.py --limit 20`) or manually from
**Actions → Check proxies for injected ads**, which requires the repository
secrets `TELEGRAM_API_ID`, `TELEGRAM_API_HASH` and `TELEGRAM_SESSION`. The
workflow has no schedule on purpose, and it is **not** used by the collector.

Caveats: Telethon cannot speak FakeTLS, so `ee`-prefixed proxies are reported as
`unsupported_transport` instead of "clean" (~28% of the current pool); results
depend on the account's country; use a dedicated account, never your main one.
See `FIXES.md` for the mechanics, the evidence and the risks before enabling it.

## Ethics and legal notes

* The lists are **aggregations of links that third parties already publish
  publicly**. The collector does not discover private endpoints and does not
  scan address space; the source inventory with licences is in `FIXES.md`.
* Publishing a proxy link is publishing somebody else's endpoint address. If a
  proxy operator asks to be removed, remove the endpoint — please open an issue
  instead of assuming consent.
* Health checks create real connections to third-party hosts. They are
  deliberately limited (one handshake per endpoint per run, a bounded candidate
  cap, a `User-Agent` identifying this project) — do not raise the limits
  carelessly, and never point the collector at hosts you were not invited to
  check.
* A green check means "this relay answered correctly right now". It is **not** a
  security, privacy or legality endorsement.
* Some jurisdictions restrict circumvention tools. You are responsible for how
  you use this data.

## Setup

1. Push this project to your repository's default branch (`main`).
2. In GitHub, open **Settings → Actions → General** and allow workflows to run.
   The workflow needs `contents: write` (to push the `data` branch) and Pages
   permissions, which are declared in the workflow file itself.
3. Enable Pages once: **Settings → Pages → Source: GitHub Actions** (see
   [GitHub Pages setup](#github-pages-setup-once)).
4. Open **Actions** and run **Update MTProto proxy list** once manually. The
   first run creates the `data` branch automatically if it does not exist.
5. Inspect the workflow log, the `data` branch and the published site.

## Scope and limitations

The source set is intentionally small and should be expanded only with reviewed
public sources. A health check is a screening step for availability, not a
security audit: it says nothing about who operates the proxy, what it logs, or
whether it injects advertising. Avoid adding sources that publish private
credentials or endpoints without authorization.
