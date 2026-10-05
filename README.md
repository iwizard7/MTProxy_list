[![Update MTProto proxy list](https://github.com/iwizard7/MTProxy_list/actions/workflows/update.yml/badge.svg)](https://github.com/iwizard7/MTProxy_list/actions/workflows/update.yml)
# Mtproxy_list

Automatically refreshed list of publicly advertised Telegram MTProto proxy links.

## Files
- `proxies/working.txt` — discovered links whose advertised endpoint accepted a TCP connection during the latest run.
- `proxies/all.txt` — syntactically valid links discovered from configured public sources.
- `proxies/stats.json` — timestamp and run counts.

**Important:** a reachable TCP port does not prove that Telegram authentication or an MTProto session works. Public proxies are operated by third parties; use caution and do not treat them as trusted infrastructure.

## Automation
GitHub Actions runs at minutes 17 and 47 of each hour, and can also be started manually from **Actions → Update MTProto proxy list → Run workflow**.

The collector only extracts explicitly published proxy links from its configured sources. It does not scan arbitrary IP ranges or ports. Source URLs and limits are configured in `src/collector.py`.

## Setup
1. Push this project to your repository's default branch.
2. In GitHub, open **Settings → Actions → General** and allow workflows to run. The workflow needs repository `contents: write` permission to commit updated lists.
3. Open **Actions** and run **Update MTProto proxy list** once manually.
4. Inspect the workflow log and resulting files.

An optional `GITHUB_TOKEN` environment variable enables additional public repository discovery through GitHub's repository search API. The built-in `GITHUB_TOKEN` can be passed by adding `env: GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}` to the workflow step if desired; repository search API access and rate limits may vary.

## Scope and limitations
The initial source set is intentionally small and can be expanded with reviewed public sources. TCP reachability is a lightweight screening step, not a full Telegram protocol test. Avoid adding sources that publish private credentials or endpoints without authorization.
