#!/usr/bin/env python3
"""Build the static GitHub Pages site from the published proxy data.

The collector writes plain files into a data directory (the ``data`` branch
worktree in CI). This module turns them into a small self-contained site:

    public/
      index.html        human-readable page: counts, files, usage, caveats
      manifest.json     sha256 + sizes of every published file (pinnable)
      .nojekyll         keep artifact deploys untouched by Jekyll
      all.txt, working.txt, stable.txt, best.txt,
      stats.json, endpoints.json, badge.json, ads.json

Only the standard library is used, and nothing is fetched at build time.

Usage:
    python -m src.publish --data-dir .data/proxies --site-dir public
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = BASE_DIR / "proxies"
DEFAULT_SITE_DIR = BASE_DIR / "public"

# Files copied verbatim into the site, in display order.
PUBLISHED_FILES = [
    ("working.txt", "text/plain", "Passed the MTProto health check in the latest run."),
    ("stable.txt", "text/plain", "Verified within the last 24 hours, most stable first."),
    ("best.txt", "text/plain", "Top endpoints by success rate, then median RTT."),
    ("all.txt", "text/plain", "Every syntactically valid link discovered (one per host:port)."),
    ("endpoints.json", "application/json", "Per-endpoint metadata, including ads status."),
    ("stats.json", "application/json", "Statistics of the latest run."),
    ("badge.json", "application/json", "shields.io endpoint badge payload."),
    ("ads.json", "application/json", "Promoted-channel detection results, when available."),
]

# Kept out of the site (internal state, large); it lives in the data branch.
INTERNAL_FILES = ["state.json"]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_lines(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def build_manifest(
    data_dir: Path,
    site_dir: Path,
    copied: list[tuple[str, str, str, int, int, str]],
    stats: dict,
    generated_at: datetime,
    commit: str | None,
    data_commit: str | None = None,
) -> dict:
    files = {}
    for name, _content_type, _description, size, lines, digest in copied:
        entry = {"bytes": size, "sha256": digest}
        if name.endswith(".txt"):
            entry["lines"] = lines
        files[name] = entry
    return {
        "generated_at": generated_at.isoformat(),
        # commit = the code revision that produced the data (GITHUB_SHA);
        # data_commit = the revision of the data branch holding these files.
        "commit": commit,
        "data_commit": data_commit,
        "source": "https://github.com/iwizard7/MTProxy_list",
        "data_branch": "data",
        "counts": {
            "discovered": stats.get("discovered"),
            "checked": stats.get("checked_candidates"),
            "verified": stats.get("mtproto_verified"),
            "stable_in_window": stats.get("stable_in_window"),
            "best": stats.get("best_published"),
            "sources_ok": stats.get("sources_ok"),
            "sources_total": stats.get("sources_total"),
            "average_rtt_ms": stats.get("average_rtt_ms"),
            "median_rtt_ms": stats.get("median_rtt_ms"),
            "updated_at": stats.get("updated_at"),
        },
        "files": files,
    }


def _fmt(value, suffix: str = "") -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.0f}{suffix}"
    return f"{value}{suffix}"


def render_index(
    stats: dict,
    table: list[tuple[str, str, int, int]],
    generated_at: datetime,
    commit: str | None,
    site_url: str,
    data_commit: str | None = None,
) -> str:
    verified = stats.get("mtproto_verified")
    stable = stats.get("stable_in_window")
    discovered = stats.get("discovered")
    updated = stats.get("updated_at") or generated_at.isoformat()
    sources_ok = stats.get("sources_ok")
    sources_total = stats.get("sources_total")

    rows = []
    for name, description, size, lines in table:
        size_text = f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} B"
        count_text = f"{lines} lines" if name.endswith(".txt") else "—"
        rows.append(
            "        <tr>"
            f'<td><a href="{html.escape(name)}">{html.escape(name)}</a></td>'
            f"<td>{html.escape(description)}</td>"
            f"<td class=\"num\">{html.escape(count_text)}</td>"
            f"<td class=\"num\">{html.escape(size_text)}</td>"
            "</tr>"
        )

    revisions = []
    if data_commit:
        revisions.append(f"data revision <code>{html.escape(data_commit[:12])}</code>")
    if commit:
        revisions.append(f"code revision <code>{html.escape(commit[:12])}</code>")
    commit_line = (
        f'<p class="meta">{" · ".join(revisions)}</p>' if revisions else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MTProto proxy list — verified Telegram proxies</title>
<meta name="description" content="Automatically refreshed list of publicly advertised Telegram MTProto proxies, verified with a real MTProto handshake.">
<style>
  :root {{ color-scheme: light dark; --fg:#111; --muted:#666; --bg:#fff; --card:#f6f7f9; --line:#e3e5e8; --accent:#0b6bcb; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --fg:#e8e8e8; --muted:#9aa0a6; --bg:#111417; --card:#1a1f24; --line:#2a3138; --accent:#6cb6ff; }} }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:2rem 1rem; background:var(--bg); color:var(--fg);
         font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  main {{ max-width: 860px; margin: 0 auto; }}
  h1 {{ font-size:1.6rem; margin:0 0 .25rem; }}
  h2 {{ font-size:1.1rem; margin:2rem 0 .5rem; }}
  p, li {{ color:var(--fg); }}
  .meta {{ color:var(--muted); font-size:.9rem; margin:.15rem 0; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:.75rem; margin:1.25rem 0; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:.85rem 1rem; }}
  .card .k {{ color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; }}
  .card .v {{ font-size:1.5rem; font-weight:600; }}
  table {{ width:100%; border-collapse:collapse; margin:.5rem 0 0; }}
  th, td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--line); font-size:.95rem; }}
  th {{ color:var(--muted); font-weight:600; font-size:.85rem; text-transform:uppercase; letter-spacing:.03em; }}
  td.num {{ text-align:right; white-space:nowrap; color:var(--muted); }}
  code, pre {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.9rem; }}
  pre {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:.8rem 1rem; overflow-x:auto; }}
  a {{ color:var(--accent); }}
  .warn {{ background:var(--card); border:1px solid var(--line); border-left:4px solid #d9822b; border-radius:10px; padding:.85rem 1rem; }}
  footer {{ margin-top:2.5rem; color:var(--muted); font-size:.85rem; border-top:1px solid var(--line); padding-top:1rem; }}
</style>
</head>
<body>
<main>
  <h1>MTProto proxy list</h1>
  <p class="meta">Publicly advertised Telegram MTProto proxies, verified with a real MTProto
     handshake (obfuscated2 + <code>req_pq_multi</code> + <code>resPQ</code>), refreshed automatically.</p>
  <p class="meta">Last run: <strong>{html.escape(str(updated))}</strong> · built {html.escape(generated_at.strftime('%Y-%m-%d %H:%M UTC'))}</p>
  {commit_line}

  <div class="cards">
    <div class="card"><div class="k">Verified now</div><div class="v">{_fmt(verified)}</div></div>
    <div class="card"><div class="k">Verified in 24h</div><div class="v">{_fmt(stable)}</div></div>
    <div class="card"><div class="k">Discovered</div><div class="v">{_fmt(discovered)}</div></div>
    <div class="card"><div class="k">Median RTT</div><div class="v">{_fmt(stats.get('median_rtt_ms'), ' ms')}</div></div>
    <div class="card"><div class="k">Sources OK</div><div class="v">{_fmt(sources_ok)}/{_fmt(sources_total)}</div></div>
  </div>

  <h2>Files</h2>
  <table>
    <thead><tr><th>File</th><th>Contents</th><th class="num">Entries</th><th class="num">Size</th></tr></thead>
    <tbody>
{chr(10).join(rows)}
    </tbody>
  </table>
  <p class="meta">A machine-readable index with sizes and sha256 hashes:
     <a href="manifest.json">manifest.json</a>.</p>

  <h2>Use it</h2>
  <pre>curl -fsSL {html.escape(site_url)}/working.txt

# Only endpoints that survived a 24h window (more stable):
curl -fsSL {html.escape(site_url)}/stable.txt</pre>
  <p>Each line is a ready to use <code>tg://proxy?server=…&amp;port=…&amp;secret=…</code> link.
     Add a proxy in Telegram via <em>Settings → Data and Storage → Proxy</em>, or tap the link.
     Prefer entries from <code>best.txt</code>/<code>stable.txt</code>: a single successful
     handshake says nothing about tomorrow.</p>

  <h2>Advertising and risks</h2>
  <div class="warn">
    <p>Some MTProto proxies are configured by their operator with a Telegram ad tag: connecting
       through them makes Telegram insert a <strong>sponsored channel</strong> into your chat list.
       That tag is server-side only and cannot be read from the link, so it is detected by querying
       Telegram through the proxy with a real user session
       (<code>help.getPromoData</code>). Results appear in <code>endpoints.json</code> under
       <code>ads.status</code> (<code>present</code>/<code>none</code>/<code>unknown</code>);
       proxies whose transport cannot be tested are reported as
       <code>unsupported_transport</code>, never as clean.</p>
  </div>
  <ul>
    <li>A green check means the proxy relayed to Telegram <em>right now</em> — it is not a security,
        privacy or trust endorsement.</li>
    <li>Public proxies are operated by third parties: they can log metadata, inject advertising and
        disappear at any time. Do not route sensitive traffic through a random proxy.</li>
    <li>The collector never scans address space: it only reads lists that others publish, refuses
        non-public addresses (loopback, RFC1918, link-local, cloud metadata) and keeps its probing
        rate deliberately low.</li>
  </ul>

  <h2>How this is built</h2>
  <ul>
    <li>Sources are explicitly configured public lists; every link is parsed, validated and
        deduplicated per <code>host:port</code>.</li>
    <li>Each candidate is checked with a real MTProto handshake, in process, 20 at a time.</li>
    <li>If discovery or verification collapses, the publish guard stops the run and the previous
        data stays in place — degraded data is never published.</li>
    <li>History (per-endpoint results, DNS cache, source contribution) lives in
        <code>state.json</code> on the <code>data</code> branch.</li>
  </ul>

  <footer>
    Source code, methodology and the full change log:
    <a href="https://github.com/iwizard7/MTProxy_list">github.com/iwizard7/MTProxy_list</a>.<br>
    Data branch: <a href="https://github.com/iwizard7/MTProxy_list/tree/data">data</a> ·
    raw: <code>{html.escape(site_url)}/&lt;file&gt;</code>
  </footer>
</main>
</body>
</html>
"""


def build_site(
    data_dir: Path = DEFAULT_DATA_DIR,
    site_dir: Path = DEFAULT_SITE_DIR,
    site_url: str = "https://iwizard7.github.io/MTProxy_list",
    commit: str | None = None,
    data_commit: str | None = None,
    generated_at: datetime | None = None,
) -> dict:
    """Copy the published data into ``site_dir`` and write index + manifest."""
    generated_at = generated_at or datetime.now(timezone.utc)
    commit = commit or os.environ.get("GITHUB_SHA") or None
    data_commit = data_commit or os.environ.get("DATA_COMMIT") or None

    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / ".nojekyll").write_text("", encoding="utf-8")

    table: list[tuple[str, str, int, int]] = []
    copied: list[tuple[str, str, str, int, int, str]] = []

    for name, content_type, description in PUBLISHED_FILES:
        source = data_dir / name
        if not source.is_file():
            continue
        shutil.copyfile(source, site_dir / name)
        size = source.stat().st_size
        lines = count_lines(source) if name.endswith(".txt") else 0
        table.append((name, description, size, lines))
        copied.append((name, content_type, description, size, lines, sha256_of(source)))

    stats = load_json(data_dir / "stats.json", {})
    if not isinstance(stats, dict):
        stats = {}

    (site_dir / "index.html").write_text(
        render_index(
            stats, table, generated_at, commit, site_url.rstrip("/"), data_commit
        ),
        encoding="utf-8",
    )

    manifest = build_manifest(
        data_dir, site_dir, copied, stats, generated_at, commit, data_commit
    )
    (site_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("DATA_DIR", str(DEFAULT_DATA_DIR)),
        help="directory with the published files (default: DATA_DIR or ./proxies)",
    )
    parser.add_argument(
        "--site-dir",
        default=str(DEFAULT_SITE_DIR),
        help="output directory for the site (default: ./public)",
    )
    parser.add_argument(
        "--site-url",
        default=os.environ.get("SITE_URL", "https://iwizard7.github.io/MTProxy_list"),
        help="public base URL used in the generated page",
    )
    parser.add_argument(
        "--data-commit",
        default=os.environ.get("DATA_COMMIT"),
        help="revision of the data branch holding these files (default: DATA_COMMIT)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    data_dir = Path(args.data_dir)
    site_dir = Path(args.site_dir)

    if not data_dir.is_dir():
        print(f"Data directory not found: {data_dir}", file=sys.stderr)
        return 3

    manifest = build_site(
        data_dir, site_dir, site_url=args.site_url, data_commit=args.data_commit
    )
    files = ", ".join(manifest["files"]) or "(no data files found)"
    print(f"Site written to {site_dir}: index.html, manifest.json, {files}")
    counts = manifest["counts"]
    print(
        f"Counts: verified={counts['verified']} stable={counts['stable_in_window']} "
        f"discovered={counts['discovered']}"
    )
    if manifest.get("data_commit"):
        print(f"Data revision: {manifest['data_commit'][:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
