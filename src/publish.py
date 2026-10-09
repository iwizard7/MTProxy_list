#!/usr/bin/env python3
"""Build the static GitHub Pages site from the published proxy data.

The collector writes plain files into a data directory (the ``data`` branch
worktree in CI). This module turns them into a small self-contained site:

    public/
      index.html        English page: counts, files, usage, caveats
      ru.html           same page in Russian (with a language switcher)
      manifest.json     sha256 + sizes of every published file (pinnable)
      .nojekyll         keep artifact deploys untouched by Jekyll
      all.txt, working.txt, stable.txt, best.txt,
      stats.json, endpoints.json, badge.json, ads.json

Both pages are rendered from one set of templates, carry ``hreflang``
alternates and a visible language switcher, and work without JavaScript.

Only the standard library is used, and nothing is fetched at build time.

Usage:
    python -m src.publish --data-dir .data/proxies --site-dir public
    python -m src.publish --languages en      # English page only
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

# Language code -> file name. The English page keeps the root URL, so existing
# links to "/" keep working.
LANGUAGES: tuple[str, ...] = ("en", "ru")
PAGE_FILES: dict[str, str] = {"en": "index.html", "ru": "ru.html"}
SITE_REPO = "https://github.com/iwizard7/MTProxy_list"

# Files copied verbatim into the site, in display order.
# Each description is per language; the file names themselves are language-neutral.
PUBLISHED_FILES: list[tuple[str, dict[str, str]]] = [
    (
        "working.txt",
        {
            "en": "Passed the MTProto health check in the latest run.",
            "ru": "Прошли проверку MTProto в последнем прогоне.",
        },
    ),
    (
        "stable.txt",
        {
            "en": "Verified within the last 24 hours, most stable first.",
            "ru": "Проверены за последние 24 часа, сначала самые стабильные.",
        },
    ),
    (
        "best.txt",
        {
            "en": "Top endpoints by success rate, then median RTT.",
            "ru": "Лучшие по доле успешных проверок, затем по медианному RTT.",
        },
    ),
    (
        "all.txt",
        {
            "en": "Every syntactically valid link discovered (one per host:port).",
            "ru": "Все синтаксически корректные ссылки (по одной на host:port).",
        },
    ),
    (
        "endpoints.json",
        {
            "en": "Per-endpoint metadata, including ads status.",
            "ru": "Метаданные по каждому эндпоинту, включая статус рекламы.",
        },
    ),
    (
        "stats.json",
        {
            "en": "Statistics of the latest run.",
            "ru": "Статистика последнего прогона.",
        },
    ),
    (
        "badge.json",
        {
            "en": "shields.io endpoint badge payload.",
            "ru": "Данные бейджа shields.io.",
        },
    ),
    (
        "ads.json",
        {
            "en": "Promoted-channel detection results, when available.",
            "ru": "Результаты проверки на встроенную рекламу, если она выполнялась.",
        },
    ),
]

# Kept out of the site (internal state, large); it lives in the data branch.
INTERNAL_FILES = ["state.json"]

STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "title": "MTProto proxy list — verified Telegram proxies",
        "description": (
            "Automatically refreshed list of publicly advertised Telegram MTProto "
            "proxies, verified with a real MTProto handshake."
        ),
        "switch_aria": "Page language",
        "h1": "MTProto proxy list",
        "subtitle": (
            "Publicly advertised Telegram MTProto proxies, verified with a real MTProto "
            "handshake (obfuscated2 + <code>req_pq_multi</code> + <code>resPQ</code>), "
            "refreshed automatically."
        ),
        "last_run": "Last run: <strong>{updated}</strong> · page built {built}",
        "data_revision": "data revision <code>{sha}</code>",
        "code_revision": "code revision <code>{sha}</code>",
        "card_verified_now": "Verified now",
        "card_verified_24h": "Verified in 24h",
        "card_discovered": "Discovered",
        "card_median_rtt": "Median RTT",
        "card_sources": "Sources OK",
        "files_heading": "Files",
        "th_file": "File",
        "th_contents": "Contents",
        "th_entries": "Entries",
        "th_size": "Size",
        "manifest_note": (
            'A machine-readable index with sizes and sha256 hashes: '
            '<a href="manifest.json">manifest.json</a>.'
        ),
        "use_heading": "Use it",
        "use_comment": "# Only endpoints that survived a 24h window (more stable):",
        "use_text": (
            "Each line is a ready to use "
            "<code>tg://proxy?server=…&amp;port=…&amp;secret=…</code> link. Add a proxy in "
            "Telegram via <em>Settings → Data and Storage → Proxy</em>, or tap the link. "
            "Prefer entries from <code>best.txt</code>/<code>stable.txt</code>: a single "
            "successful handshake says nothing about tomorrow."
        ),
        "ads_heading": "Advertising and risks",
        "ads_warn": (
            "Some MTProto proxies are configured by their operator with a Telegram ad tag: "
            "connecting through them makes Telegram insert a <strong>sponsored channel</strong> "
            "into your chat list. That tag is server-side only and cannot be read from the link, "
            "so it is detected by querying Telegram through the proxy with a real user session "
            "(<code>help.getPromoData</code>). Results appear in <code>endpoints.json</code> "
            "under <code>ads.status</code> (<code>present</code>/<code>none</code>/"
            "<code>unknown</code>); proxies whose transport cannot be tested are reported as "
            "<code>unsupported_transport</code>, never as clean."
        ),
        "ads_li_1": (
            "A green check means the proxy relayed to Telegram <em>right now</em> — it is not a "
            "security, privacy or trust endorsement."
        ),
        "ads_li_2": (
            "Public proxies are operated by third parties: they can log metadata, inject "
            "advertising and disappear at any time. Do not route sensitive traffic through a "
            "random proxy."
        ),
        "ads_li_3": (
            "The collector never scans address space: it only reads lists that others publish, "
            "refuses non-public addresses (loopback, RFC1918, link-local, cloud metadata) and "
            "keeps its probing rate deliberately low."
        ),
        "build_heading": "How this is built",
        "build_li_1": (
            "Sources are explicitly configured public lists; every link is parsed, validated and "
            "deduplicated per <code>host:port</code>."
        ),
        "build_li_2": (
            "Each candidate is checked with a real MTProto handshake, in process, 20 at a time."
        ),
        "build_li_3": (
            "If discovery or verification collapses, the publish guard stops the run and the "
            "previous data stays in place — degraded data is never published."
        ),
        "build_li_4": (
            "History (per-endpoint results, DNS cache, source contribution) lives in "
            "<code>state.json</code> on the <code>data</code> branch."
        ),
        "footer_source": (
            'Source code, methodology and the full change log: '
            f'<a href="{SITE_REPO}">{SITE_REPO.replace("https://", "")}</a>.'
        ),
        "footer_data": (
            'Data branch: <a href="{repo}/tree/data">data</a> · raw: '
            "<code>{site_url}/&lt;file&gt;</code>"
        ),
    },
    "ru": {
        "title": "Список MTProto-прокси — проверенные прокси Telegram",
        "description": (
            "Автоматически обновляемый список публично опубликованных MTProto-прокси "
            "Telegram с реальной проверкой MTProto-хендшейка."
        ),
        "switch_aria": "Язык страницы",
        "h1": "Список MTProto-прокси",
        "subtitle": (
            "Публично опубликованные MTProto-прокси Telegram, проверенные настоящим "
            "MTProto-хендшейком (obfuscated2 + <code>req_pq_multi</code> + <code>resPQ</code>), "
            "обновляются автоматически."
        ),
        "last_run": "Последний прогон: <strong>{updated}</strong> · страница собрана {built}",
        "data_revision": "ревизия данных <code>{sha}</code>",
        "code_revision": "ревизия кода <code>{sha}</code>",
        "card_verified_now": "Проверено сейчас",
        "card_verified_24h": "Проверено за 24 ч",
        "card_discovered": "Найдено",
        "card_median_rtt": "Медианный RTT",
        "card_sources": "Источники",
        "files_heading": "Файлы",
        "th_file": "Файл",
        "th_contents": "Содержимое",
        "th_entries": "Записей",
        "th_size": "Размер",
        "lines": "{n} строк",
        "manifest_note": (
            "Машиночитаемый индекс с размерами и хешами sha256: "
            '<a href="manifest.json">manifest.json</a>.'
        ),
        "use_heading": "Как использовать",
        "use_comment": "# Только эндпоинты, пережившие окно в 24 часа (стабильнее):",
        "use_text": (
            "Каждая строка — готовая ссылка "
            "<code>tg://proxy?server=…&amp;port=…&amp;secret=…</code>. Добавить прокси в "
            "Telegram можно через <em>Настройки → Данные и память → Прокси</em> или просто "
            "нажав на ссылку. Предпочитайте <code>best.txt</code>/<code>stable.txt</code>: одна "
            "успешная проверка ничего не говорит о завтрашнем дне."
        ),
        "ads_heading": "Реклама и риски",
        "ads_warn": (
            "Некоторые MTProto-прокси настроены их оператором с рекламным тегом Telegram: при "
            "подключении через них Telegram добавляет <strong>спонсорский канал</strong> в список "
            "ваших чатов. Тег живёт только на сервере, в ссылке его нет, поэтому он определяется "
            "запросом к Telegram через прокси с реальной пользовательской сессией "
            "(<code>help.getPromoData</code>). Результаты видны в <code>endpoints.json</code> в "
            "<code>ads.status</code> (<code>present</code>/<code>none</code>/"
            "<code>unknown</code>); прокси, транспорт которых проверить нельзя, помечаются "
            "<code>unsupported_transport</code>, а не «чистыми»."
        ),
        "ads_li_1": (
            "Зелёная галочка означает, что прокси <em>прямо сейчас</em> передал запрос в "
            "Telegram — это не гарантия безопасности, приватности или доверия."
        ),
        "ads_li_2": (
            "Публичные прокси управляются третьими лицами: они могут логировать метаданные, "
            "подмешивать рекламу и исчезнуть в любой момент. Не направляйте через случайный "
            "прокси чувствительный трафик."
        ),
        "ads_li_3": (
            "Коллектор не сканирует адресное пространство: он читает только те списки, которые "
            "публикуют другие, отказывается подключаться к непубличным адресам (loopback, "
            "RFC1918, link-local, метаданные облака) и намеренно держит низкий темп проверок."
        ),
        "build_heading": "Как это устроено",
        "build_li_1": (
            "Источники — явно заданные публичные списки; каждая ссылка разбирается, валидируется "
            "и дедуплицируется по <code>host:port</code>."
        ),
        "build_li_2": (
            "Каждый кандидат проверяется настоящим MTProto-хендшейком, в одном процессе, "
            "по 20 параллельно."
        ),
        "build_li_3": (
            "Если находка или проверка деградировала, publish guard останавливает прогон, и "
            "предыдущие данные остаются на месте — испорченные данные не публикуются."
        ),
        "build_li_4": (
            "История (результаты по эндпоинтам, DNS-кэш, вклад источников) лежит в "
            "<code>state.json</code> в ветке <code>data</code>."
        ),
        "footer_source": (
            "Исходный код, методология и полный список изменений: "
            f'<a href="{SITE_REPO}">{SITE_REPO.replace("https://", "")}</a>.'
        ),
        "footer_data": (
            'Ветка с данными: <a href="{repo}/tree/data">data</a> · raw: '
            "<code>{site_url}/&lt;файл&gt;</code>"
        ),
    },
}

STYLE = """
  :root { color-scheme: light dark; --fg:#111; --muted:#666; --bg:#fff; --card:#f6f7f9; --line:#e3e5e8; --accent:#0b6bcb; }
  @media (prefers-color-scheme: dark) { :root { --fg:#e8e8e8; --muted:#9aa0a6; --bg:#111417; --card:#1a1f24; --line:#2a3138; --accent:#6cb6ff; } }
  * { box-sizing: border-box; }
  body { margin:0; padding:2rem 1rem; background:var(--bg); color:var(--fg);
         font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  main { max-width: 860px; margin: 0 auto; }
  h1 { font-size:1.6rem; margin:0 0 .25rem; }
  h2 { font-size:1.1rem; margin:2rem 0 .5rem; }
  p, li { color:var(--fg); }
  .meta { color:var(--muted); font-size:.9rem; margin:.15rem 0; }
  .lang { float:right; font-size:.85rem; color:var(--muted); }
  .lang a, .lang strong { margin-left:.4rem; }
  .lang strong { color:var(--fg); }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:.75rem; margin:1.25rem 0; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:.85rem 1rem; }
  .card .k { color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; }
  .card .v { font-size:1.5rem; font-weight:600; }
  table { width:100%; border-collapse:collapse; margin:.5rem 0 0; }
  th, td { text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--line); font-size:.95rem; }
  th { color:var(--muted); font-weight:600; font-size:.85rem; text-transform:uppercase; letter-spacing:.03em; }
  td.num { text-align:right; white-space:nowrap; color:var(--muted); }
  code, pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.9rem; }
  pre { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:.8rem 1rem; overflow-x:auto; }
  a { color:var(--accent); }
  .warn { background:var(--card); border:1px solid var(--line); border-left:4px solid #d9822b; border-radius:10px; padding:.85rem 1rem; }
  footer { margin-top:2.5rem; color:var(--muted); font-size:.85rem; border-top:1px solid var(--line); padding-top:1rem; }
"""


def plural_ru(number: int, one: str = "строка", few: str = "строки", many: str = "строк") -> str:
    """Pick the Russian plural form for ``number``."""
    last_two = number % 100
    last = number % 10
    if last == 1 and last_two != 11:
        return one
    if 2 <= last <= 4 and not 12 <= last_two <= 14:
        return few
    return many


def localize_lines(lang: str, count: int) -> str:
    """``1 line`` / ``18 lines`` / ``21 строка`` (with correct plural forms)."""
    if lang == "ru":
        return f"{count} {plural_ru(count)}"
    return f"{count} line" if count == 1 else f"{count} lines"


def localize_size(lang: str, size: int) -> str:
    """``1.4 KB`` / ``1,4 КБ`` — localized units and decimal separator."""
    if size >= 1024:
        value = f"{size / 1024:.1f}"
        return f"{value.replace('.', ',')} КБ" if lang == "ru" else f"{value} KB"
    return f"{size} Б" if lang == "ru" else f"{size} B"


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
    copied: list[tuple[str, int, int, str]],
    stats: dict,
    generated_at: datetime,
    commit: str | None,
    data_commit: str | None = None,
    languages: tuple[str, ...] = LANGUAGES,
) -> dict:
    files = {}
    for name, size, lines, digest in copied:
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
        "source": SITE_REPO,
        "data_branch": "data",
        "languages": list(languages),
        "pages": {lang: PAGE_FILES[lang] for lang in languages if lang in PAGE_FILES},
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


def render_language_switcher(lang: str, languages: tuple[str, ...]) -> str:
    """``EN | RU`` with the current language highlighted and not a link."""
    parts = []
    for code in languages:
        label = code.upper()
        if code == lang:
            parts.append(f'<strong aria-current="page">{label}</strong>')
        else:
            parts.append(f'<a href="{html.escape(PAGE_FILES[code])}" hreflang="{code}">{label}</a>')
    return " · ".join(parts)


def render_hreflangs(site_url: str, languages: tuple[str, ...]) -> str:
    lines = [
        f'<link rel="alternate" hreflang="{code}" href="{html.escape(site_url)}/{html.escape(PAGE_FILES[code])}">'
        for code in languages
    ]
    lines.append(
        f'<link rel="alternate" hreflang="x-default" href="{html.escape(site_url)}/{html.escape(PAGE_FILES["en"])}">'
    )
    return "\n".join(lines)


def render_page(
    lang: str,
    stats: dict,
    table: list[tuple[str, int, int]],
    generated_at: datetime,
    commit: str | None,
    site_url: str,
    data_commit: str | None = None,
    languages: tuple[str, ...] = LANGUAGES,
) -> str:
    """Render one language of the landing page."""
    t = STRINGS[lang]
    site_url = site_url.rstrip("/")

    verified = stats.get("mtproto_verified")
    stable = stats.get("stable_in_window")
    discovered = stats.get("discovered")
    updated = stats.get("updated_at") or generated_at.isoformat()
    sources_ok = stats.get("sources_ok")
    sources_total = stats.get("sources_total")

    rows = []
    for name, size, lines in table:
        size_text = localize_size(lang, size)
        count_text = localize_lines(lang, lines) if name.endswith(".txt") else "—"
        description = next(
            (per_lang.get(lang, "") for file_name, per_lang in PUBLISHED_FILES if file_name == name),
            "",
        )
        rows.append(
            "        <tr>"
            f'<td><a href="{html.escape(name)}">{html.escape(name)}</a></td>'
            f"<td>{html.escape(description)}</td>"
            f'<td class="num">{html.escape(count_text)}</td>'
            f'<td class="num">{html.escape(size_text)}</td>'
            "</tr>"
        )

    revisions = []
    if data_commit:
        revisions.append(t["data_revision"].format(sha=html.escape(data_commit[:12])))
    if commit:
        revisions.append(t["code_revision"].format(sha=html.escape(commit[:12])))
    revisions_line = f'<p class="meta">{" · ".join(revisions)}</p>' if revisions else ""

    title = html.escape(t["title"])
    description = html.escape(t["description"])
    built = html.escape(generated_at.strftime("%Y-%m-%d %H:%M UTC"))
    switcher = render_language_switcher(lang, languages)
    hreflangs = render_hreflangs(site_url, languages)
    footer_data = t["footer_data"].format(repo=SITE_REPO, site_url=html.escape(site_url))

    return f"""<!DOCTYPE html>
<html lang="{html.escape(lang)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
{hreflangs}
<style>{STYLE}</style>
</head>
<body>
<main>
  <nav class="lang" aria-label="{html.escape(t['switch_aria'])}">{switcher}</nav>
  <h1>{html.escape(t['h1'])}</h1>
  <p class="meta">{t['subtitle']}</p>
  <p class="meta">{t['last_run'].format(updated=html.escape(str(updated)), built=built)}</p>
  {revisions_line}

  <div class="cards">
    <div class="card"><div class="k">{html.escape(t['card_verified_now'])}</div><div class="v">{_fmt(verified)}</div></div>
    <div class="card"><div class="k">{html.escape(t['card_verified_24h'])}</div><div class="v">{_fmt(stable)}</div></div>
    <div class="card"><div class="k">{html.escape(t['card_discovered'])}</div><div class="v">{_fmt(discovered)}</div></div>
    <div class="card"><div class="k">{html.escape(t['card_median_rtt'])}</div><div class="v">{_fmt(stats.get('median_rtt_ms'), ' ms')}</div></div>
    <div class="card"><div class="k">{html.escape(t['card_sources'])}</div><div class="v">{_fmt(sources_ok)}/{_fmt(sources_total)}</div></div>
  </div>

  <h2>{html.escape(t['files_heading'])}</h2>
  <table>
    <thead><tr><th>{html.escape(t['th_file'])}</th><th>{html.escape(t['th_contents'])}</th><th class="num">{html.escape(t['th_entries'])}</th><th class="num">{html.escape(t['th_size'])}</th></tr></thead>
    <tbody>
{chr(10).join(rows)}
    </tbody>
  </table>
  <p class="meta">{t['manifest_note']}</p>

  <h2>{html.escape(t['use_heading'])}</h2>
  <pre>curl -fsSL {html.escape(site_url)}/working.txt

{t['use_comment']}
curl -fsSL {html.escape(site_url)}/stable.txt</pre>
  <p>{t['use_text']}</p>

  <h2>{html.escape(t['ads_heading'])}</h2>
  <div class="warn">
    <p>{t['ads_warn']}</p>
  </div>
  <ul>
    <li>{t['ads_li_1']}</li>
    <li>{t['ads_li_2']}</li>
    <li>{t['ads_li_3']}</li>
  </ul>

  <h2>{html.escape(t['build_heading'])}</h2>
  <ul>
    <li>{t['build_li_1']}</li>
    <li>{t['build_li_2']}</li>
    <li>{t['build_li_3']}</li>
    <li>{t['build_li_4']}</li>
  </ul>

  <footer>
    {t['footer_source']}<br>
    {footer_data}
  </footer>
</main>
</body>
</html>
"""


def normalize_languages(raw) -> tuple[str, ...]:
    """Parse ``en,ru`` / ``["en"]`` into a supported, ordered language tuple."""
    if isinstance(raw, str):
        candidates = [part.strip().lower() for part in raw.split(",")]
    else:
        candidates = [str(part).strip().lower() for part in (raw or [])]
    selected = [code for code in LANGUAGES if code in candidates]
    return tuple(selected) or ("en",)


def build_site(
    data_dir: Path = DEFAULT_DATA_DIR,
    site_dir: Path = DEFAULT_SITE_DIR,
    site_url: str = "https://iwizard7.github.io/MTProxy_list",
    commit: str | None = None,
    data_commit: str | None = None,
    generated_at: datetime | None = None,
    languages: tuple[str, ...] | str = LANGUAGES,
) -> dict:
    """Copy the published data into ``site_dir`` and write the pages + manifest."""
    generated_at = generated_at or datetime.now(timezone.utc)
    commit = commit or os.environ.get("GITHUB_SHA") or None
    data_commit = data_commit or os.environ.get("DATA_COMMIT") or None
    languages = normalize_languages(languages)

    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / ".nojekyll").write_text("", encoding="utf-8")

    table: list[tuple[str, int, int]] = []
    copied: list[tuple[str, int, int, str]] = []

    for name, _descriptions in PUBLISHED_FILES:
        source = data_dir / name
        if not source.is_file():
            continue
        shutil.copyfile(source, site_dir / name)
        size = source.stat().st_size
        lines = count_lines(source) if name.endswith(".txt") else 0
        table.append((name, size, lines))
        copied.append((name, size, lines, sha256_of(source)))

    stats = load_json(data_dir / "stats.json", {})
    if not isinstance(stats, dict):
        stats = {}

    for lang in languages:
        (site_dir / PAGE_FILES[lang]).write_text(
            render_page(
                lang,
                stats,
                table,
                generated_at,
                commit,
                site_url,
                data_commit,
                languages,
            ),
            encoding="utf-8",
        )

    manifest = build_manifest(
        copied, stats, generated_at, commit, data_commit, languages
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
        help="public base URL used in the generated pages",
    )
    parser.add_argument(
        "--data-commit",
        default=os.environ.get("DATA_COMMIT"),
        help="revision of the data branch holding these files (default: DATA_COMMIT)",
    )
    parser.add_argument(
        "--languages",
        default=os.environ.get("SITE_LANGUAGES", ",".join(LANGUAGES)),
        help=f"comma-separated page languages (supported: {', '.join(LANGUAGES)})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    data_dir = Path(args.data_dir)
    site_dir = Path(args.site_dir)

    if not data_dir.is_dir():
        print(f"Data directory not found: {data_dir}", file=sys.stderr)
        return 3

    languages = normalize_languages(args.languages)
    manifest = build_site(
        data_dir,
        site_dir,
        site_url=args.site_url,
        data_commit=args.data_commit,
        languages=languages,
    )
    pages = ", ".join(manifest["pages"].values())
    files = ", ".join(manifest["files"]) or "(no data files found)"
    print(f"Site written to {site_dir}: {pages}, manifest.json, {files}")
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
