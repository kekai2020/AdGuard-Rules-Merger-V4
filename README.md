# AdGuard Rules Merger V4

A production-grade **DNS-layer** filter-rule compiler that pulls multiple AdGuard
HostlistsRegistry sources, deduplicates, applies **upward aggregation**, splits the
whitelist, resolves block/allow conflicts, and exports optimised rule sets in seven
formats with a professional HTML analysis report.

```
raw multi-source text
  → parse (AdGuard / Hosts / plain-domain / regex; drop $-modifiers & CSS/JS)
  → quality filter (length / localhost / IP rules)
  → dedup by (normalized_domain, type, wildcard) + strip_www
  → upward aggregation (exact child rules folded into surviving parents)
  → whitelist split (@@||…^ out of the main set)
  → conflict resolution (allow overrides block, subdomain-cascade)
  → stable sort
  → 7-format streaming export + tiered category files + HTML report
```

## ✨ Features

- **14+ sources** from AdGuard HostlistsRegistry (ads / malware / tracking / phishing / mining)
- **Smart dedup**: exact match + normalized (strip www / lowercase / trailing dot)
- **Upward aggregation**: child rules folded into parent wildcards (saves ~54k rules)
- **Whitelist separation**: allow rules auto-split to `whitelist.txt`
- **Conflict resolution**: `@@||A^` cascades to all subdomains
- **Regex rule recovery**: `/regex/` rules preserved (AGH officially supports them)
- **Quality filter**: configurable domain length / localhost / IP rules
- **7 output formats**: AdGuard / hosts / domains / clash / surge / smartdns
- **Tiered output**: per-category files (ads / malware / tracking / phishing / mining)
- **HTML analysis report**: interactive ECharts dashboard after every merge
- **ETag + SHA-256 cache**: compatible with `actions/cache`
- **Async I/O**: 50 concurrent downloads with retry
- **Fully configurable**: pydantic-validated YAML config

## Install

```bash
pip3 install -r requirements.txt
```

Requires Python 3.10+. No system dependencies needed.

## Quick start

```bash
# 1. Validate your source list
python3 merge_rules.py validate config/sources.yaml

# 2. Fetch, merge, optimise and export every format
python3 merge_rules.py merge --config config/sources.yaml

# 3. Run without cache (force re-download)
python3 merge_rules.py merge --config config/sources.yaml --no-cache
```

Output lands in `output/` (configurable via `output.directory`).

## Commands

| Command | Purpose |
|---|---|
| `merge --config <yaml>` | Full pipeline: fetch → parse → dedup → aggregate → split → resolve → export |
| `validate <yaml>`        | Validate the source config (pydantic v2) |
| `version`                | Print version |

## Configuration (`config/sources.yaml`)

```yaml
# ── Global settings ──────────────────────────────────
timeout: 60
max_concurrency: 50

# ── Download settings ───────────────────────────────
download:
  user_agent: "AdGuard-Rules-Merger/4.0"
  retry_count: 2
  retry_delay: 1.5

# ── Dedup settings ─────────────────────────────────
dedup:
  strip_www: true              # Treat www.example.com == example.com
  normalize_case: true
  normalize_trailing_dot: true

# ── Quality filter ──────────────────────────────────
quality_filter:
  enabled: true
  min_domain_length: 4
  max_domain_length: 253
  filter_localhost: true
  filter_ip_rules: false

# ── Aggregation ─────────────────────────────────────
aggregation:
  enabled: true
  min_aggregator_labels: 2

# ── Conflict resolution ────────────────────────────
conflict_resolution:
  enabled: true
  cascade_subdomains: true

# ── Cache ───────────────────────────────────────────
cache:
  enabled: true
  directory: cache
  ttl_seconds: 0
  max_size_mb: 500

# ── Output ──────────────────────────────────────────
output:
  directory: output
  formats:
    - adguard
    - whitelist
    - hosts
    - domains
    - clash
    - surge
    - smartdns
  tiered: true
  report: true

# ── Rule sources ────────────────────────────────────
sources:
  - name: "AdGuard DNS filter"
    url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
    enabled: true
    category: ads          # ads | malware | tracking | phishing | mining | other
    reputation: 0.95
```

Each source URL is a HostlistsRegistry `filter_N.txt` (or any DNS-format list).
Category drives the tiered output files.

## Output files

| File | Format | Description |
|---|---|---|
| `merged_rules.txt` | AdGuard | Block rules (`||domain^`), header with totals/stats |
| `whitelist.txt` | AdGuard | Allow rules (`@@||domain^`) |
| `hosts.txt` | Hosts | `0.0.0.0 domain` |
| `domains.txt` | Plain | one plain domain per line |
| `clash.yaml` | Clash | `DOMAIN-SUFFIX,domain` payload |
| `surge.list` | Surge | `DOMAIN-SUFFIX,domain` |
| `smartdns.conf` | SmartDNS | `address /domain/#` |
| `merged_ads.txt` etc. | AdGuard | Tiered subsets by category |
| `stats.json` | JSON | Machine-readable optimisation report |
| `conflicts.json` | JSON | Block rules removed by whitelist overrides |
| `report.html` | HTML | **Interactive analysis dashboard** (ECharts) |

## Analysis report (`report.html`)

After every merge, a professional HTML report is generated with:

- **Executive dashboard**: 6 key metrics at a glance
- **Optimization funnel**: raw → dedup → aggregate → conflicts
- **Rule type distribution**: pie chart (domain / wildcard / regex / IP)
- **Category breakdown**: bar chart (ads / malware / tracking / phishing / mining)
- **Top 20 domain suffixes**: horizontal bar chart
- **Grammar support matrix**: which rule types are kept/dropped
- **Performance metrics**: timing / cache hit rate / success rate

Just open `output/report.html` in your browser.

## Key design decisions

- **Dedup key** = `(normalized_domain, rule_type, wildcard)`. `||*.example.com^`
  and `||example.com^` are **never** collapsed at dedup; they are reconciled in
  the aggregation stage.
- **Upward aggregation**: an exact `||ads.example.com^` is removed when a surviving
  parent `||*.example.com^` or `||example.com^` exists; its `sources` set is merged
  into the surviving rule. The root exact `||example.com^` is *never* removed by
  `||*.example.com^` (it is not a subdomain of itself). A 2-label minimum prevents
  a pathological `||*.com^` from stripping every rule.
- **Conflict resolution**: `@@||A^` removes `||A^`, `||*.A^`, and every strict
  subdomain block of `A`; `@@||*.A^` removes only strict subdomains of `A`. Removed
  blocks are logged to `conflicts.json`.
- **Regex rule recovery**: `/regex/` rules are preserved (AGH officially supports
  them in DNS mode). They are stored as-is and don't participate in aggregation.
- **Streaming I/O**: every output file is written line-by-line (64 KB buffers);
  no 50 MB string is assembled in memory.
- **Stable sort**: `Rule` implements the full rich-comparison protocol, so two
  runs produce byte-identical rule ordering (diff-friendly).

## Testing

```bash
# unit + integration tests (offline, no network)
pytest -q
```

26 tests covering parser, aggregation, export, and edge cases.

## CI/CD (`.github/workflows/merge.yml`)

- Scheduled every 6 hours + manual dispatch.
- `actions/cache` persists `cache/` (ETag + SHA-256) between runs.
- Smart commit: only commits when `output/` actually changed; `git pull --rebase`
  before push to avoid non-fast-forward aborts.
- Separate test job runs `pytest`.
- Uploads merged output as build artifact.

## Repository layout

```
merge_rules.py        CLI entrypoint (merge / validate / version)
config_loader.py      pydantic-v2 YAML config loader
config/sources.yaml   14 HostlistsRegistry sources
merger/
  models.py           Rule (slots + total_ordering), SourceMeta
  parser.py           streaming AdGuard/Hosts/plain-domain/regex parser
  core.py             async fetch + dedup + aggregation + conflicts
  exporter.py         7-format streaming exporter + tiered files
  cache.py            ETag/SHA-256 file cache
  report.py           HTML analysis report generator
tests/                 pytest suite (parser, aggregation, export)
.github/workflows/merge.yml
```

## License

MIT
