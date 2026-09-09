"""V4 streaming multi-format exporter.

Every file is written line-by-line (no 50 MB in-memory string join).  The
exporter produces, from the same optimised rule set:

  merged_rules.txt   AdGuard block rules (||domain^), no @@ / no $ / no CSS
  whitelist.txt      AdGuard allow rules (@@||domain^)
  hosts.txt          0.0.0.0 domain
  domains.txt        one plain domain per line
  clash.yaml         DOMAIN-SUFFIX,domain
  surge.list         DOMAIN-SUFFIX,domain
  smartdns.conf      address /domain/#
  merged_ads.txt / merged_malware.txt / merged_tracking.txt / merged_phishing.txt
                     tiered subsets by category
  stats.json         machine-readable optimisation report
  conflicts.json     block rules removed by whitelist overrides
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .models import (
    Rule, CATEGORY_ADS, CATEGORY_MALWARE, CATEGORY_TRACKING,
    CATEGORY_PHISHING, CATEGORY_MINING, TIERED_CATEGORIES,
)
from .report import analyze_rules, generate_html_report

HOMEPAGE = "https://github.com/kekai2020/adguard-rules-merger-v4"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _version_stamp(dt: datetime) -> str:
    return dt.strftime("%Y%m%d%H%M")


class Exporter:
    """Stream all output formats to disk."""

    def __init__(
        self,
        out_dir: str | Path,
        formats: List[str] | None = None,
        tiered: bool = True,
        report: bool = True,
    ) -> None:
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.formats = formats or [
            "adguard", "whitelist", "hosts", "domains",
            "clash", "surge", "smartdns",
        ]
        self.tiered = tiered
        self.report = report

    # ── header helpers ────────────────────────────────────────────

    def _main_header(self, blocks: List[Rule], allows: List[Rule],
                     outcome: Any, cat_counts: Counter) -> List[str]:
        now = _now()
        src_ok = outcome.sources_ok
        src_tot = outcome.sources_total
        cached = outcome.sources_cached
        before = outcome.raw_count
        after = len(blocks) + len(allows)
        dedup_rate = (1 - after / before) * 100 if before else 0.0
        cats = " ".join(f"{k}={cat_counts.get(k, 0)}" for k in
                        ("ads", "malware", "tracking", "phishing", "mining", "other"))
        return [
            "! Title: Merged AdGuard Home Filter Rules (V4)",
            f"! Description: Auto-merged from {src_tot} sources with upward aggregation",
            f"! Version: {_version_stamp(now)}",
            f"! Last modified: {now.isoformat()}",
            f"! Homepage: {HOMEPAGE}",
            f"! Total block rules: {len(blocks)}",
            f"! Total whitelist rules: {len(allows)}",
            f"! Sources: {src_ok}/{src_tot} ({cached} cached)",
            f"! Dedup rate: {dedup_rate:.1f}%",
            f"! Aggregated: {outcome.aggregated}",
            f"! Conflicts resolved: {outcome.conflict_resolved}",
            f"! Categories: {cats}",
            "!",
        ]

    def _whitelist_header(self, allows: List[Rule]) -> List[str]:
        now = _now()
        return [
            "! Title: Whitelist for Merged Rules (V4)",
            "! Description: Allow rules separated from main filter",
            f"! Version: {_version_stamp(now)}",
            f"! Total allow rules: {len(allows)}",
            "!",
        ]

    # ── writers (all streaming) ─────────────────────────────────

    def _write_lines(self, path: Path, header: List[str],
                      body: Iterable[str]) -> None:
        with open(path, "w", encoding="utf-8", buffering=1024 * 64) as f:
            for line in header:
                f.write(line + "\n")
            for line in body:
                f.write(line + "\n")

    def write_adguard(self, blocks: List[Rule], allows: List[Rule],
                      outcome: Any, cat_counts: Counter) -> None:
        header = self._main_header(blocks, allows, outcome, cat_counts)
        self._write_lines(self.out / "merged_rules.txt", header,
                          (b.output_raw for b in blocks))

    def write_whitelist(self, allows: List[Rule]) -> None:
        header = self._whitelist_header(allows)
        self._write_lines(self.out / "whitelist.txt", header,
                          (a.output_raw for a in allows))

    def write_hosts(self, blocks: List[Rule]) -> None:
        def body():
            seen = set()
            for b in blocks:
                d = b.normalized_domain
                if d in seen:
                    continue
                seen.add(d)
                yield f"0.0.0.0 {d}"
        self._write_lines(self.out / "hosts.txt",
                          ["# Hosts format — AdGuard Rules Merger V4", "#"],
                          body())

    def write_domains(self, blocks: List[Rule]) -> None:
        seen = set()
        def body():
            for b in blocks:
                d = b.normalized_domain
                if d in seen:
                    continue
                seen.add(d)
                yield d
        self._write_lines(self.out / "domains.txt", [], body())

    def write_clash(self, blocks: List[Rule]) -> None:
        seen = set()
        def body():
            for b in blocks:
                d = b.normalized_domain
                if d in seen:
                    continue
                seen.add(d)
                yield f"  - DOMAIN-SUFFIX,{d}"
        self._write_lines(self.out / "clash.yaml",
                          ["# Clash rule-set — AdGuard Rules Merger V4",
                           "payload:"],
                          body())

    def write_surge(self, blocks: List[Rule]) -> None:
        seen = set()
        def body():
            for b in blocks:
                d = b.normalized_domain
                if d in seen:
                    continue
                seen.add(d)
                yield f"DOMAIN-SUFFIX,{d}"
        self._write_lines(self.out / "surge.list",
                          ["# Surge rule-set — AdGuard Rules Merger V4",
                           "# DOMAIN-SUFFIX,<domain>"],
                          body())

    def write_smartdns(self, blocks: List[Rule]) -> None:
        seen = set()
        def body():
            for b in blocks:
                d = b.normalized_domain
                if d in seen:
                    continue
                seen.add(d)
                yield f"address /{d}/#"
        self._write_lines(self.out / "smartdns.conf",
                          ["# SmartDNS blocking config — AdGuard Rules Merger V4",
                           "# address /domain/#  (blocks domain + subdomains)"],
                          body())

    def write_tiered(self, blocks: List[Rule]) -> None:
        buckets: Dict[str, List[Rule]] = {c: [] for c in TIERED_CATEGORIES}
        for b in blocks:
            if b.category in buckets:
                buckets[b.category].append(b)
        filenames = {
            CATEGORY_ADS: "merged_ads.txt",
            CATEGORY_MALWARE: "merged_malware.txt",
            CATEGORY_TRACKING: "merged_tracking.txt",
            CATEGORY_PHISHING: "merged_phishing.txt",
            CATEGORY_MINING: "merged_mining.txt",
        }
        now = _now()
        for cat, rules in buckets.items():
            header = [
                f"! Title: Merged {cat} filter (V4)",
                f"! Category: {cat}",
                f"! Version: {_version_stamp(now)}",
                f"! Rules: {len(rules)}",
                "!",
            ]
            self._write_lines(self.out / filenames[cat], header,
                              (r.output_raw for r in rules))

    def write_stats(self, blocks: List[Rule], allows: List[Rule],
                    outcome: Any) -> None:
        now = _now()
        cat_counts = Counter(b.category for b in blocks)
        before = outcome.raw_count
        after = len(blocks) + len(allows)
        stats = {
            "generated_at": now.isoformat(),
            "sources": {
                "total": outcome.sources_total,
                "ok": outcome.sources_ok,
                "cached": outcome.sources_cached,
            },
            "rules": {
                "before": before,
                "after": after,
                "block": len(blocks),
                "allow": len(allows),
                "dedup_rate": round((1 - after / before) * 100, 1) if before else 0.0,
            },
            "optimization": {
                "exact_merged": outcome.exact_merged,
                "normalized_merged": getattr(outcome, "normalized_merged", 0),
                "wildcard_removed": getattr(outcome, "wildcard_removed", 0),
                "conflict_resolved": outcome.conflict_resolved,
                "aggregated": outcome.aggregated,
                "whitelist_blocked": outcome.whitelist_blocked,
                "pattern_dropped": getattr(outcome, "pattern_dropped", 0),
            },
            "categories": {
                "ads": cat_counts.get(CATEGORY_ADS, 0),
                "malware": cat_counts.get(CATEGORY_MALWARE, 0),
                "tracking": cat_counts.get(CATEGORY_TRACKING, 0),
                "phishing": cat_counts.get(CATEGORY_PHISHING, 0),
                "mining": cat_counts.get("mining", 0),
                "other": cat_counts.get("other", 0),
            },
            "elapsed_seconds": round(outcome.elapsed, 3),
        }
        path = self.out / "stats.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(stats, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(path)

    def write_conflicts(self, conflicts: List[Dict[str, Any]]) -> None:
        path = self.out / "conflicts.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(conflicts, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(path)

    def write_report(self, blocks: List[Rule], allows: List[Rule],
                     outcome: Any) -> None:
        """Generate professional HTML analysis report."""
        analysis = analyze_rules(blocks, allows)
        html = generate_html_report(blocks, allows, outcome, analysis)
        path = self.out / "report.html"
        tmp = path.with_suffix(".html.tmp")
        tmp.write_text(html, encoding="utf-8")
        tmp.replace(path)

    # ── orchestration ────────────────────────────────────────────

    def export_all(self, blocks: List[Rule], allows: List[Rule],
                   outcome: Any) -> Counter:
        cat_counts = Counter(b.category for b in blocks)

        # write formats based on config
        if "adguard" in self.formats:
            self.write_adguard(blocks, allows, outcome, cat_counts)
        if "whitelist" in self.formats:
            self.write_whitelist(allows)
        if "hosts" in self.formats:
            self.write_hosts(blocks)
        if "domains" in self.formats:
            self.write_domains(blocks)
        if "clash" in self.formats:
            self.write_clash(blocks)
        if "surge" in self.formats:
            self.write_surge(blocks)
        if "smartdns" in self.formats:
            self.write_smartdns(blocks)

        # tiered output
        if self.tiered:
            self.write_tiered(blocks)

        # always write stats and conflicts (needed for report)
        self.write_stats(blocks, allows, outcome)
        self.write_conflicts(outcome.conflicts)

        # HTML report
        if self.report:
            self.write_report(blocks, allows, outcome)

        return cat_counts
