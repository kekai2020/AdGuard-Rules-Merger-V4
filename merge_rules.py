#!/usr/bin/env python3
"""AdGuard Rules Merger V4 — CLI entrypoint.

Usage:
  python merge_rules.py merge    --config config/sources.yaml
  python merge_rules.py validate config/sources.yaml
  python merge_rules.py merge    --config config/sources.yaml --no-cache
"""

from __future__ import annotations

import logging
import resource
import sys
import time
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from merger import AsyncRuleEngine, Exporter, __version__  # noqa: E402
from config_loader import load_config, load_source_metas, validate_config  # noqa: E402

app = typer.Typer(
    name="adguard-rules-merger-v4",
    help="V4: merge AdGuard DNS rules with upward aggregation + multi-format export.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level, format="%(message)s", datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )


def _peak_rss_mb() -> float:
    """Peak resident set size in megabytes (ru_maxrss is KB on Linux)."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


@app.command()
def merge(
    config: str = typer.Option("config/sources.yaml", "--config", "-c"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
):
    """Fetch, merge, optimise and export all rule formats."""
    _setup_logging(verbose, quiet)

    try:
        cfg = load_config(config)
        sources = load_source_metas(config)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Config error: {e}[/red]")
        raise typer.Exit(1)

    out_dir = output_dir or cfg.output.directory
    cache_dir = None if no_cache else cfg.cache.directory

    console.print(f"\n[bold cyan]AdGuard Rules Merger v{__version__}[/bold cyan]")
    console.print(f"  Sources: {len(sources)} | Concurrency: {cfg.max_concurrency}")
    console.print(f"  Cache: {'disabled' if no_cache else cfg.cache.directory}")
    console.print()

    engine = AsyncRuleEngine(
        timeout=cfg.timeout,
        max_concurrency=cfg.max_concurrency,
        cache_dir=cache_dir,
        cache_ttl=cfg.cache.ttl_seconds,
        cache_max_size_mb=cfg.cache.max_size_mb,
        strip_www=cfg.dedup.strip_www,
        quality_filter_enabled=cfg.quality_filter.enabled,
        min_domain_length=cfg.quality_filter.min_domain_length,
        max_domain_length=cfg.quality_filter.max_domain_length,
        filter_localhost=cfg.quality_filter.filter_localhost,
        filter_ip_rules=cfg.quality_filter.filter_ip_rules,
        aggregation_enabled=cfg.aggregation.enabled,
        min_aggregator_labels=cfg.aggregation.min_aggregator_labels,
        conflict_resolution_enabled=cfg.conflict_resolution.enabled,
        cascade_subdomains=cfg.conflict_resolution.cascade_subdomains,
        user_agent=cfg.download.user_agent,
        retry_count=cfg.download.retry_count,
        retry_delay=cfg.download.retry_delay,
    )

    t0 = time.time()
    try:
        outcome = engine.run_sync(sources)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red bold]✗ Merge failed: {e}[/red bold]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)

    wall = time.time() - t0
    exporter = Exporter(
        out_dir,
        formats=cfg.output.formats,
        tiered=cfg.output.tiered,
        report=cfg.output.report,
    )
    exporter.export_all(outcome.blocks, outcome.allows, outcome)

    # results table
    table = Table(title="Merge Results", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    table.add_row("Raw rules (before)", f"{outcome.raw_count:,}")
    table.add_row("Block rules", f"{len(outcome.blocks):,}")
    table.add_row("Whitelist rules", f"{len(outcome.allows):,}")
    table.add_row("Sources (ok/cached/total)",
                  f"{outcome.sources_ok} / {outcome.sources_cached} / {outcome.sources_total}")
    table.add_row("Exact dedup merges", f"{outcome.exact_merged:,}")
    table.add_row("Upward aggregated", f"{outcome.aggregated:,}")
    table.add_row("Conflicts resolved", f"{outcome.conflict_resolved:,}")
    table.add_row("Wall time", f"{wall:.2f}s")
    table.add_row("Peak RSS", f"{_peak_rss_mb():.1f} MB")
    console.print(table)

    console.print(f"\n[green]✓ Output written to {Path(out_dir).resolve()}[/green]")
    for fn in ("merged_rules.txt", "whitelist.txt", "hosts.txt", "domains.txt",
               "clash.yaml", "surge.list", "smartdns.conf",
               "merged_ads.txt", "merged_malware.txt",
               "merged_tracking.txt", "merged_phishing.txt",
               "merged_mining.txt",
               "stats.json", "conflicts.json", "report.html"):
        p = Path(out_dir) / fn
        if p.exists():
            console.print(f"    {fn}  ({p.stat().st_size/1024:.0f} KB)")
    console.print()


@app.command()
def validate(config_path: str = typer.Argument(..., help="YAML config to validate")):
    """Validate a sources.yaml config file."""
    issues = validate_config(config_path)
    if issues:
        console.print(f"[red]✗ {len(issues)} issue(s):[/red]")
        for i in issues:
            console.print(f"  - {i}")
        raise typer.Exit(1)
    cfg = load_config(config_path)
    console.print("[green]✓ Valid config[/green]")
    console.print(f"  Sources: {len(cfg.sources)} "
                  f"({sum(1 for s in cfg.sources if s.enabled)} enabled)")


@app.command()
def version():
    """Show version."""
    console.print(f"AdGuard Rules Merger v{__version__}")


if __name__ == "__main__":
    app()
