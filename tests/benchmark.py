#!/usr/bin/env python3
"""Benchmark runner: measures wall time + peak RSS for a merge run."""
import sys, time, resource
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from merger import AsyncRuleEngine, Exporter
from config_loader import load_config, load_source_metas

def main():
    cfg = load_config("config/sources.yaml")
    sources = load_source_metas("config/sources.yaml")
    cache_dir = cfg.cache.directory
    out_dir = cfg.output.directory

    t0 = time.time()
    engine = AsyncRuleEngine(
        timeout=cfg.timeout, max_concurrency=cfg.max_concurrency,
        cache_dir=cache_dir, cache_ttl=cfg.cache.ttl_seconds,
        cache_max_size_mb=cfg.cache.max_size_mb,
    )
    outcome = engine.run_sync(sources)
    Exporter(out_dir).export_all(outcome.blocks, outcome.allows, outcome)
    wall = time.time() - t0
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    print(f">>> RUN wall={wall:.2f}s  peak_rss={rss:.1f} MB")
    print(f">>> raw={outcome.raw_count} blocks={len(outcome.blocks)} allows={len(outcome.allows)} "
          f"aggregated={outcome.aggregated} conflicts={outcome.conflict_resolved} "
          f"sources_ok={outcome.sources_ok}/{outcome.sources_total} cached={outcome.sources_cached}")

if __name__ == "__main__":
    main()
