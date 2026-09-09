"""V4 async rule engine — fetch, parse, dedup, upward-aggregate, split
whitelist, resolve conflicts, and hand off sorted rules to the exporter.

Pipeline (one end-to-end ``run``):
  1. Concurrent fetch + streaming parse (aiohttp, ETag/SHA256 cache).
  2. Dedup by key ``(normalized_domain, rule_type, wildcard)``; sources unioned.
  3. Upward aggregation: exact ``||sub.example.com^`` rules that sit under a
     surviving ``||*.parent.com^`` or ``||parent.com^`` are removed and their
     sources merged into the surviving parent.  ``||example.com^`` itself is
     *never* removed by ``||*.example.com^`` (root exact is not a subdomain).
  4. Whitelist split: every ``@@||domain^`` is moved out of the main set.
  5. Conflict resolution: allow rules override blocks (with subdomain cascade),
     removed blocks are recorded to conflicts.json.
  6. Stable sort (Rule implements the full rich-comparison protocol).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple

import aiohttp

from .cache import SourceCache
from .models import Rule, SourceMeta, CATEGORY_OTHER
from .parser import RuleParser

logger = logging.getLogger(__name__)

# A parent domain must have at least this many labels to act as an aggregator,
# so that a pathological ``||*.com^`` never strips every single-label TLD rule.
_MIN_AGGREGATOR_LABELS = 2


def _parent_labels(norm: str) -> List[str]:
    """Return strict parent domains, most-specific first.

    ``ads.example.com`` -> ``['example.com']``
    ``sub.ads.example.com`` -> ``['ads.example.com', 'example.com']``
    """
    parts = norm.split(".")
    out: List[str] = []
    for i in range(1, len(parts)):
        out.append(".".join(parts[i:]))
    return out


@dataclass
class MergeOutcome:
    """Everything the exporter needs after one merge run."""
    blocks: List[Rule] = field(default_factory=list)
    allows: List[Rule] = field(default_factory=list)
    regex_blocks: List[Rule] = field(default_factory=list)
    regex_allows: List[Rule] = field(default_factory=list)
    raw_count: int = 0
    sources_ok: int = 0
    sources_total: int = 0
    sources_cached: int = 0
    exact_merged: int = 0
    normalized_merged: int = 0
    aggregated: int = 0
    wildcard_removed: int = 0
    conflict_resolved: int = 0
    whitelist_blocked: int = 0
    pattern_dropped: int = 0
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    elapsed: float = 0.0


class AsyncRuleEngine:
    """Fetch + merge AdGuard DNS rules (async)."""

    def __init__(
        self,
        timeout: int = 60,
        max_concurrency: int = 50,
        cache_dir: Optional[str] = None,
        cache_ttl: int = 0,
        cache_max_size_mb: int = 0,
        strip_www: bool = False,
        quality_filter_enabled: bool = True,
        min_domain_length: int = 4,
        max_domain_length: int = 253,
        filter_localhost: bool = True,
        filter_ip_rules: bool = False,
        aggregation_enabled: bool = True,
        min_aggregator_labels: int = 2,
        conflict_resolution_enabled: bool = True,
        cascade_subdomains: bool = True,
        user_agent: str = "AdGuard-Rules-Merger/4.0",
        retry_count: int = 2,
        retry_delay: float = 1.5,
    ) -> None:
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.strip_www = strip_www
        self.aggregation_enabled = aggregation_enabled
        self.conflict_resolution_enabled = conflict_resolution_enabled
        self.cascade_subdomains = cascade_subdomains
        self.min_aggregator_labels = min_aggregator_labels
        self.user_agent = user_agent
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.parser = RuleParser(
            strip_www=strip_www,
            quality_filter=quality_filter_enabled,
            min_domain_length=min_domain_length,
            max_domain_length=max_domain_length,
            filter_localhost=filter_localhost,
            filter_ip_rules=filter_ip_rules,
        )
        self.cache: Optional[SourceCache] = None
        if cache_dir is not None:
            self.cache = SourceCache(
                cache_dir=cache_dir,
                ttl_seconds=cache_ttl,
                max_size_mb=cache_max_size_mb,
            )
            self.cache.load()
        self._session: Optional[aiohttp.ClientSession] = None

    # ── async context ───────────────────────────────────────────

    async def __aenter__(self) -> "AsyncRuleEngine":
        await self._ensure_session()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self.timeout, sock_connect=30, sock_read=self.timeout)
            connector = aiohttp.TCPConnector(limit=self.max_concurrency,
                                             ttl_dns_cache=300,
                                             force_close=False)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": "AdGuard-Rules-Merger/4.0"},
            )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        if self.cache:
            self.cache.save()

    # ── fetch ────────────────────────────────────────────────────

    async def _fetch_text(self, source: str, retries: int = 2) -> Tuple[str, bool]:
        source = source.strip()
        p = Path(source)
        if p.exists() and p.is_file():
            return p.read_text(encoding="utf-8", errors="replace"), False

        cond_headers: Dict[str, str] = {}
        if self.cache:
            cond_headers = self.cache.conditional_headers(source)

        await self._ensure_session()
        assert self._session is not None
        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                async with self._session.get(source, headers=cond_headers) as resp:
                    if resp.status == 304 and self.cache:
                        cached = self.cache.get_content(source)
                        if cached is not None:
                            self.cache.store_not_modified(source)
                            return cached, True
                    resp.raise_for_status()
                    text = await resp.text(encoding="utf-8", errors="replace")
                    if self.cache:
                        changed = self.cache.content_changed(source, text)
                        self.cache.store(
                            url=source, content=text,
                            etag=resp.headers.get("ETag"),
                            last_modified=resp.headers.get("Last-Modified"),
                        )
                        if not changed:
                            return text, True
                    return text, False
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                last_exc = e
                if attempt < retries:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
        # all retries failed — try cache as fallback
        if self.cache:
            cached = self.cache.get_content(source)
            if cached is not None:
                logger.warning("fetch %s failed (%s); using cache", source, last_exc)
                return cached, True
        logger.error("fetch failed %s: %s", source, last_exc)
        raise RuntimeError(f"fetch failed: {source}") from last_exc

    async def _fetch_one(self, meta: SourceMeta) -> Tuple[List[Rule], bool, bool, int]:
        """Return (rules, success, from_cache, raw_line_count)."""
        t0 = time.time()
        try:
            text, from_cache = await self._fetch_text(meta.url)
            rules = self.parser.parse_text(text, source=meta.url, category=meta.category)
            logger.info("parsed %6d rules from %-40s (%s, %.2fs)",
                        len(rules), meta.url.split("/")[-1],
                        "cache" if from_cache else "net", time.time() - t0)
            return rules, True, from_cache, len(rules)
        except Exception as exc:  # noqa: BLE001 — skip source, keep going
            logger.warning("source failed %s: %s", meta.url, exc)
            return [], False, False, 0

    async def fetch_all(self, sources: List[SourceMeta]
                        ) -> Tuple[Dict[Tuple[str, bool], Rule],
                                   Dict[Tuple[str, bool], Rule],
                                   List[Rule], List[Rule],
                                   int, int, int, int]:
        """Fetch all sources and dedup incrementally.

        Returns (block_map, allow_map, regex_blocks, regex_allows,
                 raw_count, ok, cached, exact_merged).
        """
        sem = asyncio.Semaphore(self.max_concurrency)
        block_map: Dict[Tuple[str, bool], Rule] = {}
        allow_map: Dict[Tuple[str, bool], Rule] = {}
        regex_blocks: Dict[str, Rule] = {}  # dedup by raw string
        regex_allows: Dict[str, Rule] = {}
        raw_count = ok = cached = exact_merged = 0

        async def bounded(meta: SourceMeta):
            async with sem:
                return await self._fetch_one(meta)

        # Process results as they complete to keep memory low.
        for fut in asyncio.as_completed([bounded(s) for s in sources]):
            rules, success, from_cache, n = await fut
            if not success:
                continue
            ok += 1
            raw_count += n
            if from_cache:
                cached += 1
            # incremental dedup: fold each source's rules into the maps
            for r in rules:
                if r.rule_type == "comment":
                    continue
                # regex rules (empty domain) are deduped by raw string
                if r.normalized_domain == "":
                    m = regex_blocks if r.rule_type == "block" else regex_allows
                    key = r.raw
                    if key not in m:
                        m[key] = r
                    else:
                        existing_set = set(m[key].sources)
                        existing_set.update(r.sources)
                        m[key].sources = tuple(sorted(existing_set))
                    continue
                m = block_map if r.rule_type == "block" else allow_map
                key = (r.normalized_domain, r.wildcard)
                existing = m.get(key)
                if existing is None:
                    m[key] = r
                else:
                    # merge sources tuples
                    existing_set = set(existing.sources)
                    existing_set.update(r.sources)
                    existing.sources = tuple(sorted(existing_set))
                    if existing.category == CATEGORY_OTHER and r.category != CATEGORY_OTHER:
                        existing.category = r.category
                    exact_merged += 1
            # free the per-source list promptly
            del rules

        return (block_map, allow_map,
                list(regex_blocks.values()), list(regex_allows.values()),
                raw_count, ok, cached, exact_merged)

    # ── dedup ───────────────────────────────────────────────────

    @staticmethod
    def _dedup(rules: List[Rule]) -> Tuple[Dict[Tuple[str, bool], Rule], int]:
        """Dedup by (norm, wildcard); sources merged.  Returns map + merged count."""
        out: Dict[Tuple[str, bool], Rule] = {}
        merged = 0
        for r in rules:
            key = (r.normalized_domain, r.wildcard)
            existing = out.get(key)
            if existing is None:
                out[key] = r
            else:
                existing_set = set(existing.sources)
                existing_set.update(r.sources)
                existing.sources = tuple(sorted(existing_set))
                if existing.category == CATEGORY_OTHER and r.category != CATEGORY_OTHER:
                    existing.category = r.category
                merged += 1
        return out, merged

    # ── upward aggregation ──────────────────────────────────────

    @staticmethod
    def _aggregate(block_map: Dict[Tuple[str, bool], Rule]
                   ) -> Tuple[List[Rule], int]:
        """Remove exact child rules covered by a surviving parent aggregator.

        Returns (surviving_block_rules, aggregated_count).
        """
        wild_map: Dict[str, Rule] = {}
        exact_map: Dict[str, Rule] = {}
        for r in block_map.values():
            if r.wildcard:
                wild_map[r.normalized_domain] = r
            else:
                exact_map[r.normalized_domain] = r

        # candidate exact children: sort most-specific first so that when a
        # parent aggregator is itself removed, it has already absorbed all of
        # its own children's sources and propagates them upward.
        exact_children = sorted(
            (r for r in block_map.values() if not r.wildcard),
            key=lambda r: (-r.normalized_domain.count(".") - 1, r.normalized_domain),
        )

        removed: Set[Rule] = set()
        aggregated = 0
        for child in exact_children:
            # walk up to find closest surviving parent aggregator
            for parent in _parent_labels(child.normalized_domain):
                if parent.count(".") + 1 < _MIN_AGGREGATOR_LABELS:
                    continue
                keeper = wild_map.get(parent) or exact_map.get(parent)
                if keeper is not None:
                    merged_sources = set(keeper.sources)
                    merged_sources.update(child.sources)
                    keeper.sources = tuple(sorted(merged_sources))
                    removed.add(child)
                    aggregated += 1
                    break

        survivors = [r for r in block_map.values() if r not in removed]
        return survivors, aggregated

    # ── conflict resolution ─────────────────────────────────────

    @staticmethod
    def _resolve_conflicts(
        blocks: List[Rule],
        allows: List[Rule],
    ) -> Tuple[List[Rule], int, List[Dict[str, Any]]]:
        """Allow rules override blocks.  Returns (surviving_blocks, removed_count, conflicts).

        Efficient O(blocks * depth) implementation: index the allow bases, then walk
        each block's parent chain once.
        """
        # index allow bases
        exact_allow: Dict[str, Rule] = {}    # exact allow at A  (removes A itself)
        suffix_allow: Dict[str, Rule] = {}   # any allow at A (removes subdomains of A)
        for a in allows:
            n = a.normalized_domain
            suffix_allow[n] = a
            if not a.wildcard:
                exact_allow[n] = a

        removed: Set[Rule] = set()
        conflicts: List[Dict[str, Any]] = []

        for b in blocks:
            n = b.normalized_domain
            by = None
            # exact match first (@@||A^ removes ||A^ and ||*.A^)
            if n in exact_allow:
                by = exact_allow[n]
            else:
                # walk up parent chain looking for a suffix allow
                parts = n.split(".")
                for i in range(1, len(parts)):
                    parent = ".".join(parts[i:])
                    if parent in suffix_allow:
                        by = suffix_allow[parent]
                        break
            if by is not None:
                removed.add(b)
                srcs = b.sources
                conflicts.append({
                    "blocked_rule": b.output_raw,
                    "blocked_by": by.output_raw,
                    "source": srcs[0] if srcs else "",
                })

        survivors = [b for b in blocks if b not in removed]
        return survivors, len(removed), conflicts

    # ── high-level run ──────────────────────────────────────────

    async def run(self, sources: List[SourceMeta]) -> MergeOutcome:
        sources = [s for s in sources if s.enabled]
        if not sources:
            raise ValueError("No enabled sources")

        t0 = time.time()
        (block_map, allow_map,
         regex_blocks, regex_allows,
         raw_count, ok, cached, exact_merged) = await self.fetch_all(sources)
        logger.info("raw rules: %d from %d/%d sources (%d cached); "
                    "block_keys=%d allow_keys=%d regex_blocks=%d regex_allows=%d",
                    raw_count, ok, len(sources), cached,
                    len(block_map), len(allow_map),
                    len(regex_blocks), len(regex_allows))

        # drop the per-rule raw string (output is reconstructed) to save memory
        # except for regex rules — they need their raw form preserved
        for r in list(block_map.values()) + list(allow_map.values()):
            r.raw = ""

        # upward aggregation on blocks
        aggregated_blocks, aggregated_n = self._aggregate(block_map)
        logger.info("upward aggregation removed %d exact rules", aggregated_n)

        # conflict resolution (allow overrides block)
        final_blocks, removed_n, conflicts = self._resolve_conflicts(
            aggregated_blocks, list(allow_map.values()))

        # stable sort
        final_blocks.sort()
        final_allows = sorted(allow_map.values())

        # append regex rules (they don't participate in aggregation/conflict resolution)
        final_blocks = sorted(final_blocks + regex_blocks)
        final_allows = sorted(final_allows + regex_allows)

        outcome = MergeOutcome(
            blocks=final_blocks,
            allows=final_allows,
            regex_blocks=regex_blocks,
            regex_allows=regex_allows,
            raw_count=raw_count,
            sources_ok=ok,
            sources_total=len(sources),
            sources_cached=cached,
            exact_merged=exact_merged,
            aggregated=aggregated_n,
            conflict_resolved=removed_n,
            whitelist_blocked=removed_n,
            pattern_dropped=self.parser.pattern_dropped,
            conflicts=conflicts,
            elapsed=time.time() - t0,
        )
        return outcome

    def run_sync(self, sources: List[SourceMeta]) -> MergeOutcome:
        async def _go():
            async with self:
                return await self.run(sources)
        return asyncio.run(_go())
