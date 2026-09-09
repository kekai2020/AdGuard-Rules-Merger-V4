"""Upward aggregation + conflict resolution unit tests."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from merger import RuleParser
from merger.core import AsyncRuleEngine


def _blocks(text, src="src"):
    return [r for r in RuleParser().parse_text(text, source=src) if r.rule_type == "block"]


def _allows(text, src="src"):
    return [r for r in RuleParser().parse_text(text, source=src) if r.rule_type == "allow"]


def test_wildcard_aggregates_children():
    blocks = _blocks(
        "||ads.example.com^\n||tracker.sub.example.com^\n||*.example.com^"
    )
    bmap, _ = AsyncRuleEngine._dedup(blocks)
    survivors, n = AsyncRuleEngine._aggregate(bmap)
    assert n == 2  # ads.example.com + tracker.sub.example.com removed
    out = {r.output_raw for r in survivors}
    assert "||*.example.com^" in out
    assert "||ads.example.com^" not in out
    assert "||tracker.sub.example.com^" not in out


def test_root_exact_not_aggregated_by_wildcard():
    """||example.com^ must survive even when ||*.example.com^ exists."""
    blocks = _blocks("||example.com^\n||*.example.com^")
    bmap, _ = AsyncRuleEngine._dedup(blocks)
    survivors, n = AsyncRuleEngine._aggregate(bmap)
    out = {r.output_raw for r in survivors}
    assert "||example.com^" in out
    assert "||*.example.com^" in out


def test_exact_parent_aggregates_children():
    """||other.com^ (exact) removes ||deep.other.com^."""
    blocks = _blocks("||other.com^\n||deep.other.com^")
    bmap, _ = AsyncRuleEngine._dedup(blocks)
    survivors, n = AsyncRuleEngine._aggregate(bmap)
    out = {r.output_raw for r in survivors}
    assert n == 1
    assert "||other.com^" in out
    assert "||deep.other.com^" not in out


def test_aggregated_sources_merged():
    blocks = _blocks("||ads.example.com^", src="A") + _blocks("||*.example.com^", src="B")
    bmap, _ = AsyncRuleEngine._dedup(blocks)
    survivors, n = AsyncRuleEngine._aggregate(bmap)
    wildcard = [r for r in survivors if r.wildcard][0]
    assert n == 1
    assert "A" in wildcard.sources and "B" in wildcard.sources


def test_no_over_removal_tld():
    """||*.com^ must not strip single-label TLD rules."""
    blocks = _blocks("||example.com^\n||*.com^")
    bmap, _ = AsyncRuleEngine._dedup(blocks)
    survivors, n = AsyncRuleEngine._aggregate(bmap)
    out = {r.output_raw for r in survivors}
    # example.com should NOT be removed by *.com (TLD-only guard)
    assert "||example.com^" in out


def test_allow_exact_overrides_block():
    blocks = _blocks("||example.com^\n||*.example.com^\n||ads.example.com^")
    allows = _allows("@@||example.com^")
    fin, removed, conflicts = AsyncRuleEngine._resolve_conflicts(blocks, allows)
    out = {r.output_raw for r in fin}
    # exact allow removes root exact + root wildcard + subdomains
    assert "||example.com^" not in out
    assert "||*.example.com^" not in out
    assert "||ads.example.com^" not in out
    assert removed == 3
    assert conflicts[0]["blocked_by"] == "@@||example.com^"


def test_allow_wildcard_overrides_subdomains():
    blocks = _blocks(
        "||example.com^\n||*.example.com^\n"
        "||ads.example.com^\n||*.ads.example.com^"
    )
    allows = _allows("@@||*.example.com^")
    fin, removed, conflicts = AsyncRuleEngine._resolve_conflicts(blocks, allows)
    out = {r.output_raw for r in fin}
    # wildcard allow drops strict subdomains (ads.example.com, *.ads.example.com)
    # but NOT the root example.com or root *.example.com
    assert "||ads.example.com^" not in out
    assert "||*.ads.example.com^" not in out
    assert "||example.com^" in out
    assert "||*.example.com^" in out


def test_conflict_record_format():
    blocks = _blocks("||safe.example.com^", src="https://filter_1.txt")
    allows = _allows("@@||example.com^")
    fin, removed, conflicts = AsyncRuleEngine._resolve_conflicts(blocks, allows)
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c["blocked_rule"] == "||safe.example.com^"
    assert c["blocked_by"] == "@@||example.com^"
    assert c["source"] == "https://filter_1.txt"
