"""Parser unit tests."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from merger import RuleParser


def parse(text, src="src"):
    return RuleParser().parse_text(text, source=src)


def test_block_rule():
    rules = parse("||ads.example.com^")
    assert len(rules) == 1
    r = rules[0]
    assert r.rule_type == "block"
    assert r.domain == "ads.example.com"
    assert not r.wildcard
    assert r.output_raw == "||ads.example.com^"


def test_allow_rule():
    rules = parse("@@||safe.example.com^")
    assert len(rules) == 1
    r = rules[0]
    assert r.rule_type == "allow"
    assert r.output_raw == "@@||safe.example.com^"


def test_wildcard_rule():
    rules = parse("||*.example.com^")
    assert len(rules) == 1
    r = rules[0]
    assert r.wildcard is True
    assert r.domain == "*.example.com"
    assert r.normalized_domain == "example.com"
    assert r.output_raw == "||*.example.com^"


def test_modifier_truncated():
    rules = parse(r"||modded.com^$third-party")
    assert len(rules) == 1
    assert rules[0].output_raw == "||modded.com^"


def test_css_dropped():
    assert not [r for r in parse("##.ad-banner") if r.rule_type != "comment"]
    assert not [r for r in parse("#@#.ad-banner") if r.rule_type != "comment"]


def test_regex_kept():
    """Regex rules are supported by AGH and should be kept."""
    rules = parse("/example\\.com/")
    assert len(rules) == 1
    assert rules[0].rule_type == "block"
    assert rules[0].output_raw == "/example\\.com/"

    rules = parse("@@/example\\.com/")
    assert len(rules) == 1
    assert rules[0].rule_type == "allow"
    assert rules[0].output_raw == "@@/example\\.com/"


def test_url_bar_dropped():
    assert not [r for r in parse("|https://bad.com/") if r.rule_type != "comment"]


def test_hosts_conversion():
    rules = parse("0.0.0.0 hoststest.com")
    assert len(rules) == 1
    assert rules[0].rule_type == "block"
    assert rules[0].output_raw == "||hoststest.com^"
    rules = parse("127.0.0.1 localhost.localdomain")
    assert not [r for r in rules if r.rule_type != "comment"]


def test_plain_domain_conversion():
    rules = parse("plain-domain.com")
    assert len(rules) == 1
    assert rules[0].rule_type == "block"
    assert rules[0].output_raw == "||plain-domain.com^"


def test_comment_kept():
    rules = parse("! This is a comment")
    assert len(rules) == 1
    assert rules[0].rule_type == "comment"


def test_dedup_key_distinct():
    """||*.example.com^ and ||example.com^ are different rules at dedup."""
    rules = parse("||*.example.com^\n||example.com^")
    from merger.core import AsyncRuleEngine
    bmap, m = AsyncRuleEngine._dedup([r for r in rules if r.rule_type == "block"])
    assert len(bmap) == 2  # wildcard and exact kept separate
    assert m == 0


# ── embedded '*' must be dropped (DNS layer only supports leading *.domain) ──

def test_embedded_star_block_dropped():
    p = RuleParser()
    rules = p.parse_text("||*-ad.example.com^", source="src")
    assert not [r for r in rules if r.rule_type == "block"]
    assert p.pattern_dropped == 1


def test_mid_star_block_dropped():
    p = RuleParser()
    rules = p.parse_text("||*tracker*.example.com^", source="src")
    assert not [r for r in rules if r.rule_type == "block"]
    assert p.pattern_dropped == 1


def test_embedded_star_allow_dropped():
    p = RuleParser()
    rules = p.parse_text("@@||*a*.b^", source="src")
    assert not [r for r in rules if r.rule_type == "allow"]
    assert p.pattern_dropped == 1


def test_leading_wildcard_still_kept():
    p = RuleParser()
    rules = p.parse_text("||*.example.com^", source="src")
    blocks = [r for r in rules if r.rule_type == "block"]
    assert len(blocks) == 1
    assert blocks[0].wildcard is True
    assert blocks[0].output_raw == "||*.example.com^"
    assert p.pattern_dropped == 0


def test_embedded_star_counted_aggregate():
    p = RuleParser()
    text = ("||*.example.com^\n"
            "||*-ad.example.com^\n"
            "||*tracker*.example.com^\n"
            "||clean.example.com^")
    rules = p.parse_text(text, source="src")
    blocks = [r for r in rules if r.rule_type == "block"]
    outs = {r.output_raw for r in blocks}
    assert "||*.example.com^" in outs
    assert "||clean.example.com^" in outs
    assert not any("*" in r.domain and not r.wildcard for r in blocks)
    assert p.pattern_dropped == 2

