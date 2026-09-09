"""Multi-format export + end-to-end integration tests (local files, no network)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from merger import RuleParser, Exporter, SourceMeta
from merger.core import AsyncRuleEngine


SRC_A = """! Source A
||ads.example.com^
||tracker.sub.example.com^
||example.com^
||*.example.com^
||malware.test.com^
"""

SRC_B = """! Source B
@@||example.com^
||ads.example.com^
||phishing.bad.com^
0.0.0.0 hosttest.com
"""


def _write_source(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_end_to_end_local(tmp_path):
    a = _write_source(tmp_path, "a.txt", SRC_A)
    b = _write_source(tmp_path, "b.txt", SRC_B)
    out = tmp_path / "out"

    engine = AsyncRuleEngine(cache_dir=None)
    sources = [
        SourceMeta(name="A", url=a, category="ads"),
        SourceMeta(name="B", url=b, category="phishing"),
    ]
    outcome = engine.run_sync(sources)
    exporter = Exporter(out)
    exporter.export_all(outcome.blocks, outcome.allows, outcome)

    # --- merged_rules.txt checks ---
    merged = (out / "merged_rules.txt").read_text(encoding="utf-8")
    assert "@@" not in merged
    assert "$" not in merged
    assert "##" not in merged.split("!\n", 1)[1]  # body has no CSS
    assert "Total block rules:" in merged
    assert "Aggregated:" in merged
    assert "Categories:" in merged
    # wild child aggregated away
    assert "||ads.example.com^" not in merged
    assert "||tracker.sub.example.com^" not in merged
    # allow @@||example.com^ removes the whole example.com tree
    assert "||example.com^" not in merged
    assert "||*.example.com^" not in merged
    # other blocks survive
    assert "||malware.test.com^" in merged
    assert "||phishing.bad.com^" in merged
    assert "||hosttest.com^" in merged

    # --- whitelist.txt ---
    wl = (out / "whitelist.txt").read_text(encoding="utf-8")
    assert "@@||example.com^" in wl
    assert "@@" in wl

    # --- hosts.txt ---
    hosts = (out / "hosts.txt").read_text(encoding="utf-8")
    assert "0.0.0.0 malware.test.com" in hosts

    # --- domains.txt ---
    dom = (out / "domains.txt").read_text(encoding="utf-8").splitlines()
    assert "malware.test.com" in dom

    # --- clash.yaml ---
    clash = (out / "clash.yaml").read_text(encoding="utf-8")
    assert "DOMAIN-SUFFIX,malware.test.com" in clash

    # --- surge.list ---
    surge = (out / "surge.list").read_text(encoding="utf-8")
    assert "DOMAIN-SUFFIX,malware.test.com" in surge

    # --- smartdns.conf ---
    sdns = (out / "smartdns.conf").read_text(encoding="utf-8")
    assert "address /malware.test.com/#" in sdns

    # --- stats.json ---
    stats = json.loads((out / "stats.json").read_text(encoding="utf-8"))
    assert "optimization" in stats
    assert stats["optimization"]["aggregated"] >= 1
    assert stats["optimization"]["conflict_resolved"] >= 1

    # --- conflicts.json ---
    conflicts = json.loads((out / "conflicts.json").read_text(encoding="utf-8"))
    assert isinstance(conflicts, list)
    if conflicts:
        assert {"blocked_rule", "blocked_by", "source"} <= set(conflicts[0])


def test_stable_sort(tmp_path):
    """Two runs must produce byte-identical merged_rules.txt."""
    a = _write_source(tmp_path, "a.txt", SRC_A)
    b = _write_source(tmp_path, "b.txt", SRC_B)
    sources = [
        SourceMeta(name="A", url=a, category="ads"),
        SourceMeta(name="B", url=b, category="phishing"),
    ]
    engine = AsyncRuleEngine(cache_dir=None)
    out1 = tmp_path / "o1"
    out2 = tmp_path / "o2"
    o1 = engine.run_sync(sources)
    Exporter(out1).export_all(o1.blocks, o1.allows, o1)
    o2 = engine.run_sync(sources)
    Exporter(out2).export_all(o2.blocks, o2.allows, o2)
    a1 = (out1 / "merged_rules.txt").read_text(encoding="utf-8")
    a2 = (out2 / "merged_rules.txt").read_text(encoding="utf-8")
    # strip the timestamp/version header line, compare bodies
    body1 = a1.split("!\n", 1)[1]
    body2 = a2.split("!\n", 1)[1]
    assert body1 == body2
