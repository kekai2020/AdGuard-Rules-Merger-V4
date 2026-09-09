"""V4 Data models for AdGuard DNS filter rules.

V4 improvements over V3:
  - ``__slots__`` on Rule for memory efficiency.
  - The per-rule ``domain`` string is *not* stored — it is reconstructed on
    demand from ``_norm`` + ``wildcard`` (saves one str per rule).
  - Normalized-domain strings are ``sys.intern``-ed so dict keys and rule
    objects share the same string objects.
  - Full rich-comparison protocol via ``functools.total_ordering`` so
    ``sorted(rules)`` is deterministic and stable across runs.
  - Dedup key stays ``(normalized_domain, rule_type, wildcard)`` —
    ``*.example.com`` and ``example.com`` are *never* collapsed at dedup.
"""

from __future__ import annotations

import sys
from functools import total_ordering
from typing import Optional


# ── categories (aligned with HostlistsRegistry purpose:* tags) ──────
CATEGORY_ADS = "ads"
CATEGORY_MALWARE = "malware"
CATEGORY_TRACKING = "tracking"
CATEGORY_PHISHING = "phishing"
CATEGORY_MINING = "mining"
CATEGORY_OTHER = "other"
CATEGORY_COMMENT = "comment"

ALL_CATEGORIES = frozenset({
    CATEGORY_ADS, CATEGORY_MALWARE, CATEGORY_TRACKING,
    CATEGORY_PHISHING, CATEGORY_MINING, CATEGORY_OTHER, CATEGORY_COMMENT,
})

TIERED_CATEGORIES = (
    CATEGORY_ADS, CATEGORY_MALWARE, CATEGORY_TRACKING,
    CATEGORY_PHISHING, CATEGORY_MINING,
)


def normalize_domain(domain: str, strip_www: bool = False) -> str:
    """Lowercase, strip ``*.`` prefix, strip trailing dot, optionally strip www."""
    d = domain.lower().strip()
    if d.startswith("*."):
        d = d[2:]
    if d.endswith("."):
        d = d[:-1]
    if strip_www and d.startswith("www."):
        d = d[4:]
    return d


@total_ordering
class Rule:
    """A single DNS-layer filter rule with full provenance.

    Stored slots: ``raw``, ``rule_type``, ``wildcard``, ``sources``,
    ``category``, ``_norm``.  The ``domain`` is derived (not stored).
    """

    __slots__ = ("raw", "rule_type", "wildcard", "sources",
                 "category", "_norm")

    def __init__(
        self,
        raw: str,
        domain: str,
        rule_type: str,
        wildcard: bool,
        sources=None,
        category: str = CATEGORY_OTHER,
        strip_www: bool = False,
    ) -> None:
        self.raw = raw
        self.rule_type = rule_type
        self.wildcard = bool(wildcard)
        if sources is None:
            self.sources = ()
        elif isinstance(sources, str):
            self.sources = (sources,)
        else:
            self.sources = tuple(sources)
        self.category = category
        # intern the normalized domain so dict keys share the object
        self._norm = sys.intern(normalize_domain(domain, strip_www=strip_www))

    # ── properties ────────────────────────────────────────────────

    @property
    def domain(self) -> str:
        """Reconstruct the display domain (with *. prefix when wildcard)."""
        return f"*.{self._norm}" if self.wildcard else self._norm

    @property
    def normalized_domain(self) -> str:
        return self._norm

    @property
    def output_raw(self) -> str:
        """Canonical AdGuard line for output."""
        if self.rule_type == "comment":
            return self.raw
        # regex rules (empty domain) keep their original form
        if self._norm == "":
            return self.raw
        prefix = "@@||" if self.rule_type == "allow" else "||"
        return f"{prefix}{self.domain}^"

    # ── equality / hashing (dedup key) ────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Rule):
            return NotImplemented
        return (self._norm == other._norm
                and self.rule_type == other.rule_type
                and self.wildcard == other.wildcard)

    def __hash__(self) -> int:
        return hash((self._norm, self.rule_type, self.wildcard))

    # ── total ordering (stable sort protocol) ─────────────────────

    _TYPE_ORDER = {"block": 0, "allow": 1, "comment": 2}

    def __lt__(self, other: "Rule") -> bool:
        if not isinstance(other, Rule):
            return NotImplemented
        ta = self._TYPE_ORDER[self.rule_type]
        tb = self._TYPE_ORDER[other.rule_type]
        if ta != tb:
            return ta < tb
        if self._norm != other._norm:
            return self._norm < other._norm
        # Within same normalized domain: wildcard rule sorts first.
        if self.wildcard != other.wildcard:
            return self.wildcard and not other.wildcard
        return False  # fully ordered by earlier keys

    def __str__(self) -> str:
        return self.output_raw

    def __repr__(self) -> str:
        src = ",".join(self.sources[:2])
        if len(self.sources) > 2:
            src += ",..."
        return f"Rule({self.rule_type} {self.domain!r} [{src}])"


class SourceMeta:
    """Metadata for a rule source."""

    __slots__ = ("name", "url", "category", "enabled", "reputation", "timeout")

    def __init__(
        self,
        name: str,
        url: str,
        category: str = CATEGORY_OTHER,
        enabled: bool = True,
        reputation: float = 0.5,
        timeout: Optional[int] = None,
    ) -> None:
        self.name = name
        self.url = url
        self.category = category
        self.enabled = enabled
        self.reputation = max(0.0, min(1.0, reputation))
        self.timeout = timeout
