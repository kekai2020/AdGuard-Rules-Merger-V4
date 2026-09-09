"""AdGuard Rules Merger V4 — DNS-layer rule compiler.

Pipeline: multi-source fetch -> parse -> dedup -> upward aggregation ->
whitelist split -> conflict resolution -> stable sort -> multi-format export.
"""

from .cache import SourceCache, CacheEntry
from .core import AsyncRuleEngine, MergeOutcome
from .exporter import Exporter
from .models import (
    Rule, SourceMeta,
    CATEGORY_ADS, CATEGORY_MALWARE, CATEGORY_TRACKING,
    CATEGORY_PHISHING, CATEGORY_MINING, CATEGORY_OTHER, CATEGORY_COMMENT,
)
from .parser import RuleParser

__version__ = "4.0.0"
__all__ = [
    "AsyncRuleEngine", "MergeOutcome", "Exporter",
    "Rule", "SourceMeta", "RuleParser", "SourceCache", "CacheEntry",
    "CATEGORY_ADS", "CATEGORY_MALWARE", "CATEGORY_TRACKING",
    "CATEGORY_PHISHING", "CATEGORY_MINING", "CATEGORY_OTHER", "CATEGORY_COMMENT",
    "__version__",
]
