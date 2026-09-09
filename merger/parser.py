"""V4 streaming parser for DNS-layer AdGuard / Hosts / plain-domain lists.

V4 parsing rules (strict DNS-layer only):
  - AdGuard block:  ``||domain^``            -> block
  - AdGuard allow:  ``@@||domain^``         -> allow
  - Wildcard:       ``||*.domain^``         -> block, wildcard=True
  - Hosts:          ``0.0.0.0 domain`` / ``127.0.0.1 domain`` -> block
  - Plain domain:  ``example.com``          -> block
  - Comment:        ``! ...``              -> comment (preserved for header)
  - Drop:           ``$`` modifiers (truncate at first ``$``)
  - Drop:           CSS/JS selectors ``##..``, ``#@#..``
  - Drop:           regex rules ``/regex/``
  - Drop:           embedded-wildcard patterns like ``||*-x.com^`` or
                    ``||*tracker*.example.com^`` — DNS layer only supports
                    the leading ``*.domain.com`` wildcard form; any other
                    occurrence of ``*`` is rejected (counted as pattern_dropped).

The parser is a generator: ``parse_stream(lines)`` yields Rule objects one at
a time so the download -> parse -> dedup pipeline never materialises a whole
source in memory.
"""

from __future__ import annotations

import re
from typing import Iterator, List, Optional, Set

from .models import Rule, CATEGORY_OTHER, CATEGORY_COMMENT


class RuleParser:
    """High-performance streaming parser (keeps a pattern_dropped counter)."""

    # ── pre-compiled patterns ──────────────────────────────────
    RE_BLOCK   = re.compile(r"^\|\|([^/^\s]+)\^")
    RE_ALLOW   = re.compile(r"^@@\|\|([^/^\s]+)\^")
    RE_WILD    = re.compile(r"^\*\.")
    # hosts: any IP + hostname (not just 0.0.0.0/127.0.0.1)
    RE_HOSTS   = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+(\S+)")
    RE_DOMAIN  = re.compile(r"^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")
    RE_WILD_DOMAIN = re.compile(r"^\*\.([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")
    RE_CSS     = re.compile(r"^#@?#")
    RE_REGEX   = re.compile(r"^(?:@@)?/.+/\$?.*$")
    RE_URLBAR  = re.compile(r"^\|?https?://")

    LOCALHOST: Set[str] = frozenset({
        "localhost", "localhost.localdomain",
        "localhost6", "localhost6.localdomain6",
    })

    # Valid TLDs (common ones — keep it simple, not exhaustive)
    VALID_TLDS: Set[str] = frozenset({
        "com", "net", "org", "edu", "gov", "mil", "int",
        "cn", "io", "co", "ai", "app", "dev", "me", "tv",
        "xyz", "info", "biz", "us", "uk", "de", "fr", "jp",
        "ru", "br", "in", "au", "ca", "it", "es", "nl",
        "se", "no", "dk", "fi", "ch", "at", "be", "pl",
        "cz", "kr", "sg", "hk", "tw", "my", "id", "th",
        "vn", "ph", "tr", "il", "ae", "sa", "za", "mx",
        "ar", "cl", "co.uk", "co.jp", "co.kr", "com.cn",
        "net.cn", "org.cn", "gov.cn",
    })

    MAX_DOMAIN_LENGTH = 253  # DNS max length

    def __init__(
        self,
        strip_www: bool = False,
        quality_filter: bool = True,
        min_domain_length: int = 4,
        max_domain_length: int = 253,
        filter_localhost: bool = True,
        filter_ip_rules: bool = False,
    ) -> None:
        # count of rules dropped because they contained an embedded '*'
        # after stripping the single leading "*.":
        self.pattern_dropped: int = 0
        self.quality_dropped: int = 0
        self.strip_www = strip_www
        self.quality_filter_enabled = quality_filter
        self.min_domain_length = min_domain_length
        self.max_domain_length = max_domain_length
        self.filter_localhost = filter_localhost
        self.filter_ip_rules = filter_ip_rules

    # ── helpers ────────────────────────────────────────────────

    @staticmethod
    def _clean(domain: str) -> str:
        d = domain.lower().strip()
        if d.endswith("."):
            d = d[:-1]
        return d

    @staticmethod
    def _is_ip(text: str) -> bool:
        parts = text.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return False

    @staticmethod
    def _strip_modifiers(s: str) -> str:
        i = s.find("$")
        if i != -1:
            s = s[:i]
        return s.strip()

    def _valid_dns_domain(self, d: str) -> Optional[bool]:
        """Return True if d is a clean DNS domain (no embedded '*').

        The single leading ``*.`` is accepted (wildcard); any other ``*``
        makes the rule unsupported at the DNS layer.
        """
        if "*" not in d:
            return True
        # only a leading "*." is allowed
        return d.startswith("*.") and "*" not in d[2:]

    def _quality_check(self, d: str) -> bool:
        """Return True if domain passes quality checks."""
        if not self.quality_filter_enabled:
            return True

        # strip wildcard prefix for checks
        check_d = d[2:] if d.startswith("*.") else d

        # too short
        if len(check_d) < self.min_domain_length:
            return False

        # too long
        if len(check_d) > self.max_domain_length:
            return False

        # localhost related
        if self.filter_localhost:
            if check_d in self.LOCALHOST or check_d.endswith(".localhost"):
                return False

        # IP rules
        if self.filter_ip_rules:
            parts = check_d.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return False

        # must have at least one dot (not a TLD itself)
        if "." not in check_d:
            return False

        # all parts must be non-empty
        parts = check_d.split(".")
        if any(not p for p in parts):
            return False

        return True

    # ── single-line parse ──────────────────────────────────────

    def parse_line(
        self,
        line: str,
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> Optional[Rule]:
        if not line:
            return None
        s = line.strip()
        if not s:
            return None

        if s.startswith("!"):
            return Rule(raw=s, domain="", rule_type="comment",
                        wildcard=False, sources=source, category=CATEGORY_COMMENT)

        if self.RE_CSS.match(s) or self.RE_URLBAR.match(s):
            return None

        # regex rules are supported by AGH — keep them as-is
        if self.RE_REGEX.match(s):
            rule_type = "allow" if s.startswith("@@") else "block"
            return Rule(raw=s, domain="", rule_type=rule_type,
                        wildcard=False, sources=source,
                        category=category, strip_www=self.strip_www)

        s = self._strip_modifiers(s)
        if not s:
            return None

        # allow: @@||domain^
        m = self.RE_ALLOW.match(s)
        if m:
            d = self._clean(m.group(1))
            if not d or not self._valid_dns_domain(d):
                if d and "*" in d:
                    self.pattern_dropped += 1
                return None
            if not self._quality_check(d):
                self.quality_dropped += 1
                return None
            return Rule(raw=f"@@||{d}^", domain=d, rule_type="allow",
                        wildcard=self.RE_WILD.match(d) is not None,
                        sources=source, category=category,
                        strip_www=self.strip_www)

        # block: ||domain^
        m = self.RE_BLOCK.match(s)
        if m:
            d = self._clean(m.group(1))
            if not d or not self._valid_dns_domain(d):
                if d and "*" in d:
                    self.pattern_dropped += 1
                return None
            if not self._quality_check(d):
                self.quality_dropped += 1
                return None
            return Rule(raw=f"||{d}^", domain=d, rule_type="block",
                        wildcard=self.RE_WILD.match(d) is not None,
                        sources=source, category=category,
                        strip_www=self.strip_www)

        # hosts: any IP + hostname (0.0.0.0, 127.0.0.1, or other)
        m = self.RE_HOSTS.match(s)
        if m:
            d = self._clean(m.group(1))
            if d in self.LOCALHOST or "*" in d:
                if "*" in d:
                    self.pattern_dropped += 1
                return None
            if not self._quality_check(d):
                self.quality_dropped += 1
                return None
            return Rule(raw=f"||{d}^", domain=d, rule_type="block",
                        wildcard=False, sources=source, category=category,
                        strip_www=self.strip_www)

        # plain domain with wildcard: *.example.com
        if self.RE_WILD_DOMAIN.match(s) and not self._is_ip(s):
            d = self._clean(s)
            if not self._quality_check(d):
                self.quality_dropped += 1
                return None
            return Rule(raw=f"||{d}^", domain=d, rule_type="block",
                        wildcard=True, sources=source, category=category,
                        strip_www=self.strip_www)

        # plain domain
        if self.RE_DOMAIN.match(s) and not self._is_ip(s):
            d = self._clean(s)
            if not self._quality_check(d):
                self.quality_dropped += 1
                return None
            return Rule(raw=f"||{d}^", domain=d, rule_type="block",
                        wildcard=False, sources=source, category=category,
                        strip_www=self.strip_www)

        return None

    # ── streaming parse ─────────────────────────────────────────

    def parse_stream(
        self,
        lines: Iterator[str],
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> Iterator[Rule]:
        """Yield Rule objects from a line iterator, one at a time."""
        re_block = self.RE_BLOCK.match
        re_allow = self.RE_ALLOW.match
        re_hosts = self.RE_HOSTS.match
        re_plain = self.RE_DOMAIN.match
        re_wild_plain = self.RE_WILD_DOMAIN.match
        re_css = self.RE_CSS.match
        re_regex = self.RE_REGEX.match
        re_urlbar = self.RE_URLBAR.match
        re_wild = self.RE_WILD.match
        clean = self._clean
        is_ip = self._is_ip
        localhost = self.LOCALHOST
        strip_mod = self._strip_modifiers
        valid_dns = self._valid_dns_domain
        quality_check = self._quality_check
        RuleCls = Rule
        cat_comment = CATEGORY_COMMENT
        strip_www = self.strip_www

        for line in lines:
            if not line:
                continue
            s = line.strip()
            if not s:
                continue

            if s.startswith("!"):
                yield RuleCls(raw=s, domain="", rule_type="comment",
                              wildcard=False, sources=source,
                              category=cat_comment, strip_www=strip_www)
                continue

            if re_css(s) or re_urlbar(s):
                continue

            # regex rules are supported by AGH — keep them as-is
            if re_regex(s):
                rule_type = "allow" if s.startswith("@@") else "block"
                yield RuleCls(raw=s, domain="", rule_type=rule_type,
                              wildcard=False, sources=source,
                              category=category, strip_www=strip_www)
                continue

            s2 = strip_mod(s)
            if not s2:
                continue

            m = re_allow(s2)
            if m:
                d = clean(m.group(1))
                if d and valid_dns(d) and quality_check(d):
                    yield RuleCls(raw=f"@@||{d}^", domain=d, rule_type="allow",
                                  wildcard=re_wild(d) is not None,
                                  sources=source, category=category,
                                  strip_www=strip_www)
                elif d and "*" in d:
                    self.pattern_dropped += 1
                elif d:
                    self.quality_dropped += 1
                continue

            m = re_block(s2)
            if m:
                d = clean(m.group(1))
                if d and valid_dns(d) and quality_check(d):
                    yield RuleCls(raw=f"||{d}^", domain=d, rule_type="block",
                                  wildcard=re_wild(d) is not None,
                                  sources=source, category=category,
                                  strip_www=strip_www)
                elif d and "*" in d:
                    self.pattern_dropped += 1
                elif d:
                    self.quality_dropped += 1
                continue

            m = re_hosts(s2)
            if m:
                d = clean(m.group(1))
                if d in localhost or "*" in d:
                    if "*" in d:
                        self.pattern_dropped += 1
                    continue
                if quality_check(d):
                    yield RuleCls(raw=f"||{d}^", domain=d, rule_type="block",
                                  wildcard=False, sources=source, category=category,
                                  strip_www=strip_www)
                else:
                    self.quality_dropped += 1
                continue

            # plain domain with wildcard: *.example.com
            if re_wild_plain(s2) and not is_ip(s2):
                d = clean(s2)
                if quality_check(d):
                    yield RuleCls(raw=f"||{d}^", domain=d, rule_type="block",
                                  wildcard=True, sources=source, category=category,
                                  strip_www=strip_www)
                else:
                    self.quality_dropped += 1
                continue

            if re_plain(s2) and not is_ip(s2):
                d = clean(s2)
                if quality_check(d):
                    yield RuleCls(raw=f"||{d}^", domain=d, rule_type="block",
                                  wildcard=False, sources=source, category=category,
                                  strip_www=strip_www)
                else:
                    self.quality_dropped += 1
                continue

    # ── bulk (small files / tests) ─────────────────────────────

    def parse_text(
        self,
        text: str,
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> List[Rule]:
        return list(self.parse_stream(iter(text.splitlines()), source, category))
