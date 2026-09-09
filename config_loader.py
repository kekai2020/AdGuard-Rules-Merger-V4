"""V4 configuration loader — pydantic v2 validated YAML config."""

from __future__ import annotations

from pathlib import Path
from typing import List

import yaml
from pydantic import BaseModel, Field, model_validator


class SourceConfig(BaseModel):
    name: str
    url: str
    enabled: bool = True
    category: str = "other"
    reputation: float = Field(default=0.5, ge=0.0, le=1.0)
    timeout: int | None = None


class CacheConfig(BaseModel):
    enabled: bool = True
    directory: str = "cache"
    ttl_seconds: int = Field(default=0, ge=0)
    max_size_mb: int = Field(default=500, ge=0)


class QualityFilterConfig(BaseModel):
    enabled: bool = True
    min_domain_length: int = Field(default=4, ge=1, le=100)
    max_domain_length: int = Field(default=253, ge=10, le=500)
    filter_localhost: bool = True
    filter_ip_rules: bool = False


class AggregationConfig(BaseModel):
    enabled: bool = True
    min_aggregator_labels: int = Field(default=2, ge=1, le=5)


class ConflictResolutionConfig(BaseModel):
    enabled: bool = True
    cascade_subdomains: bool = True


class DownloadConfig(BaseModel):
    user_agent: str = "AdGuard-Rules-Merger/4.0"
    retry_count: int = Field(default=2, ge=0, le=5)
    retry_delay: float = Field(default=1.5, ge=0.1, le=10.0)


class OutputConfig(BaseModel):
    directory: str = "output"
    formats: List[str] = Field(
        default_factory=lambda: [
            "adguard", "whitelist", "hosts", "domains",
            "clash", "surge", "smartdns",
        ]
    )
    tiered: bool = True
    report: bool = True

    @model_validator(mode="after")
    def _check_formats(self) -> "OutputConfig":
        valid = {
            "adguard", "whitelist", "hosts", "domains",
            "clash", "surge", "smartdns",
        }
        invalid = set(self.formats) - valid
        if invalid:
            raise ValueError(
                f"Invalid output formats: {invalid}. "
                f"Valid options: {valid}"
            )
        return self


class DedupConfig(BaseModel):
    strip_www: bool = False
    normalize_case: bool = True
    normalize_trailing_dot: bool = True


class MergeConfig(BaseModel):
    sources: List[SourceConfig] = Field(default_factory=list)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    dedup: DedupConfig = Field(default_factory=DedupConfig)
    quality_filter: QualityFilterConfig = Field(default_factory=QualityFilterConfig)
    aggregation: AggregationConfig = Field(default_factory=AggregationConfig)
    conflict_resolution: ConflictResolutionConfig = Field(default_factory=ConflictResolutionConfig)
    download: DownloadConfig = Field(default_factory=DownloadConfig)
    timeout: int = Field(default=60, ge=1)
    max_concurrency: int = Field(default=50, ge=1, le=200)

    @model_validator(mode="after")
    def _check(self) -> "MergeConfig":
        enabled = [s for s in self.sources if s.enabled]
        if not enabled:
            raise ValueError("At least one enabled source is required")
        urls = [s.url for s in enabled]
        if len(urls) != len(set(urls)):
            raise ValueError(f"Duplicate source URLs detected: {len(urls) - len(set(urls))} duplicates")
        # validate categories
        valid_cats = {"ads", "malware", "tracking", "phishing", "mining", "other"}
        invalid_cats = set(s.category for s in enabled) - valid_cats
        if invalid_cats:
            raise ValueError(f"Invalid categories: {invalid_cats}. Valid: {valid_cats}")
        return self


def load_config(path: str) -> MergeConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    try:
        return MergeConfig(**raw)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Config validation failed: {e}") from e


def load_source_metas(path: str):
    from merger.models import SourceMeta
    cfg = load_config(path)
    return [
        SourceMeta(name=s.name, url=s.url, category=s.category,
                   enabled=s.enabled, reputation=s.reputation, timeout=s.timeout)
        for s in cfg.sources if s.enabled
    ]


def validate_config(path: str) -> List[str]:
    try:
        load_config(path)
        return []
    except (FileNotFoundError, ValueError) as e:
        return [str(e)]
