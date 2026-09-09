"""V4 professional analysis report generator.

Generates a comprehensive HTML report after each merge run, including:
  - Executive summary (key metrics at a glance)
  - Rule type distribution (domain / wildcard / regex / IP)
  - Category breakdown (ads / malware / tracking / phishing / mining)
  - Optimization pipeline funnel (raw → dedup → aggregate → conflicts)
  - Top domain suffixes (Top 20)
  - Source contribution analysis
  - Output format comparison
  - Performance metrics
  - Rule grammar coverage matrix
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .models import Rule


# ── analysis helpers ──────────────────────────────────────────────

def _classify_rule(rule: Rule) -> str:
    """Classify a rule by its syntax type."""
    if rule.normalized_domain == "":
        return "regex"
    if rule.wildcard:
        return "wildcard"
    # check if it's an IP address
    parts = rule.normalized_domain.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    return "domain"


def _extract_suffix(domain: str) -> str:
    """Extract the registrable suffix (e.g. example.com → com, foo.co.uk → co.uk)."""
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    # handle common second-level ccTLDs
    second_level_cc = {"co", "com", "net", "org", "gov", "edu"}
    if len(parts) >= 3 and parts[-2] in second_level_cc and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyze_rules(blocks: List[Rule], allows: List[Rule]) -> Dict[str, Any]:
    """Run full analysis on the rule set."""
    all_rules = blocks + allows

    # rule type distribution
    type_counts = Counter(_classify_rule(r) for r in all_rules)

    # category distribution
    cat_counts = Counter(r.category for r in blocks)

    # suffix distribution (Top 20)
    suffix_counts = Counter()
    domain_lengths = []
    for r in blocks:
        if r.normalized_domain:
            suffix = _extract_suffix(r.normalized_domain)
            suffix_counts[suffix] += 1
            domain_lengths.append(len(r.normalized_domain))

    top_suffixes = suffix_counts.most_common(20)

    # whitelist analysis
    allow_types = Counter(_classify_rule(r) for r in allows)

    return {
        "rule_types": dict(type_counts),
        "categories": dict(cat_counts),
        "top_suffixes": top_suffixes,
        "allow_types": dict(allow_types),
        "avg_domain_length": sum(domain_lengths) / len(domain_lengths) if domain_lengths else 0,
        "max_domain_length": max(domain_lengths) if domain_lengths else 0,
        "min_domain_length": min(domain_lengths) if domain_lengths else 0,
    }


# ── HTML report generator ──────────────────────────────────────────

def generate_html_report(
    blocks: List[Rule],
    allows: List[Rule],
    outcome: Any,
    analysis: Dict[str, Any],
) -> str:
    """Generate a full HTML analysis report as a string."""

    now = datetime.now()
    generated_at = now.isoformat()

    # key metrics
    total_block = len(blocks)
    total_allow = len(allows)
    raw_count = outcome.raw_count
    dedup_rate = (1 - (total_block + total_allow) / raw_count) * 100 if raw_count else 0

    # categories
    cats = analysis["categories"]

    # top suffixes for charts
    top_suffix_labels = [s[0] for s in analysis["top_suffixes"]]
    top_suffix_values = [s[1] for s in analysis["top_suffixes"]]

    # rule type data
    rt = analysis["rule_types"]
    domain_count = rt.get("domain", 0)
    wildcard_count = rt.get("wildcard", 0)
    regex_count = rt.get("regex", 0)
    ip_count = rt.get("ip", 0)

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AdGuard Rules Merger V4 - 规则分析报告</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 1280px; margin: 0 auto; padding: 20px; }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        .header h1 {{ font-size: 2.2em; margin-bottom: 8px; }}
        .header .subtitle {{ opacity: 0.9; font-size: 1.1em; }}
        .header .meta {{ margin-top: 15px; font-size: 0.9em; opacity: 0.8; }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); }}
        .stat-card .value {{ font-size: 1.8em; font-weight: 700; color: #2a5298; }}
        .stat-card .label {{ color: #666; font-size: 0.85em; margin-top: 4px; }}

        .section {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            margin-bottom: 25px;
        }}
        .section h2 {{
            margin-bottom: 20px;
            color: #1e3c72;
            border-left: 4px solid #2a5298;
            padding-left: 15px;
            font-size: 1.3em;
        }}

        .two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 25px;
        }}
        @media (max-width: 768px) {{ .two-col {{ grid-template-columns: 1fr; }} }}

        .chart {{ width: 100%; height: 350px; }}

        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #555; }}
        tr:hover {{ background: #f8f9fa; }}

        .tag {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.82em;
            font-weight: 500;
        }}
        .tag-green {{ background: #d4edda; color: #155724; }}
        .tag-blue {{ background: #d1ecf1; color: #0c5460; }}
        .tag-yellow {{ background: #fff3cd; color: #856404; }}
        .tag-red {{ background: #f8d7da; color: #721c24; }}

        .funnel-step {{
            display: flex;
            align-items: center;
            padding: 12px 15px;
            margin: 8px 0;
            border-radius: 8px;
            background: #f8f9fa;
        }}
        .funnel-step .step-name {{ flex: 1; font-weight: 500; }}
        .funnel-step .step-count {{ font-weight: 700; color: #2a5298; }}
        .funnel-step .step-diff {{ width: 100px; text-align: right; color: #28a745; font-size: 0.9em; }}

        .footer {{
            text-align: center;
            color: #999;
            padding: 20px;
            font-size: 0.85em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AdGuard Rules Merger V4</h1>
            <div class="subtitle">专业规则合并分析报告</div>
            <div class="meta">生成时间：{generated_at[:19].replace('T', ' ')} | 源：{outcome.sources_ok}/{outcome.sources_total} | 版本：V4.0.0</div>
        </div>

        <!-- 核心指标 -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{total_block:,}</div>
                <div class="label">Block 规则总数</div>
            </div>
            <div class="stat-card">
                <div class="value">{total_allow:,}</div>
                <div class="label">Allow 白名单</div>
            </div>
            <div class="stat-card">
                <div class="value">{dedup_rate:.1f}%</div>
                <div class="label">综合去重率</div>
            </div>
            <div class="stat-card">
                <div class="value">{outcome.aggregated:,}</div>
                <div class="label">向上聚合</div>
            </div>
            <div class="stat-card">
                <div class="value">{outcome.conflict_resolved:,}</div>
                <div class="label">冲突消解</div>
            </div>
            <div class="stat-card">
                <div class="value">{outcome.elapsed:.1f}s</div>
                <div class="label">总耗时</div>
            </div>
        </div>

        <!-- 优化流水线漏斗 -->
        <div class="section">
            <h2>📊 优化流水线漏斗</h2>
            <div class="funnel-step">
                <div class="step-name">原始规则（Raw）</div>
                <div class="step-count">{raw_count:,}</div>
                <div class="step-diff">-</div>
            </div>
            <div class="funnel-step">
                <div class="step-name">精确去重后</div>
                <div class="step-count">{raw_count - outcome.exact_merged:,}</div>
                <div class="step-diff">-{outcome.exact_merged:,}</div>
            </div>
            <div class="funnel-step">
                <div class="step-name">向上聚合后</div>
                <div class="step-count">{raw_count - outcome.exact_merged - outcome.aggregated:,}</div>
                <div class="step-diff">-{outcome.aggregated:,}</div>
            </div>
            <div class="funnel-step">
                <div class="step-name">冲突消解后</div>
                <div class="step-count">{total_block + total_allow:,}</div>
                <div class="step-diff">-{outcome.conflict_resolved:,}</div>
            </div>
        </div>

        <!-- 规则类型 + 类别分布 -->
        <div class="two-col">
            <div class="section">
                <h2>📋 规则类型分布</h2>
                <div id="ruleTypeChart" class="chart"></div>
            </div>
            <div class="section">
                <h2>🏷️ 类别分布</h2>
                <div id="categoryChart" class="chart"></div>
            </div>
        </div>

        <!-- 域名后缀 Top 20 -->
        <div class="section">
            <h2>🌐 域名后缀 Top 20</h2>
            <div id="suffixChart" class="chart" style="height: 450px;"></div>
        </div>

        <!-- 规则语法支持度 -->
        <div class="section">
            <h2>📝 规则语法支持度矩阵</h2>
            <table>
                <thead>
                    <tr>
                        <th>规则类型</th>
                        <th>语法示例</th>
                        <th>支持状态</th>
                        <th>处理方式</th>
                        <th>数量</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Block 规则</td>
                        <td><code>||example.com^</code></td>
                        <td><span class="tag tag-green">✅ 支持</span></td>
                        <td>核心输出</td>
                        <td>{domain_count:,}</td>
                    </tr>
                    <tr>
                        <td>通配符 Block</td>
                        <td><code>||*.example.com^</code></td>
                        <td><span class="tag tag-green">✅ 支持</span></td>
                        <td>向上聚合覆盖子域</td>
                        <td>{wildcard_count:,}</td>
                    </tr>
                    <tr>
                        <td>Allow 白名单</td>
                        <td><code>@@||example.com^</code></td>
                        <td><span class="tag tag-green">✅ 支持</span></td>
                        <td>分离到 whitelist.txt</td>
                        <td>{total_allow:,}</td>
                    </tr>
                    <tr>
                        <td>正则规则</td>
                        <td><code>/ads.*/</code></td>
                        <td><span class="tag tag-blue">✅ 回收</span></td>
                        <td>原样保留（AGH 支持）</td>
                        <td>{regex_count:,}</td>
                    </tr>
                    <tr>
                        <td>IP 规则</td>
                        <td><code>||8.8.8.8^</code></td>
                        <td><span class="tag tag-blue">✅ 支持</span></td>
                        <td>按域名字符串处理</td>
                        <td>{ip_count:,}</td>
                    </tr>
                    <tr>
                        <td>Hosts 格式</td>
                        <td><code>0.0.0.0 example.com</code></td>
                        <td><span class="tag tag-green">✅ 支持</span></td>
                        <td>转换为 ||domain^</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td>$ 修饰符</td>
                        <td><code>||example.com^$third-party</code></td>
                        <td><span class="tag tag-yellow">⚠️ 截断</span></td>
                        <td>保留域名，丢弃修饰符</td>
                        <td>{outcome.pattern_dropped:,}</td>
                    </tr>
                    <tr>
                        <td>CSS 选择器</td>
                        <td><code>##.ad-banner</code></td>
                        <td><span class="tag tag-red">❌ 丢弃</span></td>
                        <td>DNS 层不支持</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td>JS 注入</td>
                        <td><code>#%#scriptlet(...)</code></td>
                        <td><span class="tag tag-red">❌ 丢弃</span></td>
                        <td>DNS 层不支持</td>
                        <td>-</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- 性能 + 输出 -->
        <div class="two-col">
            <div class="section">
                <h2>⚡ 性能指标</h2>
                <table>
                    <tr><td>总耗时</td><td><strong>{outcome.elapsed:.1f}s</strong></td></tr>
                    <tr><td>源成功率</td><td>{outcome.sources_ok}/{outcome.sources_total} ({outcome.sources_ok/outcome.sources_total*100:.0f}%)</td></tr>
                    <tr><td>缓存命中</td><td>{outcome.sources_cached}/{outcome.sources_total}</td></tr>
                    <tr><td>精确去重</td><td>{outcome.exact_merged:,}</td></tr>
                    <tr><td>模式规则丢弃</td><td>{outcome.pattern_dropped:,}</td></tr>
                </table>
            </div>
            <div class="section">
                <h2>📦 输出格式</h2>
                <table>
                    <tr><td>merged_rules.txt</td><td>AdGuard 格式</td></tr>
                    <tr><td>whitelist.txt</td><td>白名单</td></tr>
                    <tr><td>hosts.txt</td><td>Hosts 格式</td></tr>
                    <tr><td>domains.txt</td><td>纯域名列表</td></tr>
                    <tr><td>clash.yaml</td><td>Clash 规则集</td></tr>
                    <tr><td>surge.list</td><td>Surge 规则集</td></tr>
                    <tr><td>smartdns.conf</td><td>SmartDNS 配置</td></tr>
                </table>
            </div>
        </div>

        <!-- 域名统计 -->
        <div class="section">
            <h2>📏 域名长度统计</h2>
            <table>
                <tr><td>平均域名长度</td><td>{analysis['avg_domain_length']:.1f} 字符</td></tr>
                <tr><td>最短域名</td><td>{analysis['min_domain_length']} 字符</td></tr>
                <tr><td>最长域名</td><td>{analysis['max_domain_length']} 字符</td></tr>
            </table>
        </div>

        <div class="footer">
            AdGuard Rules Merger V4 · 自动生成 · {generated_at[:10]}
        </div>
    </div>

    <script>
        // 规则类型饼图
        const ruleTypeChart = echarts.init(document.getElementById('ruleTypeChart'));
        ruleTypeChart.setOption({{
            tooltip: {{ trigger: 'item' }},
            legend: {{ bottom: 0 }},
            series: [{{
                type: 'pie',
                radius: ['40%', '70%'],
                data: [
                    {{ value: {domain_count}, name: '普通域名', itemStyle: {{ color: '#2a5298' }} }},
                    {{ value: {wildcard_count}, name: '通配符', itemStyle: {{ color: '#6ab04c' }} }},
                    {{ value: {regex_count}, name: '正则', itemStyle: {{ color: '#f0932b' }} }},
                    {{ value: {ip_count}, name: 'IP', itemStyle: {{ color: '#eb4d4b' }} }},
                ],
                label: {{ formatter: '{{b}}\\n{{d}}%' }}
            }}]
        }});

        // 类别柱状图
        const categoryChart = echarts.init(document.getElementById('categoryChart'));
        const catData = {json.dumps(cats)};
        const catLabels = Object.keys(catData);
        const catValues = Object.values(catData);
        categoryChart.setOption({{
            tooltip: {{ trigger: 'axis' }},
            grid: {{ left: '3%', right: '4%', bottom: '3%', containLabel: true }},
            xAxis: {{ type: 'category', data: catLabels, axisLabel: {{ rotate: 30 }} }},
            yAxis: {{ type: 'value' }},
            series: [{{
                type: 'bar',
                data: catValues,
                itemStyle: {{
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        {{ offset: 0, color: '#2a5298' }},
                        {{ offset: 1, color: '#1e3c72' }}
                    ])
                }}
            }}]
        }});

        // 域名后缀 Top 20
        const suffixChart = echarts.init(document.getElementById('suffixChart'));
        suffixChart.setOption({{
            tooltip: {{ trigger: 'axis' }},
            grid: {{ left: '3%', right: '4%', bottom: '3%', containLabel: true }},
            xAxis: {{ type: 'value' }},
            yAxis: {{
                type: 'category',
                data: {json.dumps(list(reversed(top_suffix_labels)))},
            }},
            series: [{{
                type: 'bar',
                data: {json.dumps(list(reversed(top_suffix_values)))},
                itemStyle: {{ color: '#2a5298' }}
            }}]
        }});

        // 响应式
        window.addEventListener('resize', () => {{
            ruleTypeChart.resize();
            categoryChart.resize();
            suffixChart.resize();
        }});
    </script>
</body>
</html>"""
    return html
