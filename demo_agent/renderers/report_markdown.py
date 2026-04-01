from typing import Any, Dict, List, Optional


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _text(value: Any) -> str:
    return str(value or "").strip()


def _confidence_phrase(confidence: int) -> str:
    if confidence >= 80:
        return "较高"
    if confidence >= 60:
        return "中等"
    return "有限"


def _synthesized_url(item: Dict[str, Any], analysis: Dict[str, Any]) -> Optional[str]:
    url = _text(item.get("url"))
    if url:
        return url

    event = analysis.get("event") or {}
    local_intel = analysis.get("local_intel") or {}
    best = local_intel.get("best_match") or {}
    fp = event.get("trigger_fingerprint") or {}

    source = _text(item.get("source")).lower()
    kind = _text(item.get("kind"))

    if kind == "local_intel" and source == "sslbl":
        indicator_type = _text(best.get("indicator_type")).lower()
        indicator_value = _text(best.get("indicator_value"))
        if indicator_type in {"ja3", "ja3_md5"} and indicator_value:
            return f"https://sslbl.abuse.ch/ja3-fingerprints/{indicator_value}/"

    if source == "virustotal" and _text(fp.get("type")).upper() == "IP":
        ip_value = _text(item.get("query")) or _text(fp.get("value"))
        if ip_value:
            return f"https://www.virustotal.com/gui/ip-address/{ip_value}"

    return None


def _format_reference(label: str, url: Optional[str]) -> str:
    if not url:
        return label
    return f"[{label}]({url})"


def _looks_mostly_ascii(text: str) -> bool:
    text = _text(text)
    if not text:
        return False
    ascii_chars = sum(1 for ch in text if ord(ch) < 128)
    return ascii_chars / max(len(text), 1) > 0.85


def _short_text(text: str, limit: int = 120) -> str:
    text = _text(text)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _family_name(analysis: Dict[str, Any]) -> str:
    assessment = analysis.get("assessment") or {}
    return _text(assessment.get("family")) or "该家族"


def _localized_claim(item: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    claim = _text(item.get("claim"))
    if not claim:
        return claim
    if not _looks_mostly_ascii(claim):
        return claim

    source = _text(item.get("source")).lower()
    title = _text(item.get("title"))
    family = _family_name(analysis)
    fp = (analysis.get("event") or {}).get("trigger_fingerprint") or {}
    fp_type = _text(fp.get("type"))
    fp_value = _text(fp.get("value"))

    if source == "virustotal":
        return f"VirusTotal 提供了指标 `{fp_value}` 的信誉与基础归属信息，可作为该事件风险判断的辅助依据。"
    if source in {"sslbl", "ja4db"}:
        return f"{source.upper()} 将 {fp_type} 指标 `{fp_value}` 关联到 `{family}`。"
    if "malpedia" in source:
        return f"Malpedia 将 `{family}` 描述为已知恶意软件家族，并提供了相应家族背景信息。"
    if "microsoft.com" in source:
        return f"Microsoft 威胁百科页面给出了与 `{family}` 相关的检测说明和威胁描述。"
    if "trendmicro.com" in source:
        return f"Trend Micro 的研究文章提到了与 `{family}` 相关的攻击活动或投递方式。"
    if "checkpoint.com" in source:
        return f"Check Point 的公开资料对 `{family}` 的功能和危害进行了概述。"
    if "bitsight.com" in source:
        return f"Bitsight 的研究内容提到了 `{family}` 的传播或运营活动。"
    if "malwarebytes.com" in source:
        return f"Malwarebytes 的检测页面将相关样本归入 `{family}` 并给出简要说明。"
    if "proofpoint.com" in source:
        return f"Proofpoint 的研究内容提供了与 `{family}` 相关的威胁活动线索。"
    if "infosecurity-magazine.com" in source:
        return f"该资讯文章提到了与 `{family}` 相关的最新攻击活动或传播方式。"
    if "spamhaus.org" in source:
        return f"Spamhaus 的研究文章涉及 `{family}` 的网络活动与阻断思路。"
    if "bazaar.abuse.ch" in source:
        return f"MalwareBazaar 页面展示了与 `{family}` 相关的恶意软件家族归类信息。"
    if "any.run" in source:
        return f"ANY.RUN 沙箱报告显示相关样本存在恶意行为，并与 `{family}` 线索相符。"
    if "ja4db.com" in source:
        return f"JA4DB 页面将该 JA4 指纹与 `{family}` 关联，可作为本地命中的外部补充佐证。"
    if "github.com" in source:
        return f"GitHub 页面包含与 `{family}` 或该指纹相关的映射/项目资料，可作为辅助参考。"
    if "reddit.com" in source:
        return f"社区讨论中提到了与 `{family}` 相关的感染或处置经历，仅适合作为低权重参考。"

    short = _short_text(claim, 100)
    if title:
        return f"该来源页面《{title}》提到了与 `{family}` 或指标 `{fp_value}` 相关的信息：{short}"
    return f"该来源提到了与 `{family}` 或指标 `{fp_value}` 相关的信息：{short}"


def _material_uncertainties(analysis: Dict[str, Any]) -> List[str]:
    assessment = analysis.get("assessment") or {}
    corroboration = analysis.get("corroboration") or {}
    local_intel = analysis.get("local_intel") or {}
    uncertainties: List[str] = []

    if local_intel.get("error"):
        uncertainties.append("本地指纹情报查询未成功返回完整结果，部分结论未能获得本地库补充。")

    if assessment.get("family") == "Unknown":
        uncertainties.append("当前自动化情报不足以稳定归因到明确恶意软件家族。")

    if corroboration.get("conflict"):
        uncertainties.append("本地情报与外部情报出现不同家族线索，当前归因应结合人工复核审慎使用。")

    return uncertainties


def _conclusion_lines(analysis: Dict[str, Any]) -> List[str]:
    event = analysis.get("event") or {}
    assessment = analysis.get("assessment") or {}
    corroboration = analysis.get("corroboration") or {}
    local_intel = analysis.get("local_intel") or {}
    confidence = _coerce_int(assessment.get("confidence"), 0)
    family = _text(assessment.get("family")) or "Unknown"
    fp = event.get("trigger_fingerprint") or {}
    src = event.get("src") or {}
    dst = event.get("dst") or {}

    lines = [
        (
            f"在 {event.get('event_time')}，检测到 {src.get('ip')} 与 {dst.get('ip')} 之间存在 "
            f"{event.get('protocol')} 流量，该流量命中 {fp.get('type')} 指标 `{fp.get('value')}`。"
        )
    ]

    if family != "Unknown":
        if local_intel.get("matched") and corroboration.get("supported_by_external"):
            lines.append(
                f"结合本地指纹情报与外部公开情报，当前将该事件关联到 `{family}` 的把握为{_confidence_phrase(confidence)}。"
            )
        elif local_intel.get("matched"):
            lines.append(
                f"本地指纹情报将该指标关联到 `{family}`，当前未发现明显冲突信息，建议将其作为优先研判方向。"
            )
        else:
            lines.append(
                f"当前家族线索主要来自告警附带标签和外部情报，现阶段更倾向于将该事件关联到 `{family}`。"
            )
    else:
        lines.append("当前已确认该事件具备可疑恶意流量特征，但自动化情报尚不足以稳定归因到明确家族。")

    return lines


def _key_evidence(analysis: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = list(analysis.get("evidence") or [])
    priority = {
        "local_intel": 0,
        "enrichment": 1,
        "family_intel": 2,
        "search_result": 3,
        "supplemental": 4,
        "hint": 5,
    }
    filtered = [item for item in evidence if item.get("kind") != "event"]
    filtered.sort(
        key=lambda item: (
            priority.get(_text(item.get("kind")), 9),
            -_coerce_int(item.get("weight"), 0),
            -_coerce_int(item.get("confidence"), 0),
        )
    )
    return filtered[:limit]


def _background_evidence(analysis: Dict[str, Any], limit: int = 3) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = list(analysis.get("evidence") or [])
    background: List[Dict[str, Any]] = []
    for item in evidence:
        kind = _text(item.get("kind"))
        if kind not in {"family_intel", "search_result", "supplemental"}:
            continue
        claim = _text(item.get("claim"))
        title = _text(item.get("title"))
        if claim or title:
            background.append(item)
    background.sort(key=lambda item: (-_coerce_int(item.get("weight"), 0), title if (title := _text(item.get("title"))) else ""))
    return background[:limit]


def _reference_items(analysis: Dict[str, Any], limit: int = 6) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    seen = set()
    for item in _key_evidence(analysis, limit=10):
        url = _synthesized_url(item, analysis)
        title = _text(item.get("title")) or _text(item.get("source")) or "相关情报"
        key = (title, url)
        if key in seen:
            continue
        seen.add(key)
        refs.append({"title": title, "url": url, "source": _text(item.get("source")), "claim": _text(item.get("claim"))})
        if len(refs) >= limit:
            break
    return refs


def render_report_from_analysis(analysis: Dict[str, Any]) -> str:
    event = analysis.get("event") or {}
    assessment = analysis.get("assessment") or {}
    local_intel = analysis.get("local_intel") or {}
    actions: List[Dict[str, Any]] = list(analysis.get("recommended_actions") or [])
    family = _text(assessment.get("family")) or "Unknown"
    confidence = _coerce_int(assessment.get("confidence"), 0)
    severity = _text(assessment.get("severity"))
    fp = event.get("trigger_fingerprint") or {}

    lines: List[str] = ["# 网络安全事件分析报告", ""]

    lines.append("## 事件概述")
    lines.append(f"- 事件时间：{event.get('event_time')}")
    lines.append(f"- 通信关系：`{(event.get('src') or {}).get('ip')}` -> `{(event.get('dst') or {}).get('ip')}`")
    lines.append(f"- 协议：{event.get('protocol')}")
    lines.append(f"- 命中指标：{fp.get('type')} `{fp.get('value')}`")
    lines.append(f"- 当前研判：{family if family != 'Unknown' else '可疑恶意流量'}")
    lines.append(f"- 置信度：{confidence}")
    lines.append(f"- 严重度：{severity}")
    lines.append("")

    lines.append("## 研判结论")
    for line in _conclusion_lines(analysis):
        lines.append(line)
        lines.append("")

    lines.append("## 关键证据与情报")
    key_items = _key_evidence(analysis)
    if key_items:
        for item in key_items:
            title = _text(item.get("title")) or _text(item.get("source")) or "相关证据"
            source = _text(item.get("source"))
            claim = _localized_claim(item, analysis)
            url = _synthesized_url(item, analysis)
            level = _text(item.get("weight_level"))
            lines.append(f"### {title}")
            if source:
                lines.append(f"来源：{source}")
            if claim:
                lines.append(f"说明：{claim}")
            if level:
                lines.append(f"证据等级：{level}")
            if url:
                lines.append(f"参考：{_format_reference(url, url)}")
            lines.append("")
    else:
        lines.append("当前未提取到可直接展示的结构化证据。")
        lines.append("")

    if local_intel.get("matched"):
        lines.append("## 本地指纹情报")
        lines.append(
            f"本地情报库命中 `{local_intel.get('indicator_type')}` 指标 `{local_intel.get('indicator_value')}`，"
            f"关联家族为 `{local_intel.get('malware_family')}`，来源 `{local_intel.get('source')}`。"
        )
        if local_intel.get("last_updated"):
            lines.append(f"该记录最近更新时间为 {local_intel.get('last_updated')}。")
        local_ref = _synthesized_url({"kind": "local_intel", "source": local_intel.get("source")}, analysis)
        if local_ref:
            lines.append(f"可参考：{_format_reference(local_ref, local_ref)}")
        lines.append("")

    background = _background_evidence(analysis)
    if background:
        lines.append("## 相关情报参考")
        for item in background:
            title = _text(item.get("title")) or "相关情报"
            claim = _localized_claim(item, analysis)
            url = _synthesized_url(item, analysis)
            if url:
                lines.append(f"- {_format_reference(title, url)}：{claim}")
            else:
                lines.append(f"- {title}：{claim}")
        lines.append("")

    material_uncertainties = _material_uncertainties(analysis)
    if material_uncertainties:
        lines.append("## 说明")
        for item in material_uncertainties:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("## 处置建议")
    if actions:
        for item in actions:
            lines.append(f"- [{_text(item.get('priority')).upper()}] {_text(item.get('action'))} 理由：{_text(item.get('rationale'))}")
    else:
        lines.append("- 当前未生成结构化处置建议。")

    references = _reference_items(analysis)
    if references:
        lines.append("")
        lines.append("## 参考链接")
        for item in references:
            url = item.get("url")
            title = _text(item.get("title")) or "相关情报"
            claim = _localized_claim(item, analysis)
            if url:
                lines.append(f"- {_format_reference(title, url)}")
            else:
                lines.append(f"- {title}")
            if claim:
                lines.append(f"  摘要：{claim}")

    return "\n".join(lines).strip() + "\n"
