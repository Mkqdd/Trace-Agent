from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


TIME_FULL_RE = re.compile(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: UTC)?\b")
TIME_FULL_ZH_RE = re.compile(
    r"\b\d{4}\s*年\s*\d{1,2}\s*月\s*\d{1,2}\s*日(?:凌晨|早上|上午|中午|下午|傍晚|晚上)?\s*\d{2}:\d{2}:\d{2}(?:\s*UTC)?\b"
)
TIME_MINUTE_WITH_DATE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?!:\d{2})(?:\s*UTC)?\b"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
SECTION_RE = re.compile(r"^(#{1,3})\s+(.+?)\s*$")
SENTENCE_SPLIT_RE = re.compile(r"(?<=[。！？!?])\s*|\n+")
NON_DOMAIN_TLDS = {
    "7z",
    "aspx",
    "bat",
    "cmd",
    "dat",
    "dll",
    "exe",
    "jsp",
    "log",
    "php",
    "ps1",
    "rar",
    "sys",
    "tmp",
    "zip",
}


def _text(value: Any) -> str:
    text = str(value or "").strip()
    for char in ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212"):
        text = text.replace(char, "-")
    return text


def _dedupe_text(values: List[Any]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        text = _text(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _split_components(value: Any) -> List[str]:
    text = _text(value)
    if not text:
        return []
    return _dedupe_text(part.strip("` ") for part in text.split("/") if part.strip("` "))


def _normalize_time_text(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    text = text.replace("T", " ").replace("Z", " UTC")
    text = re.sub(r"\s+", " ", text).strip()

    zh_match = re.match(
        r"(?P<year>\d{4})\s*年\s*(?P<month>\d{1,2})\s*月\s*(?P<day>\d{1,2})\s*日"
        r"(?:凌晨|早上|上午|中午|下午|傍晚|晚上)?\s*"
        r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\s*UTC)?",
        text,
    )
    if zh_match:
        return (
            f"{int(zh_match.group('year')):04d}-{int(zh_match.group('month')):02d}-{int(zh_match.group('day')):02d} "
            f"{zh_match.group('hour')}:{zh_match.group('minute')}:{zh_match.group('second')} UTC"
        )

    iso_match = re.match(
        r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2}) "
        r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\s*UTC)?",
        text,
    )
    if iso_match:
        return (
            f"{iso_match.group('year')}-{iso_match.group('month')}-{iso_match.group('day')} "
            f"{iso_match.group('hour')}:{iso_match.group('minute')}:{iso_match.group('second')} UTC"
        )

    return text


def _normalize_minute_time_text(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    text = text.replace("T", " ").replace("Z", " UTC")
    text = re.sub(r"\s+", " ", text).strip()
    match = re.match(r"(?P<prefix>\d{4}-\d{2}-\d{2} \d{2}:\d{2})(?:\s*UTC)?", text)
    if not match:
        return text
    return f"{match.group('prefix')}:00 UTC"


def _extract_sections(markdown: str) -> List[Dict[str, Any]]:
    current = {"title": "全文", "lines": []}
    sections: List[Dict[str, Any]] = []
    for raw_line in str(markdown or "").splitlines():
        line = raw_line.rstrip()
        match = SECTION_RE.match(line)
        if match and match.group(2):
            if current.get("lines"):
                sections.append(current)
            current = {"title": match.group(2).strip(), "lines": []}
            continue
        current.setdefault("lines", []).append(line)
    if current.get("lines"):
        sections.append(current)
    return [
        {"title": _text(item.get("title")) or "全文", "text": "\n".join(item.get("lines") or []).strip()}
        for item in sections
        if _text(item.get("title")) or _text("\n".join(item.get("lines") or []))
    ]


def _body_only(markdown: str) -> str:
    text = str(markdown or "")
    if "\n---\n" in text:
        text = text.split("\n---\n", 1)[0]
    appendix_marker = "## 事件调查技术附录"
    if appendix_marker in text:
        text = text.split(appendix_marker, 1)[0]
    return text.strip()


def _split_sentences(text: str) -> List[str]:
    return [_text(item) for item in SENTENCE_SPLIT_RE.split(_text(text)) if _text(item)]


def _known_sets(report_fact_cards: Dict[str, Any]) -> Dict[str, Any]:
    facts = [dict(item) for item in list(report_fact_cards.get("fact_cards") or []) if isinstance(item, dict)]
    allowed_full_times: set[str] = set()
    allowed_minute_prefixes: set[str] = set()
    allowed_ips: set[str] = set()
    allowed_domains: set[str] = set()

    for fact in facts:
        fact_type = _text(fact.get("fact_type"))
        if fact_type == "event":
            time_text = _text(fact.get("time"))
            if time_text:
                normalized_time = _normalize_time_text(time_text)
                if normalized_time:
                    allowed_full_times.add(normalized_time)
                    allowed_minute_prefixes.add(normalized_time[:16])
            for item in _split_components(fact.get("object")):
                if IP_RE.fullmatch(item):
                    allowed_ips.add(item)
                elif DOMAIN_RE.fullmatch(item):
                    allowed_domains.add(item.lower())
        if fact_type == "scope":
            entity = _text(fact.get("entity"))
            if entity:
                if IP_RE.fullmatch(entity):
                    allowed_ips.add(entity)
                elif DOMAIN_RE.fullmatch(entity):
                    allowed_domains.add(entity.lower())

    return {
        "allowed_full_times": allowed_full_times,
        "allowed_minute_prefixes": allowed_minute_prefixes,
        "allowed_ips": allowed_ips,
        "allowed_domains": allowed_domains,
    }


def _add_issue(
    issues: List[Dict[str, Any]],
    *,
    severity: str,
    code: str,
    section: str,
    sentence: str,
    message: str,
    evidence: List[str] | None = None,
) -> None:
    issues.append(
        {
            "severity": severity,
            "code": code,
            "section": section,
            "sentence": _text(sentence),
            "message": _text(message),
            "evidence": _dedupe_text(list(evidence or [])),
        }
    )


def _is_domain_like(value: str) -> bool:
    text = _text(value).lower()
    if not text or not DOMAIN_RE.fullmatch(text):
        return False
    suffix = text.rsplit(".", 1)[-1]
    if suffix in NON_DOMAIN_TLDS:
        return False
    return True


def _mask_spans(text: str, spans: List[Tuple[int, int]]) -> str:
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for index in range(start, min(end, len(chars))):
            chars[index] = " "
    return "".join(chars)


def _iter_full_time_matches(sentence: str) -> List[Tuple[str, Tuple[int, int]]]:
    matches: List[Tuple[str, Tuple[int, int]]] = []
    for pattern in (TIME_FULL_RE, TIME_FULL_ZH_RE):
        for match in pattern.finditer(sentence):
            matches.append((match.group(0), match.span()))
    return sorted(matches, key=lambda item: item[1][0])


def validate_report_polish(body_markdown: str, report_fact_cards: Dict[str, Any]) -> Dict[str, Any]:
    body = _body_only(body_markdown)
    if not body.strip():
        return {
            "schema_version": "report-polish-validation-v1",
            "applied": False,
            "status": "skipped_empty_body",
            "issues": [],
            "summary": "没有可验证的 polished 正文。",
        }

    known = _known_sets(report_fact_cards)
    sections = _extract_sections(body)
    issues: List[Dict[str, Any]] = []

    for section in sections:
        section_title = _text(section.get("title")) or "全文"
        section_text = _text(section.get("text"))
        sentences = _split_sentences(section_text)

        for sentence in sentences:
            full_time_ranges: List[Tuple[int, int]] = []
            for full_time, span in _iter_full_time_matches(sentence):
                full_time_ranges.append(span)
                if _normalize_time_text(full_time) not in known["allowed_full_times"]:
                    _add_issue(
                        issues,
                        severity="hard_fail",
                        code="unknown_time",
                        section=section_title,
                        sentence=sentence,
                        message=f"正文引用了事实卡中不存在的时间 `{full_time}`。",
                        evidence=[full_time],
                    )
            minute_scan_sentence = _mask_spans(sentence, full_time_ranges)
            minute_time_ranges: List[Tuple[int, int]] = []
            for match in TIME_MINUTE_WITH_DATE_RE.finditer(minute_scan_sentence):
                minute_time = sentence[match.start() : match.end()]
                minute_time_ranges.append(match.span())
                normalized_minute = _normalize_minute_time_text(minute_time)
                if normalized_minute in known["allowed_full_times"]:
                    continue
                if normalized_minute[:16] in known["allowed_minute_prefixes"]:
                    _add_issue(
                        issues,
                        severity="soft_warn",
                        code="time_precision_drift",
                        section=section_title,
                        sentence=sentence,
                        message=f"正文把事实卡中的精确时间写成了分钟级表述 `{minute_time}`。",
                        evidence=[minute_time],
                    )
                else:
                    _add_issue(
                        issues,
                        severity="hard_fail",
                        code="unknown_time",
                        section=section_title,
                        sentence=sentence,
                        message=f"正文引用了事实卡中不存在的时间 `{minute_time}`。",
                        evidence=[minute_time],
                    )
            for ip in IP_RE.findall(sentence):
                if ip not in known["allowed_ips"]:
                    _add_issue(
                        issues,
                        severity="hard_fail",
                        code="unknown_ip",
                        section=section_title,
                        sentence=sentence,
                        message=f"正文引用了事实卡中不存在的 IP `{ip}`。",
                        evidence=[ip],
                    )
            for domain in DOMAIN_RE.findall(sentence):
                lowered = domain.lower()
                if not _is_domain_like(lowered):
                    continue
                if lowered not in known["allowed_domains"]:
                    _add_issue(
                        issues,
                        severity="hard_fail",
                        code="unknown_domain",
                        section=section_title,
                        sentence=sentence,
                        message=f"正文引用了事实卡中不存在的域名 `{domain}`。",
                        evidence=[domain],
                    )

    hard_fail_count = len([item for item in issues if _text(item.get("severity")) == "hard_fail"])
    soft_warn_count = len([item for item in issues if _text(item.get("severity")) == "soft_warn"])
    status = "hard_fail" if hard_fail_count else ("soft_warn" if soft_warn_count else "clean")
    summary = (
        "未发现事实漂移。"
        if status == "clean"
        else f"发现 {hard_fail_count} 条 hard-fail 和 {soft_warn_count} 条 soft-warn。"
    )

    return {
        "schema_version": "report-polish-validation-v1",
        "applied": True,
        "status": status,
        "summary": summary,
        "issue_counts": {
            "hard_fail": hard_fail_count,
            "soft_warn": soft_warn_count,
        },
        "issues": issues,
    }
