#!/usr/bin/env python3
"""
Passive OSINT harvester for educational use.

The tool gathers public information about a domain without port scanning,
credential testing, or exploitation. It queries public indexes and archives,
then exports JSON, CSV and Markdown reports.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import io
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


USER_AGENT = "SparkVision-OSINT-Harvester/1.0 (educational passive OSINT)"
SOURCE_NAMES = ("crtsh", "dns", "wayback", "urlscan", "hackertarget")
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA")
DNS_SECURITY_QUERIES = (("_dmarc", "TXT"),)
DOC_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
    ".docm",
    ".xlsm",
    ".pptm",
    ".doc",
    ".xls",
    ".ppt",
}
OOXML_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
EMAIL_RE = re.compile(
    r"(?<![A-Z0-9._%+\-])([A-Z0-9._%+\-]{1,64}@[A-Z0-9.\-]+\.[A-Z]{2,63})(?![A-Z0-9._%+\-])",
    re.IGNORECASE,
)
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
PDF_INFO_KEYS = (
    "Title",
    "Author",
    "Subject",
    "Keywords",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
    "Company",
)


@dataclass
class EmailFinding:
    value: str
    sources: set[str] = field(default_factory=set)
    contexts: set[str] = field(default_factory=set)


@dataclass
class HarvestState:
    target: str
    started_at: str
    subdomains: dict[str, set[str]] = field(default_factory=dict)
    emails: dict[str, EmailFinding] = field(default_factory=dict)
    dns_records: list[dict[str, Any]] = field(default_factory=list)
    documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    metadata: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    def add_subdomain(self, value: str, source: str) -> None:
        hostname = normalize_hostname(value)
        if not hostname or not is_in_scope(hostname, self.target):
            return
        if hostname == self.target:
            return
        self.subdomains.setdefault(hostname, set()).add(source)

    def add_email(self, value: str, source: str, context: str = "") -> None:
        email = normalize_email(value)
        if not email:
            return
        if not email_in_scope(email, self.target, include_external=False):
            return
        finding = self.emails.setdefault(email, EmailFinding(value=email))
        finding.sources.add(source)
        if context:
            finding.contexts.add(trim(context, 180))

    def add_dns_record(self, record: dict[str, Any]) -> None:
        self.dns_records.append(record)

    def add_document(self, url: str, source: str, **extra: Any) -> None:
        doc = self.documents.setdefault(
            url,
            {
                "url": url,
                "sources": [],
                "extension": get_url_extension(url),
                "mimetype": "",
                "first_seen": "",
                "last_seen": "",
                "archive_url": "",
                "metadata": {},
                "metadata_error": "",
            },
        )
        if source not in doc["sources"]:
            doc["sources"].append(source)
        for key, value in extra.items():
            if value:
                if key == "timestamp":
                    update_seen_dates(doc, str(value))
                else:
                    doc[key] = value

    def add_error(self, source: str, message: str) -> None:
        self.errors.append({"source": source, "message": trim(message, 300)})


def now_utc() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def trim(value: str, limit: int) -> str:
    value = " ".join(str(value).split())
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def normalize_target(raw: str) -> str:
    value = raw.strip().lower()
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        value = parsed.hostname or value
    else:
        value = value.split("/", 1)[0]
        value = value.split("?", 1)[0]
        value = value.split("#", 1)[0]
        if "@" in value:
            value = value.rsplit("@", 1)[-1]
    value = value.strip().strip(".")
    if value.startswith("*."):
        value = value[2:]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid domain: {raw}") from exc
    if not HOST_RE.match(value):
        raise ValueError(f"Invalid domain: {raw}")
    return value


def normalize_hostname(raw: str | None) -> str:
    if not raw:
        return ""
    value = str(raw).strip().lower()
    value = value.replace("\\n", "\n").splitlines()[0].strip()
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        value = parsed.hostname or ""
    value = value.strip().strip(".")
    if value.startswith("*."):
        value = value[2:]
    if ":" in value and not value.startswith("["):
        value = value.split(":", 1)[0]
    value = value.strip("[]")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if HOST_RE.match(value):
        return value
    return ""


def normalize_email(raw: str | None) -> str:
    if not raw:
        return ""
    value = urllib.parse.unquote(str(raw).strip())
    value = value.strip("<>.,;:'\"()[]{}")
    match = EMAIL_RE.search(value)
    if not match:
        return ""
    return match.group(1).lower()


def is_in_scope(hostname: str, target: str) -> bool:
    return hostname == target or hostname.endswith("." + target)


def email_in_scope(email: str, target: str, include_external: bool) -> bool:
    if include_external:
        return True
    domain = email.rsplit("@", 1)[-1]
    return domain == target or domain.endswith("." + target)


def get_url_hostname(url: str) -> str:
    return normalize_hostname(urllib.parse.urlparse(url).hostname)


def get_url_extension(url: str) -> str:
    path = urllib.parse.urlparse(url).path
    suffix = Path(urllib.parse.unquote(path)).suffix.lower()
    return suffix[:12]


def is_document_url(url: str) -> bool:
    return get_url_extension(url) in DOC_EXTENSIONS


def update_seen_dates(doc: dict[str, Any], timestamp: str) -> None:
    if not timestamp:
        return
    if not doc.get("first_seen") or timestamp < doc["first_seen"]:
        doc["first_seen"] = timestamp
    if not doc.get("last_seen") or timestamp > doc["last_seen"]:
        doc["last_seen"] = timestamp


def wayback_raw_url(timestamp: str, original_url: str) -> str:
    return f"https://web.archive.org/web/{timestamp}id_/{original_url}"


def http_fetch(
    url: str,
    timeout: int,
    *,
    accept: str = "*/*",
    max_bytes: int | None = None,
) -> tuple[bytes, dict[str, str]]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": accept,
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        headers = {key.lower(): value for key, value in response.headers.items()}
        if max_bytes is None:
            return response.read(), headers
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            data = data[:max_bytes]
            headers["x-osint-truncated"] = "true"
        return data, headers


def http_json(url: str, timeout: int, source: str) -> Any:
    data, _ = http_fetch(
        url,
        timeout,
        accept="application/json,text/plain;q=0.8,*/*;q=0.5",
        max_bytes=25_000_000,
    )
    text = data.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        snippet = trim(text, 200)
        raise ValueError(f"{source} returned non-JSON data: {snippet}") from exc


def http_text(url: str, timeout: int) -> str:
    data, _ = http_fetch(url, timeout, accept="text/plain,*/*;q=0.5", max_bytes=5_000_000)
    return data.decode("utf-8", errors="replace")


def extract_emails_from_text(state: HarvestState, text: str, source: str, context: str = "") -> None:
    decoded = urllib.parse.unquote(text)
    for match in EMAIL_RE.finditer(decoded):
        state.add_email(match.group(1), source, context or match.group(0))


def run_crtsh(state: HarvestState, timeout: int, limit: int) -> None:
    query = urllib.parse.quote(f"%.{state.target}")
    url = f"https://crt.sh/?q={query}&output=json"
    try:
        rows = http_json(url, timeout, "crtsh")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return
        raise
    if not isinstance(rows, list):
        raise ValueError("crtsh response is not a list")
    count = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        for name in str(row.get("name_value", "")).splitlines():
            state.add_subdomain(name, "crtsh")
            count += 1
            if count >= limit:
                return


def run_dns(state: HarvestState, timeout: int, limit: int) -> None:
    for record_type in DNS_TYPES:
        count = 0
        url = (
            "https://dns.google/resolve?"
            + urllib.parse.urlencode({"name": state.target, "type": record_type})
        )
        payload = http_json(url, timeout, "dns")
        answers = payload.get("Answer", []) if isinstance(payload, dict) else []
        for answer in answers:
            if not isinstance(answer, dict):
                continue
            record = {
                "source": "dns",
                "name": answer.get("name", "").rstrip("."),
                "type": record_type,
                "ttl": answer.get("TTL", ""),
                "data": str(answer.get("data", "")).strip(),
            }
            state.add_dns_record(record)
            count += 1
            extract_emails_from_text(state, record["data"], "dns", f"DNS {record_type}")
            for hostname in extract_hostnames_from_dns_data(record_type, record["data"]):
                state.add_subdomain(hostname, "dns")
            if count >= limit:
                break
    for prefix, record_type in DNS_SECURITY_QUERIES:
        query_name = f"{prefix}.{state.target}"
        url = (
            "https://dns.google/resolve?"
            + urllib.parse.urlencode({"name": query_name, "type": record_type})
        )
        payload = http_json(url, timeout, "dns")
        answers = payload.get("Answer", []) if isinstance(payload, dict) else []
        for answer in answers:
            if not isinstance(answer, dict):
                continue
            record = {
                "source": "dns",
                "name": answer.get("name", "").rstrip("."),
                "type": record_type,
                "ttl": answer.get("TTL", ""),
                "data": str(answer.get("data", "")).strip(),
            }
            state.add_dns_record(record)
            extract_emails_from_text(state, record["data"], "dns", f"DNS {record_type}")


def extract_hostnames_from_dns_data(record_type: str, data: str) -> list[str]:
    value = data.strip().strip(".")
    if record_type == "MX":
        parts = value.split()
        if len(parts) >= 2:
            value = parts[-1]
    if record_type in {"MX", "NS", "SOA", "CNAME"}:
        host = normalize_hostname(value)
        return [host] if host else []
    return []


def run_wayback(state: HarvestState, timeout: int, limit: int) -> None:
    per_query_limit = max(1, limit // 2)
    for pattern in (f"{state.target}/*", f"*.{state.target}/*"):
        try:
            process_wayback_pattern(state, timeout, per_query_limit, pattern)
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            state.add_error("wayback", f"{pattern}: {exc}")


def process_wayback_pattern(state: HarvestState, timeout: int, limit: int, pattern: str) -> None:
    params = {
        "url": pattern,
        "output": "json",
        "fl": "original,mimetype,statuscode,timestamp",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": str(limit),
    }
    url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    try:
        payload = http_json(url, timeout, "wayback")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return
        raise
    if not isinstance(payload, list) or not payload:
        return
    headers = payload[0]
    if not isinstance(headers, list):
        return
    for row in payload[1:]:
        if not isinstance(row, list):
            continue
        item = dict(zip(headers, row))
        original_url = item.get("original", "")
        timestamp = item.get("timestamp", "")
        host = get_url_hostname(original_url)
        state.add_subdomain(host, "wayback")
        extract_emails_from_text(state, original_url, "wayback", original_url)
        if is_document_url(original_url):
            state.add_document(
                original_url,
                "wayback",
                mimetype=item.get("mimetype", ""),
                timestamp=timestamp,
                archive_url=wayback_raw_url(timestamp, original_url) if timestamp else "",
            )


def run_urlscan(state: HarvestState, timeout: int, limit: int) -> None:
    size = max(1, min(limit, 100))
    params = {"q": f"domain:{state.target}", "size": str(size)}
    url = "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode(params)
    payload = http_json(url, timeout, "urlscan")
    results = payload.get("results", []) if isinstance(payload, dict) else []
    for result in results[:size]:
        if not isinstance(result, dict):
            continue
        page = result.get("page", {}) if isinstance(result.get("page"), dict) else {}
        task = result.get("task", {}) if isinstance(result.get("task"), dict) else {}
        state.add_subdomain(page.get("domain", ""), "urlscan")
        for candidate in (page.get("url", ""), task.get("url", "")):
            if not candidate:
                continue
            host = get_url_hostname(candidate)
            state.add_subdomain(host, "urlscan")
            extract_emails_from_text(state, candidate, "urlscan", candidate)
            if is_document_url(candidate):
                state.add_document(candidate, "urlscan", mimetype=page.get("mimeType", ""))


def run_hackertarget(state: HarvestState, timeout: int, limit: int) -> None:
    url = "https://api.hackertarget.com/hostsearch/?" + urllib.parse.urlencode({"q": state.target})
    text = http_text(url, timeout)
    if "error" in text.lower() and "," not in text:
        raise ValueError(trim(text, 200))
    for index, line in enumerate(text.splitlines()):
        if index >= limit:
            return
        hostname = line.split(",", 1)[0].strip()
        state.add_subdomain(hostname, "hackertarget")


def fetch_document_metadata(
    state: HarvestState,
    timeout: int,
    metadata_limit: int,
    max_doc_bytes: int,
    delay: float,
) -> None:
    if metadata_limit <= 0:
        return
    candidates = sorted(
        state.documents.values(),
        key=lambda item: (item.get("first_seen") or "", item.get("url") or ""),
    )
    for doc in candidates[:metadata_limit]:
        source_url = doc.get("archive_url") or doc["url"]
        try:
            time.sleep(delay)
            data, headers = http_fetch(source_url, timeout, max_bytes=max_doc_bytes)
            if headers.get("x-osint-truncated") == "true":
                doc["metadata_error"] = f"Document larger than {max_doc_bytes} bytes"
                continue
            metadata = extract_document_metadata(data, doc["url"], headers)
            metadata["sha256"] = hashlib.sha256(data).hexdigest()
            metadata["size_bytes"] = len(data)
            metadata["fetched_from"] = "wayback" if "web.archive.org" in source_url else "original"
            doc["metadata"] = metadata
            state.metadata.append({"url": doc["url"], "metadata": metadata})
            extract_emails_from_bytes(state, data, "document", doc["url"])
        except (urllib.error.URLError, TimeoutError, ValueError, zipfile.BadZipFile) as exc:
            doc["metadata_error"] = trim(str(exc), 240)
            state.add_error("metadata", f"{doc['url']}: {exc}")


def extract_emails_from_bytes(state: HarvestState, data: bytes, source: str, context: str) -> None:
    text = data.decode("latin-1", errors="ignore")
    extract_emails_from_text(state, text, source, context)


def extract_document_metadata(data: bytes, url: str, headers: dict[str, str]) -> dict[str, Any]:
    extension = get_url_extension(url)
    content_type = headers.get("content-type", "")
    metadata: dict[str, Any] = {
        "extension": extension,
        "content_type": content_type,
    }
    if data.startswith(b"%PDF") or extension == ".pdf" or "pdf" in content_type:
        metadata.update(extract_pdf_metadata(data))
        metadata["parser"] = "pdf"
        return compact_metadata(metadata)
    if extension in OOXML_EXTENSIONS or data.startswith(b"PK"):
        metadata.update(extract_ooxml_metadata(data))
        metadata["parser"] = "ooxml"
        return compact_metadata(metadata)
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        metadata["parser"] = "ole-unsupported"
        metadata["note"] = "Legacy Office OLE file detected; parser not implemented."
        return compact_metadata(metadata)
    metadata["parser"] = "generic"
    return compact_metadata(metadata)


def extract_pdf_metadata(data: bytes) -> dict[str, str]:
    text = data.decode("latin-1", errors="ignore")
    metadata: dict[str, str] = {}
    for key in PDF_INFO_KEYS:
        literal = re.search(rf"/{key}\s*\((.*?)\)", text, flags=re.DOTALL)
        if literal:
            metadata[key] = decode_pdf_literal(literal.group(1))
            continue
        hex_value = re.search(rf"/{key}\s*<([0-9A-Fa-f]+)>", text)
        if hex_value:
            metadata[key] = decode_pdf_hex(hex_value.group(1))
    return metadata


def decode_pdf_literal(value: str) -> str:
    replacements = {
        r"\(": "(",
        r"\)": ")",
        r"\\": "\\",
        r"\n": "\n",
        r"\r": "\r",
        r"\t": "\t",
        r"\b": "\b",
        r"\f": "\f",
    }
    for src, dest in replacements.items():
        value = value.replace(src, dest)
    value = re.sub(
        r"\\([0-7]{1,3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )
    return trim(value, 500)


def decode_pdf_hex(value: str) -> str:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return ""
    for encoding in ("utf-16-be", "utf-8", "latin-1"):
        try:
            decoded = raw.decode(encoding).lstrip("\ufeff")
            if decoded:
                return trim(decoded, 500)
        except UnicodeDecodeError:
            continue
    return ""


def extract_ooxml_metadata(data: bytes) -> dict[str, str]:
    metadata: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in ("docProps/core.xml", "docProps/app.xml"):
            if member not in archive.namelist():
                continue
            root = ElementTree.fromstring(archive.read(member))
            for element in root.iter():
                key = element.tag.rsplit("}", 1)[-1]
                value = (element.text or "").strip()
                if value:
                    metadata[key] = trim(value, 500)
    return metadata


def compact_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in metadata.items()
        if value not in ("", None, [], {})
    }


def normalize_dns_text(data: str) -> str:
    return " ".join(str(data).replace('" "', "").replace('"', "").split())


def evaluate_security_controls(target: str, dns_records: list[dict[str, Any]]) -> dict[str, Any]:
    target_txt = [
        normalize_dns_text(record.get("data", ""))
        for record in dns_records
        if record.get("type") == "TXT" and str(record.get("name", "")).rstrip(".") == target
    ]
    dmarc_name = f"_dmarc.{target}"
    dmarc_txt = [
        normalize_dns_text(record.get("data", ""))
        for record in dns_records
        if record.get("type") == "TXT" and str(record.get("name", "")).rstrip(".") == dmarc_name
    ]
    mx_records = [
        record
        for record in dns_records
        if record.get("type") == "MX" and normalize_dns_text(record.get("data", "")) not in {"0 .", "."}
    ]
    spf_values = [value for value in target_txt if "v=spf1" in value.lower()]
    dmarc_values = [value for value in dmarc_txt if "v=dmarc1" in value.lower()]
    dmarc_policy = parse_dmarc_policy(dmarc_values[0]) if dmarc_values else ""
    return {
        "spf": {
            "present": bool(spf_values),
            "status": classify_spf(spf_values[0]) if spf_values else "missing",
            "value": spf_values[0] if spf_values else "",
        },
        "dmarc": {
            "present": bool(dmarc_values),
            "status": classify_dmarc_policy(dmarc_policy),
            "policy": dmarc_policy,
            "value": dmarc_values[0] if dmarc_values else "",
        },
        "mx": {
            "present": bool(mx_records),
            "count": len(mx_records),
        },
        "caa": {
            "present": any(record.get("type") == "CAA" for record in dns_records),
        },
    }


def parse_dmarc_policy(value: str) -> str:
    match = re.search(r"(?:^|;)\s*p\s*=\s*([a-zA-Z]+)", value)
    return match.group(1).lower() if match else ""


def classify_spf(value: str) -> str:
    lower = value.lower()
    if "+all" in lower:
        return "weak"
    if "?all" in lower or "~all" in lower:
        return "soft"
    if "-all" in lower:
        return "strict"
    return "present"


def classify_dmarc_policy(policy: str) -> str:
    if policy in {"reject", "quarantine"}:
        return "enforced"
    if policy == "none":
        return "monitoring"
    return "missing"


def build_risk_assessment(
    subdomains: list[dict[str, Any]],
    emails: list[dict[str, Any]],
    documents: list[dict[str, Any]],
    security_controls: dict[str, Any],
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []

    def add_finding(
        category: str,
        severity: str,
        points: int,
        title: str,
        evidence: str,
        recommendation: str,
    ) -> None:
        findings.append(
            {
                "category": category,
                "severity": severity,
                "points": points,
                "title": title,
                "evidence": evidence,
                "recommendation": recommendation,
            }
        )

    spf = security_controls["spf"]
    dmarc = security_controls["dmarc"]
    if not spf["present"]:
        add_finding(
            "Email security",
            "Medium",
            12,
            "SPF absent",
            "Aucun enregistrement SPF public n'a ete observe sur le domaine racine.",
            "Publier un enregistrement SPF limite aux serveurs d'envoi autorises.",
        )
    elif spf["status"] == "weak":
        add_finding(
            "Email security",
            "High",
            18,
            "SPF permissif",
            "Le SPF contient '+all', ce qui autorise n'importe quel emetteur.",
            "Remplacer '+all' par '-all' apres inventaire des services d'envoi legitimes.",
        )
    elif spf["status"] == "soft":
        add_finding(
            "Email security",
            "Low",
            6,
            "SPF en mode souple",
            "Le SPF utilise '~all' ou '?all'.",
            "Passer progressivement vers '-all' lorsque les flux email sont maitrises.",
        )

    if not dmarc["present"]:
        add_finding(
            "Email security",
            "High",
            20,
            "DMARC absent",
            "Aucun enregistrement TXT _dmarc n'a ete observe.",
            "Publier une politique DMARC, d'abord en monitoring, puis en quarantine ou reject.",
        )
    elif dmarc["status"] == "monitoring":
        add_finding(
            "Email security",
            "Medium",
            10,
            "DMARC en monitoring seulement",
            "La politique DMARC est p=none.",
            "Analyser les rapports DMARC puis appliquer p=quarantine ou p=reject.",
        )

    if not security_controls["caa"]["present"]:
        add_finding(
            "DNS hygiene",
            "Low",
            4,
            "CAA absent",
            "Aucun enregistrement CAA n'a ete observe.",
            "Ajouter CAA pour limiter les autorites de certification autorisees.",
        )

    if emails:
        add_finding(
            "Exposure",
            "Medium" if len(emails) < 5 else "High",
            min(25, 5 * len(emails)),
            "Emails publics trouves",
            f"{len(emails)} adresse(s) email du domaine ont ete collectees.",
            "Eviter les emails nominatifs en clair et surveiller les boites exposees au phishing.",
        )

    if documents:
        add_finding(
            "Exposure",
            "Low" if len(documents) < 5 else "Medium",
            min(15, 3 * len(documents)),
            "Documents publics indexes",
            f"{len(documents)} document(s) public(s) ont ete observes dans les sources.",
            "Revoir les documents publics et supprimer les fichiers obsoletes ou sensibles.",
        )

    metadata_docs = documents_with_personal_metadata(documents)
    if metadata_docs:
        add_finding(
            "Metadata",
            "Medium",
            min(20, 8 * len(metadata_docs)),
            "Metadonnees nominatives",
            f"{len(metadata_docs)} document(s) contiennent des champs auteur, createur ou entreprise.",
            "Nettoyer les metadonnees avant publication des PDF et documents Office.",
        )

    sensitive_subdomains = find_sensitive_subdomains(subdomains)
    if sensitive_subdomains:
        add_finding(
            "Attack surface",
            "Medium",
            min(20, 4 * len(sensitive_subdomains)),
            "Sous-domaines sensibles",
            ", ".join(sensitive_subdomains[:10]),
            "Verifier que les interfaces internes, preproduction et administration ne sont pas publiques.",
        )

    if len(subdomains) >= 50:
        add_finding(
            "Attack surface",
            "Low",
            8 if len(subdomains) < 100 else 14,
            "Surface de sous-domaines importante",
            f"{len(subdomains)} sous-domaines collectes.",
            "Maintenir un inventaire DNS et retirer les entrees obsoletes.",
        )

    if errors:
        add_finding(
            "Collection",
            "Info",
            0,
            "Collecte partielle",
            f"{len(errors)} erreur(s) de source pendant la collecte.",
            "Relancer la collecte ou augmenter le timeout pour confirmer les resultats.",
        )

    score = min(100, sum(item["points"] for item in findings))
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    findings.sort(key=lambda item: (severity_order.get(item["severity"], 9), -item["points"], item["title"]))
    return {
        "score": score,
        "level": risk_level(score),
        "findings": findings,
    }


def documents_with_personal_metadata(documents: list[dict[str, Any]]) -> list[str]:
    keys = {"Author", "Creator", "Company", "creator", "lastModifiedBy", "manager", "company"}
    result = []
    for document in documents:
        metadata = document.get("metadata", {})
        if any(metadata.get(key) for key in keys):
            result.append(document.get("url", ""))
    return result


def find_sensitive_subdomains(subdomains: list[dict[str, Any]]) -> list[str]:
    keywords = (
        "admin",
        "vpn",
        "remote",
        "dev",
        "test",
        "staging",
        "preprod",
        "jira",
        "git",
        "grafana",
        "jenkins",
        "backup",
        "sso",
    )
    matches = []
    for item in subdomains:
        value = item.get("value", "")
        labels = value.split(".")
        if any(keyword in labels or any(label.startswith(keyword + "-") for label in labels) for keyword in keywords):
            matches.append(value)
    return sorted(set(matches))


def risk_level(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


def build_report(state: HarvestState) -> dict[str, Any]:
    subdomains = [
        {"value": value, "sources": sorted(sources)}
        for value, sources in sorted(state.subdomains.items())
    ]
    emails = [
        {
            "value": finding.value,
            "sources": sorted(finding.sources),
            "contexts": sorted(finding.contexts),
        }
        for finding in sorted(state.emails.values(), key=lambda item: item.value)
    ]
    documents = [
        normalize_document_for_report(doc)
        for doc in sorted(state.documents.values(), key=lambda item: item["url"])
    ]
    generated_at = now_utc()
    security_controls = evaluate_security_controls(state.target, state.dns_records)
    risk_assessment = build_risk_assessment(
        subdomains,
        emails,
        documents,
        security_controls,
        state.errors,
    )
    return {
        "target": state.target,
        "started_at": state.started_at,
        "generated_at": generated_at,
        "summary": {
            "subdomains": len(subdomains),
            "emails": len(emails),
            "dns_records": len(state.dns_records),
            "documents": len(documents),
            "metadata_records": len(state.metadata),
            "errors": len(state.errors),
            "risk_score": risk_assessment["score"],
            "risk_level": risk_assessment["level"],
        },
        "security_controls": security_controls,
        "risk_assessment": risk_assessment,
        "subdomains": subdomains,
        "emails": emails,
        "dns_records": state.dns_records,
        "documents": documents,
        "errors": state.errors,
    }


def normalize_document_for_report(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": doc.get("url", ""),
        "sources": sorted(doc.get("sources", [])),
        "extension": doc.get("extension", ""),
        "mimetype": doc.get("mimetype", ""),
        "first_seen": doc.get("first_seen", ""),
        "last_seen": doc.get("last_seen", ""),
        "archive_url": doc.get("archive_url", ""),
        "metadata": doc.get("metadata", {}),
        "metadata_error": doc.get("metadata_error", ""),
    }


def write_outputs(report: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (out_dir / "report.html").write_text(render_html(report), encoding="utf-8")
    write_subdomains_csv(report, out_dir / "subdomains.csv")
    write_emails_csv(report, out_dir / "emails.csv")
    write_dns_csv(report, out_dir / "dns_records.csv")
    write_documents_csv(report, out_dir / "documents.csv")
    write_risk_findings_csv(report, out_dir / "risk_findings.csv")


def write_subdomains_csv(report: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["subdomain", "sources"])
        writer.writeheader()
        for item in report["subdomains"]:
            writer.writerow({"subdomain": item["value"], "sources": ", ".join(item["sources"])})


def write_emails_csv(report: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["email", "sources", "contexts"])
        writer.writeheader()
        for item in report["emails"]:
            writer.writerow(
                {
                    "email": item["value"],
                    "sources": ", ".join(item["sources"]),
                    "contexts": " | ".join(item["contexts"]),
                }
            )


def write_dns_csv(report: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = ["source", "name", "type", "ttl", "data"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in report["dns_records"]:
            writer.writerow({key: item.get(key, "") for key in fieldnames})


def write_documents_csv(report: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "url",
            "sources",
            "extension",
            "mimetype",
            "first_seen",
            "last_seen",
            "metadata",
            "metadata_error",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in report["documents"]:
            writer.writerow(
                {
                    "url": item.get("url", ""),
                    "sources": ", ".join(item.get("sources", [])),
                    "extension": item.get("extension", ""),
                    "mimetype": item.get("mimetype", ""),
                    "first_seen": item.get("first_seen", ""),
                    "last_seen": item.get("last_seen", ""),
                    "metadata": json.dumps(item.get("metadata", {}), ensure_ascii=False),
                    "metadata_error": item.get("metadata_error", ""),
                }
            )


def write_risk_findings_csv(report: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = ["severity", "category", "points", "title", "evidence", "recommendation"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in report.get("risk_assessment", {}).get("findings", []):
            writer.writerow({key: item.get(key, "") for key in fieldnames})


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    risk = report["risk_assessment"]
    controls = report["security_controls"]
    lines = [
        f"# Rapport OSINT passif - {report['target']}",
        "",
        f"- Debut: `{report['started_at']}`",
        f"- Generation: `{report['generated_at']}`",
        "- Cadre: sources publiques uniquement, pas de scan de ports, pas de tentative de connexion.",
        "",
        "## Synthese",
        "",
        "| Indicateur | Nombre |",
        "| --- | ---: |",
        f"| Sous-domaines | {summary['subdomains']} |",
        f"| Emails | {summary['emails']} |",
        f"| Enregistrements DNS | {summary['dns_records']} |",
        f"| Documents publics | {summary['documents']} |",
        f"| Metadonnees extraites | {summary['metadata_records']} |",
        f"| Erreurs source | {summary['errors']} |",
        f"| Score de risque | {risk['score']} / 100 ({risk['level']}) |",
        "",
        "## Controle email/DNS",
        "",
        "| Controle | Statut | Valeur |",
        "| --- | --- | --- |",
        f"| SPF | {controls['spf']['status']} | {controls['spf'].get('value', '') or 'N/A'} |",
        f"| DMARC | {controls['dmarc']['status']} | {controls['dmarc'].get('value', '') or 'N/A'} |",
        f"| MX | {'present' if controls['mx']['present'] else 'missing'} | {controls['mx']['count']} record(s) |",
        f"| CAA | {'present' if controls['caa']['present'] else 'missing'} | N/A |",
        "",
    ]
    lines.extend(
        render_table(
            "Constats priorises",
            ["Severite", "Categorie", "Constat", "Preuve", "Recommandation"],
            risk["findings"],
            risk_row,
        )
    )
    lines.extend(render_table("Sous-domaines", ["Sous-domaine", "Sources"], report["subdomains"], subdomain_row))
    lines.extend(render_table("Emails", ["Email", "Sources"], report["emails"], email_row))
    lines.extend(render_table("DNS publics", ["Type", "Nom", "Donnee"], report["dns_records"], dns_row))
    lines.extend(render_table("Documents publics", ["Extension", "URL", "Metadonnees"], report["documents"], document_row))
    if report["errors"]:
        lines.extend(render_table("Erreurs", ["Source", "Message"], report["errors"], error_row))
    return "\n".join(lines).rstrip() + "\n"


def render_html(report: dict[str, Any]) -> str:
    summary = report["summary"]
    risk = report["risk_assessment"]
    controls = report["security_controls"]
    target = html_escape(report["target"])
    return f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rapport OSINT - {target}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #5c6b7a;
      --line: #d9e1ea;
      --accent: #116d6e;
      --accent-2: #c2410c;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      color: var(--text);
      background: var(--bg);
      line-height: 1.5;
    }}
    header {{
      background: #102a43;
      color: #fff;
      padding: 28px 36px;
    }}
    header p {{ margin: 6px 0 0; color: #d9e8f6; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px 20px 48px; }}
    h1, h2 {{ margin: 0; }}
    h2 {{ margin-top: 30px; margin-bottom: 12px; font-size: 1.25rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .kpi {{ font-size: 1.9rem; font-weight: 700; }}
    .label {{ color: var(--muted); font-size: .9rem; }}
    .risk {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      margin-top: 16px;
      padding: 10px 14px;
      border-radius: 999px;
      background: #fff7ed;
      color: #7c2d12;
      font-weight: 700;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 9px 10px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }}
    th {{ background: #eaf1f8; font-size: .88rem; }}
    tr:last-child td {{ border-bottom: 0; }}
    code {{ background: #edf2f7; padding: 2px 5px; border-radius: 4px; }}
    .severity-high {{ color: #991b1b; font-weight: 700; }}
    .severity-medium {{ color: #9a3412; font-weight: 700; }}
    .severity-low {{ color: #1d4ed8; font-weight: 700; }}
    .severity-info {{ color: #475569; font-weight: 700; }}
    .note {{ color: var(--muted); }}
    @media (max-width: 800px) {{
      header {{ padding: 22px 18px; }}
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      th, td {{ font-size: .92rem; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Rapport OSINT passif - {target}</h1>
    <p>Generation: <code>{html_escape(report["generated_at"])}</code></p>
    <div class="risk">Score de risque: {risk["score"]} / 100 - {html_escape(risk["level"])}</div>
  </header>
  <main>
    <section class="grid">
      {html_kpi("Sous-domaines", summary["subdomains"])}
      {html_kpi("Emails", summary["emails"])}
      {html_kpi("Documents", summary["documents"])}
      {html_kpi("Metadonnees", summary["metadata_records"])}
    </section>
    <p class="note">Sources publiques uniquement. Aucun scan de ports, aucune tentative de connexion, aucune exploitation.</p>
    <h2>Controle email/DNS</h2>
    {html_table(["Controle", "Statut", "Valeur"], [
        ["SPF", controls["spf"]["status"], controls["spf"].get("value", "") or "N/A"],
        ["DMARC", controls["dmarc"]["status"], controls["dmarc"].get("value", "") or "N/A"],
        ["MX", "present" if controls["mx"]["present"] else "missing", str(controls["mx"]["count"]) + " record(s)"],
        ["CAA", "present" if controls["caa"]["present"] else "missing", "N/A"],
    ])}
    <h2>Constats priorises</h2>
    {html_table(["Severite", "Categorie", "Constat", "Preuve", "Recommandation"], [
        [
            severity_badge(item.get("severity", "")),
            item.get("category", ""),
            item.get("title", ""),
            item.get("evidence", ""),
            item.get("recommendation", ""),
        ]
        for item in risk["findings"]
    ], raw_columns={0})}
    <h2>Sous-domaines</h2>
    {html_table(["Sous-domaine", "Sources"], [[item["value"], ", ".join(item["sources"])] for item in report["subdomains"]], limit=150)}
    <h2>Emails</h2>
    {html_table(["Email", "Sources"], [[item["value"], ", ".join(item["sources"])] for item in report["emails"]], limit=150)}
    <h2>DNS publics</h2>
    {html_table(["Type", "Nom", "Donnee"], [[item.get("type", ""), item.get("name", ""), item.get("data", "")] for item in report["dns_records"]], limit=150)}
    <h2>Documents publics</h2>
    {html_table(["Extension", "URL", "Metadonnees"], [document_row(item) for item in report["documents"]], limit=150)}
  </main>
</body>
</html>
"""


def html_kpi(label: str, value: Any) -> str:
    return (
        '<div class="card">'
        f'<div class="kpi">{html_escape(value)}</div>'
        f'<div class="label">{html_escape(label)}</div>'
        "</div>"
    )


def html_table(
    headers: list[str],
    rows: list[list[Any]],
    *,
    limit: int = 100,
    raw_columns: set[int] | None = None,
) -> str:
    raw_columns = raw_columns or set()
    if not rows:
        return '<p class="note">Aucun resultat.</p>'
    head = "".join(f"<th>{html_escape(header)}</th>" for header in headers)
    body_rows = []
    for row in rows[:limit]:
        cells = []
        for index, value in enumerate(row):
            cell = str(value) if index in raw_columns else html_escape(value)
            cells.append(f"<td>{cell}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    if len(rows) > limit:
        body_rows.append(
            f'<tr><td colspan="{len(headers)}" class="note">'
            f"{len(rows) - limit} lignes supplementaires dans les CSV"
            "</td></tr>"
        )
    return "<table><thead><tr>" + head + "</tr></thead><tbody>" + "".join(body_rows) + "</tbody></table>"


def severity_badge(severity: str) -> str:
    css = "severity-" + severity.lower()
    return f'<span class="{html_escape(css)}">{html_escape(severity)}</span>'


def html_escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_table(
    title: str,
    headers: list[str],
    rows: list[dict[str, Any]],
    row_builder: Any,
    max_rows: int = 100,
) -> list[str]:
    lines = [f"## {title}", ""]
    if not rows:
        lines.extend(["Aucun resultat.", ""])
        return lines
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for item in rows[:max_rows]:
        values = [escape_md(str(value)) for value in row_builder(item)]
        lines.append("| " + " | ".join(values) + " |")
    if len(rows) > max_rows:
        lines.append(f"| ... | {len(rows) - max_rows} lignes supplementaires dans les CSV |")
    lines.append("")
    return lines


def subdomain_row(item: dict[str, Any]) -> list[str]:
    return [item["value"], ", ".join(item["sources"])]


def email_row(item: dict[str, Any]) -> list[str]:
    return [item["value"], ", ".join(item["sources"])]


def dns_row(item: dict[str, Any]) -> list[str]:
    return [item.get("type", ""), item.get("name", ""), trim(item.get("data", ""), 120)]


def document_row(item: dict[str, Any]) -> list[str]:
    metadata = item.get("metadata", {})
    if metadata:
        selected = {
            key: metadata[key]
            for key in ("Title", "Author", "Creator", "Producer", "creator", "lastModifiedBy", "created", "modified")
            if key in metadata
        }
        metadata_text = json.dumps(selected or metadata, ensure_ascii=False)
    else:
        metadata_text = item.get("metadata_error", "")
    return [item.get("extension", ""), trim(item.get("url", ""), 120), trim(metadata_text, 160)]


def risk_row(item: dict[str, Any]) -> list[str]:
    return [
        item.get("severity", ""),
        item.get("category", ""),
        item.get("title", ""),
        trim(item.get("evidence", ""), 120),
        trim(item.get("recommendation", ""), 140),
    ]


def error_row(item: dict[str, Any]) -> list[str]:
    return [item.get("source", ""), item.get("message", "")]


def escape_md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def load_json_report(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON report {path}: {exc}") from exc


def compare_reports(old_report: dict[str, Any], new_report: dict[str, Any]) -> dict[str, Any]:
    sections = {
        "subdomains": (
            {item.get("value", "") for item in old_report.get("subdomains", [])},
            {item.get("value", "") for item in new_report.get("subdomains", [])},
        ),
        "emails": (
            {item.get("value", "") for item in old_report.get("emails", [])},
            {item.get("value", "") for item in new_report.get("emails", [])},
        ),
        "documents": (
            {item.get("url", "") for item in old_report.get("documents", [])},
            {item.get("url", "") for item in new_report.get("documents", [])},
        ),
        "dns_records": (
            {dns_record_key(item) for item in old_report.get("dns_records", [])},
            {dns_record_key(item) for item in new_report.get("dns_records", [])},
        ),
    }
    changes = {}
    for name, (old_values, new_values) in sections.items():
        old_values.discard("")
        new_values.discard("")
        changes[name] = {
            "added": sorted(new_values - old_values),
            "removed": sorted(old_values - new_values),
        }
    old_score = old_report.get("risk_assessment", {}).get("score", 0)
    new_score = new_report.get("risk_assessment", {}).get("score", 0)
    return {
        "generated_at": now_utc(),
        "old_target": old_report.get("target", ""),
        "new_target": new_report.get("target", ""),
        "same_target": old_report.get("target", "") == new_report.get("target", ""),
        "old_generated_at": old_report.get("generated_at", ""),
        "new_generated_at": new_report.get("generated_at", ""),
        "risk_delta": {
            "old_score": old_score,
            "new_score": new_score,
            "delta": new_score - old_score,
            "old_level": old_report.get("risk_assessment", {}).get("level", ""),
            "new_level": new_report.get("risk_assessment", {}).get("level", ""),
        },
        "summary": {
            name: {
                "added": len(value["added"]),
                "removed": len(value["removed"]),
            }
            for name, value in changes.items()
        },
        "changes": changes,
    }


def dns_record_key(item: dict[str, Any]) -> str:
    return "|".join(
        [
            str(item.get("type", "")),
            str(item.get("name", "")),
            normalize_dns_text(str(item.get("data", ""))),
        ]
    )


def write_comparison_outputs(comparison: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "comparison.json").write_text(
        json.dumps(comparison, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_dir / "comparison.md").write_text(render_comparison_markdown(comparison), encoding="utf-8")
    (out_dir / "comparison.html").write_text(render_comparison_html(comparison), encoding="utf-8")


def render_comparison_markdown(comparison: dict[str, Any]) -> str:
    delta = comparison["risk_delta"]
    lines = [
        "# Comparaison OSINT",
        "",
        f"- Ancienne cible: `{comparison['old_target']}`",
        f"- Nouvelle cible: `{comparison['new_target']}`",
        f"- Ancien rapport: `{comparison['old_generated_at']}`",
        f"- Nouveau rapport: `{comparison['new_generated_at']}`",
        f"- Score: {delta['old_score']} -> {delta['new_score']} ({delta['delta']:+})",
        "",
        "## Synthese",
        "",
        "| Section | Ajoutes | Retires |",
        "| --- | ---: | ---: |",
    ]
    for section, counts in comparison["summary"].items():
        lines.append(f"| {section} | {counts['added']} | {counts['removed']} |")
    lines.append("")
    for section, changes in comparison["changes"].items():
        lines.extend([f"## {section}", ""])
        if not changes["added"] and not changes["removed"]:
            lines.extend(["Aucun changement.", ""])
            continue
        for label, values in (("Ajoutes", changes["added"]), ("Retires", changes["removed"])):
            lines.append(f"### {label}")
            if values:
                lines.extend(f"- `{escape_md(value)}`" for value in values[:100])
            else:
                lines.append("Aucun.")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_comparison_html(comparison: dict[str, Any]) -> str:
    delta = comparison["risk_delta"]
    summary_rows = [
        [section, counts["added"], counts["removed"]]
        for section, counts in comparison["summary"].items()
    ]
    change_sections = []
    for section, changes in comparison["changes"].items():
        rows = [[value, "added"] for value in changes["added"][:150]]
        rows.extend([value, "removed"] for value in changes["removed"][:150])
        change_sections.append(f"<h2>{html_escape(section)}</h2>{html_table(['Valeur', 'Etat'], rows)}")
    return f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Comparaison OSINT</title>
  <style>
    body {{ font-family: Arial, Helvetica, sans-serif; margin: 0; background: #f5f7fb; color: #17202a; }}
    header {{ background: #102a43; color: #fff; padding: 28px 36px; }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 28px 20px 48px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d9e1ea; }}
    th, td {{ border-bottom: 1px solid #d9e1ea; padding: 9px 10px; text-align: left; overflow-wrap: anywhere; }}
    th {{ background: #eaf1f8; }}
    h2 {{ margin-top: 30px; }}
    code {{ background: #edf2f7; padding: 2px 5px; border-radius: 4px; }}
  </style>
</head>
<body>
  <header>
    <h1>Comparaison OSINT</h1>
    <p>Cibles: <code>{html_escape(comparison['old_target'])}</code> vers <code>{html_escape(comparison['new_target'])}</code></p>
    <p>Score: <code>{delta['old_score']}</code> vers <code>{delta['new_score']}</code> ({delta['delta']:+})</p>
  </header>
  <main>
    <h2>Synthese</h2>
    {html_table(["Section", "Ajoutes", "Retires"], summary_rows)}
    {''.join(change_sections)}
  </main>
</body>
</html>
"""


def parse_sources(value: str) -> list[str]:
    selected = [item.strip().lower() for item in value.split(",") if item.strip()]
    if not selected or selected == ["all"]:
        return list(SOURCE_NAMES)
    unknown = sorted(set(selected) - set(SOURCE_NAMES))
    if unknown:
        raise argparse.ArgumentTypeError(f"Unknown source(s): {', '.join(unknown)}")
    return selected


def default_output_dir(target: str) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(__file__).resolve().parent / "reports" / f"{target}-{stamp}"


def default_comparison_output_dir() -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(__file__).resolve().parent / "reports" / f"compare-{stamp}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passive OSINT harvester for a domain target.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="Domain to analyze, for example example.com")
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("OLD_JSON", "NEW_JSON"),
        type=Path,
        help="Compare two report.json files and generate comparison outputs",
    )
    parser.add_argument(
        "--sources",
        type=parse_sources,
        default=list(SOURCE_NAMES),
        help="Comma-separated source list, or all",
    )
    parser.add_argument("--limit", type=int, default=100, help="Maximum records per source")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between source calls")
    parser.add_argument(
        "--metadata-limit",
        type=int,
        default=3,
        help="Maximum public documents to fetch for embedded metadata; use 0 to disable",
    )
    parser.add_argument(
        "--max-doc-bytes",
        type=int,
        default=5_000_000,
        help="Maximum bytes downloaded per document",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output directory. Defaults to reports/<target>-<timestamp>",
    )
    return parser


def run_source(name: str, state: HarvestState, args: argparse.Namespace) -> None:
    runners = {
        "crtsh": run_crtsh,
        "dns": run_dns,
        "wayback": run_wayback,
        "urlscan": run_urlscan,
        "hackertarget": run_hackertarget,
    }
    runner = runners[name]
    print(f"[+] Source {name}")
    try:
        runner(state, args.timeout, args.limit)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        state.add_error(name, str(exc))
        print(f"[!] {name}: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.compare:
        try:
            old_report = load_json_report(args.compare[0])
            new_report = load_json_report(args.compare[1])
            comparison = compare_reports(old_report, new_report)
        except ValueError as exc:
            parser.error(str(exc))
        out_dir = args.out or default_comparison_output_dir()
        write_comparison_outputs(comparison, out_dir)
        print(f"[+] Comparison written to: {out_dir}")
        print(
            "[+] Risk score: "
            f"{comparison['risk_delta']['old_score']} -> "
            f"{comparison['risk_delta']['new_score']} "
            f"({comparison['risk_delta']['delta']:+})"
        )
        return 0

    if not args.target:
        parser.error("target is required unless --compare is used")

    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    if args.limit < 1:
        parser.error("--limit must be >= 1")
    if args.timeout < 1:
        parser.error("--timeout must be >= 1")
    if args.metadata_limit < 0:
        parser.error("--metadata-limit must be >= 0")
    if args.max_doc_bytes < 100_000:
        parser.error("--max-doc-bytes must be >= 100000")

    state = HarvestState(target=target, started_at=now_utc())
    print(f"[*] Passive OSINT collection for {target}")
    print("[*] Authorized use only. No port scan, no login attempt, no exploitation.")

    for source in args.sources:
        time.sleep(args.delay)
        run_source(source, state, args)

    fetch_document_metadata(state, args.timeout, args.metadata_limit, args.max_doc_bytes, args.delay)

    report = build_report(state)
    out_dir = args.out or default_output_dir(target)
    write_outputs(report, out_dir)
    print(f"[+] Report written to: {out_dir}")
    print(
        "[+] Summary: "
        f"{report['summary']['subdomains']} subdomains, "
        f"{report['summary']['emails']} emails, "
        f"{report['summary']['documents']} documents, "
        f"{report['summary']['metadata_records']} metadata records"
    )
    if report["summary"]["errors"]:
        print(f"[!] Completed with {report['summary']['errors']} source error(s); see report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
