"""Tiện ích dùng chung cho các tool: cắt chuỗi, duyệt file mã, băm, trích IOC bằng regex.

Chỉ đọc byte/text, không bao giờ thực thi nội dung mẫu.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlparse

CODE_SUFFIXES = {".py", ".pyw", ".pyi", ".cfg", ".toml", ".txt", ".sh", ".bat", ".ps1", ".js", ".json", ".yml", ".yaml"}
MAX_TEXT_FILE = 2 * 1024 * 1024


def trunc(v: object, n: int = 200) -> str:
    s = str(v)
    return s if len(s) <= n else s[:n] + "…"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(root: Path, suffixes: set[str] | None = None, max_size: int = MAX_TEXT_FILE) -> Iterator[Path]:
    """Duyệt file thường (bỏ symlink), sắp xếp ổn định."""
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if suffixes is not None and p.suffix.lower() not in suffixes:
            continue
        try:
            if p.stat().st_size > max_size:
                continue
        except OSError:
            continue
        yield p


def read_text(p: Path, max_size: int = MAX_TEXT_FILE) -> str | None:
    try:
        if p.stat().st_size > max_size:
            return None
        return p.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return None


def is_binary(b: bytes) -> bool:
    if b"\x00" in b[:4096]:
        return True
    sample = b[:4096]
    if not sample:
        return False
    text = sum(32 <= c < 127 or c in (9, 10, 13) or c >= 128 for c in sample)
    return text / len(sample) < 0.85


def main_code_files(root: Path, limit: int = 5) -> list[Path]:
    """File mã 'chính' để băm/so khớp: setup.py, __init__.py nông nhất, rồi các .py lớn nhất."""
    pys = list(iter_files(root, {".py"}))
    chosen: list[Path] = []
    for name in ("setup.py", "__init__.py"):
        cands = sorted((p for p in pys if p.name == name and p.stat().st_size > 0), key=lambda p: len(p.parts))
        if cands:
            chosen.append(cands[0])
    for p in sorted(pys, key=lambda p: p.stat().st_size, reverse=True):
        if len(chosen) >= limit:
            break
        if p not in chosen and p.stat().st_size > 0:
            chosen.append(p)
    return chosen[:limit]


# ---------------- IOC ----------------

_URL = re.compile(r"""\b(?:https?|ftp|wss?)://[^\s'"<>`\\)\]}]{3,300}""", re.I)
_DISCORD = re.compile(r"(?:discord(?:app)?\.com|canary\.discord\.com)/api/webhooks/\d{5,25}/[\w-]{20,120}", re.I)
_TELEGRAM = re.compile(r"api\.telegram\.org/bot(\d{6,12}:[\w-]{30,50})", re.I)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_TOKENS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("discord_bot_token", re.compile(r"\b[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]
_PATHS = re.compile(
    r"(?:\.ssh[\\/](?:id_rsa|id_ed25519|known_hosts)|\.aws[\\/]credentials|\.bash_history|\.zsh_history|"
    r"/etc/passwd|/etc/shadow|Local Storage[\\/]leveldb|Login Data|Cookies|Local State|"
    r"\.config[\\/]discord|discord[\\/]Local Storage|Exodus[\\/]exodus\.wallet|\.electrum|"
    r"wallet\.dat|\.npmrc|\.pypirc|\.git-credentials|\.docker[\\/]config\.json|\.kube[\\/]config)",
    re.I,
)
# Tên miền vô hại hay gặp trong metadata/README; vẫn trả về nhưng gắn cờ.
COMMON_DOMAINS = {
    "github.com", "pypi.org", "python.org", "www.python.org", "readthedocs.io", "docs.python.org",
    "opensource.org", "www.apache.org", "apache.org", "gnu.org", "www.gnu.org", "files.pythonhosted.org",
    "creativecommons.org", "packaging.python.org", "setuptools.pypa.io", "img.shields.io", "badge.fury.io",
}


def _valid_public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved)


def extract_iocs(text: str, max_items: int = 30) -> list[dict]:
    """Trích IOC kèm số dòng. Trả [{type, value, line, common?}]."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(t: str, v: str, line: int, **extra) -> None:
        key = (t, v)
        if key in seen or len(out) >= max_items:
            return
        seen.add(key)
        out.append({"type": t, "value": trunc(v, 200), "line": line, **extra})

    for ln, line in enumerate(text.splitlines(), 1):
        if len(out) >= max_items:
            break
        if len(line) > 20000:
            line = line[:20000]
        for m in _DISCORD.finditer(line):
            add("webhook", "https://" + m.group(0), ln)
        for m in _TELEGRAM.finditer(line):
            add("webhook", "https://" + m.group(0), ln)
            add("token", m.group(1), ln, token_kind="telegram_bot_token")
        for m in _URL.finditer(line):
            url = m.group(0).rstrip(".,;:'\"")
            if _DISCORD.search(url) or _TELEGRAM.search(url):
                continue
            host = (urlparse(url).hostname or "").lower()
            common = host in COMMON_DOMAINS or any(host.endswith("." + d) for d in COMMON_DOMAINS)
            add("url", url, ln, **({"common": True} if common else {}))
            if host and not _IPV4.fullmatch(host):
                add("domain", host, ln, **({"common": True} if common else {}))
        for m in _IPV4.finditer(line):
            if _valid_public_ip(m.group(0)):
                ip = ipaddress.ip_address(m.group(0))
                add("ip", m.group(0), ln, **({"private": True} if ip.is_private else {}))
        for kind, rx in _TOKENS:
            for m in rx.finditer(line):
                add("token", m.group(0), ln, token_kind=kind)
        for m in _PATHS.finditer(line):
            add("path", m.group(0).strip(" '\""), ln)
    return out
