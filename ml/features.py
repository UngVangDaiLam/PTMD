"""Trích token từ mã nguồn gói (chỉ đọc text) cho mô hình TF-IDF + Random Forest.

Token gồm: tên định danh / tên có chấm (os.environ, requests.post…), từ khoá Python, và
token đặc biệt thay cho giá trị cụ thể để mô hình học HÀNH VI chứ không học IOC:
__URL__, __IP__, __WEBHOOK__, __B64BLOB__, __HEXBLOB__, __LONGLINE__, __CMDCLASS__, __SETUP_PY__.
"""

from __future__ import annotations

import re
from pathlib import Path

from tools.common import iter_files, read_text

FEATURE_VERSION = 1
MAX_TOKENS = 60_000

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_URL = re.compile(r"""(?:https?|ftp|wss?)://[^\s'"<>]+""", re.I)
_WEBHOOK = re.compile(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot", re.I)
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_B64 = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}|[0-9a-fA-F]{120,}")


def tokens_of_text(text: str, is_setup: bool = False) -> list[str]:
    toks: list[str] = ["__SETUP_PY__"] if is_setup else []
    for line in text.splitlines():
        if len(line) > 1000:
            toks.append("__LONGLINE__")
        if _WEBHOOK.search(line):
            toks.append("__WEBHOOK__")
        toks += ["__URL__"] * len(_URL.findall(line))
        toks += ["__IP__"] * len(_IP.findall(line))
        toks += ["__B64BLOB__"] * len(_B64.findall(line))
        toks += ["__HEXBLOB__"] * len(_HEX.findall(line))
        clean = _B64.sub(" ", _HEX.sub(" ", _URL.sub(" ", line)))
        for m in _IDENT.findall(clean[:2000]):
            if len(m) > 1 and len(m) <= 60:
                toks.append(m.lower())
        if "cmdclass" in line:
            toks.append("__CMDCLASS__")
    return toks


def tokens_of_package(root: Path) -> str:
    """Trả chuỗi token nối bằng dấu cách (đầu vào cho TfidfVectorizer(tokenizer=str.split))."""
    toks: list[str] = []
    for p in iter_files(root, {".py", ".pyw", ".cfg", ".toml"}):
        text = read_text(p)
        if text is None:
            continue
        toks += tokens_of_text(text, is_setup=p.name == "setup.py")
        if len(toks) >= MAX_TOKENS:
            break
    return " ".join(toks[:MAX_TOKENS])
