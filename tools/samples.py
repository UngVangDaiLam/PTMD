"""Duyệt bộ mẫu trong data/malicious, data/benign, data/injection và đọc đáp án ground_truth.

Mỗi mẫu là một file nén (.tar.gz/.whl/.zip, kể cả zip có mật khẩu của DataDog) hoặc một
thư mục đã giải nén. `open_sample()` trả thư mục để đọc; với file nén thì giải nén an toàn
vào thư mục tạm (tự xoá), và nếu bên trong chỉ có MỘT file nén nữa thì giải tiếp một lớp.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Iterator
from pathlib import Path

from tools.safe_extract import TAR_SUFFIXES, ZIP_SUFFIXES, ExtractionError, Limits, extracted

ARCHIVE_SUFFIXES = TAR_SUFFIXES + ZIP_SUFFIXES


def sample_id(path: Path) -> str:
    """Tên mẫu = tên file bỏ đuôi nén; dùng để ghép với ground_truth/<id>.json."""
    s = re.sub(r"\.(tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|tar|whl|zip|egg)$", "", path.name, flags=re.I)
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:120] or "package"


def is_archive(p: Path) -> bool:
    return p.is_file() and p.name.lower().endswith(ARCHIVE_SUFFIXES)


def iter_samples(d: Path) -> Iterator[tuple[str, Path]]:
    if not d.is_dir():
        return
    for p in sorted(d.iterdir()):
        if p.name.startswith("."):
            continue
        if is_archive(p) or p.is_dir():
            yield sample_id(p), p


@contextlib.contextmanager
def open_sample(p: Path, password: bytes | None = None, limits: Limits | None = None,
                temp_root: Path | None = None) -> Iterator[Path]:
    if p.is_dir():
        yield p
        return
    with extracted(p, temp_root, limits, password) as r:
        inner = [f for f in r.files if f.lower().endswith(ARCHIVE_SUFFIXES)]
        if len(r.files) == 1 and len(inner) == 1:
            with extracted(r.root / inner[0], temp_root, limits, password) as r2:
                yield r2.root
        else:
            yield r.root


def load_ground_truth(gt_dir: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not gt_dir.is_dir():
        return out
    for p in sorted(gt_dir.glob("*.json")):
        try:
            out[p.stem] = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def family_of(gt: dict | None) -> tuple[str, str]:
    """(tên họ, loại hành vi) từ đáp án; rỗng nếu không có."""
    fam = (gt or {}).get("family") or {}
    return str(fam.get("name") or ""), str(fam.get("behavior_type") or "")


__all__ = ["sample_id", "iter_samples", "open_sample", "load_ground_truth", "family_of", "ExtractionError"]
