"""Giải nén an toàn gói PyPI (.tar.gz/.tgz/.tar/.tar.bz2/.tar.xz sdist, .whl/.zip).

Nguyên tắc (CLAUDE.md mục 2):
- Không bao giờ thực thi gì trong gói; chỉ ghi byte ra đĩa để đọc dạng text.
- Mỗi gói giải nén vào một thư mục tạm riêng, xoá sau khi phân tích
  (dùng context manager `extracted()`).
- Chặn path traversal (`../`, đường dẫn tuyệt đối, ổ đĩa Windows, `\\`).
- Không tạo symlink, hardlink, file thiết bị, FIFO: các entry này bị bỏ qua
  và ghi vào `warnings` (bản thân chúng là dấu hiệu đáng ngờ, agent cần thấy).
- Chống zip bomb: giới hạn số file, kích thước từng file, tổng kích thước,
  tỉ lệ nén khai báo; đồng thời đếm byte thực ghi ra (header zip có thể nói dối).
  Vượt giới hạn thì huỷ toàn bộ, xoá thư mục tạm, ném `ExtractionError`.

Không dùng `extractall`: mỗi file thường được đọc qua stream và tự ghi ra,
nên kiểm soát hết đường dẫn, quyền file (không giữ bit thực thi) và số byte.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO

DEFAULT_MAX_TOTAL_BYTES = 200 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_RATIO = 100
_CHUNK = 64 * 1024

TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
ZIP_SUFFIXES = (".whl", ".zip", ".egg")


class ExtractionError(Exception):
    """Gói không giải nén được hoặc vượt giới hạn an toàn."""


@dataclass
class Limits:
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_files: int = DEFAULT_MAX_FILES
    max_ratio: float = DEFAULT_MAX_RATIO


@dataclass
class ExtractResult:
    root: Path
    archive_type: str
    files: list[str] = field(default_factory=list)
    total_bytes: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "archive_type": self.archive_type,
            "files_count": len(self.files),
            "files": self.files,
            "total_bytes": self.total_bytes,
            "warnings": self.warnings,
        }


class _Budget:
    """Đếm số file và số byte thực ghi ra đĩa."""

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.files = 0
        self.total = 0

    def add_file(self) -> None:
        self.files += 1
        if self.files > self.limits.max_files:
            raise ExtractionError(f"vượt số file tối đa ({self.limits.max_files})")

    def check_declared(self, name: str, size: int, compressed: int | None = None) -> None:
        if size > self.limits.max_file_bytes:
            raise ExtractionError(f"{name}: kích thước khai báo {size} B vượt giới hạn mỗi file")
        if self.total + size > self.limits.max_total_bytes:
            raise ExtractionError("tổng kích thước khai báo vượt giới hạn")
        if compressed is not None and size > 0:
            ratio = size / max(compressed, 1)
            if ratio > self.limits.max_ratio:
                raise ExtractionError(f"{name}: tỉ lệ nén {ratio:.0f}x vượt giới hạn {self.limits.max_ratio}x")

    def write(self, name: str, src: BinaryIO, dst: Path) -> int:
        written = 0
        with open(dst, "xb") as out:  # "x": không ghi đè file đã có
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                self.total += len(chunk)
                if written > self.limits.max_file_bytes:
                    raise ExtractionError(f"{name}: dữ liệu thực vượt giới hạn mỗi file")
                if self.total > self.limits.max_total_bytes:
                    raise ExtractionError("tổng dữ liệu thực vượt giới hạn")
                out.write(chunk)
        os.chmod(dst, stat.S_IRUSR | stat.S_IWUSR)  # bỏ mọi bit thực thi
        return written


def _safe_relpath(name: str) -> PurePosixPath | None:
    """Chuẩn hoá tên entry; trả None nếu tên không an toàn."""
    if not name or "\x00" in name:
        return None
    norm = name.replace("\\", "/")
    if norm.startswith("/") or PureWindowsPath(name).drive or PureWindowsPath(name).root:
        return None
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    # Tên có ':' gây ADS trên NTFS / ổ đĩa ngầm; không hợp lệ trong gói Python bình thường.
    if any(":" in p for p in parts):
        return None
    # Tên thiết bị của Windows (CON, NUL, COM1...) chỉ nguy hiểm khi chạy trên Windows.
    if os.name == "nt" and any(p.split(".")[0].upper().rstrip(" ") in _WIN_RESERVED for p in parts):
        return None
    return PurePosixPath(*parts)


_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{d}{i}" for d in ("COM", "LPT") for i in range(1, 10)
}


def _target(root: Path, rel: PurePosixPath) -> Path:
    target = (root / Path(*rel.parts)).resolve()
    root_resolved = root.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ExtractionError(f"đường dẫn thoát khỏi thư mục giải nén: {rel}")
    return target


def detect_type(path: Path) -> str:
    lower = path.name.lower()
    if lower.endswith(ZIP_SUFFIXES):
        return "zip"
    if lower.endswith(TAR_SUFFIXES):
        return "tar"
    # Đuôi lạ: đoán theo nội dung (chỉ đọc header, không thực thi).
    if zipfile.is_zipfile(path):
        return "zip"
    if tarfile.is_tarfile(path):
        return "tar"
    raise ExtractionError(f"định dạng không hỗ trợ: {path.name}")


def _prepare_dir(root: Path, rel: PurePosixPath) -> Path:
    d = _target(root, rel)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _extract_tar(archive: Path, root: Path, budget: _Budget, result: ExtractResult) -> None:
    try:
        tf = tarfile.open(archive, mode="r:*")
    except (tarfile.TarError, OSError) as e:
        raise ExtractionError(f"không mở được tar: {e}") from e
    with tf:
        for m in tf:  # duyệt lần lượt, không gọi getmembers() để tránh nạp hết vào RAM
            rel = _safe_relpath(m.name)
            if rel is None:
                result.warnings.append(f"bỏ qua entry có đường dẫn không an toàn: {m.name!r}")
                continue
            if m.issym() or m.islnk():
                result.warnings.append(f"bỏ qua link: {m.name!r} -> {m.linkname!r}")
                continue
            if m.isdir():
                _prepare_dir(root, rel)
                continue
            if not m.isreg():
                result.warnings.append(f"bỏ qua entry đặc biệt (thiết bị/FIFO): {m.name!r}")
                continue
            budget.add_file()
            budget.check_declared(m.name, m.size)
            dst = _target(root, rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                result.warnings.append(f"bỏ qua entry trùng tên: {m.name!r}")
                continue
            src = tf.extractfile(m)
            if src is None:
                continue
            with src:
                budget.write(m.name, src, dst)
            result.files.append(rel.as_posix())


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def _extract_zip(archive: Path, root: Path, budget: _Budget, result: ExtractResult,
                 password: bytes | None = None) -> None:
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as e:
        raise ExtractionError(f"không mở được zip: {e}") from e
    with zf:
        infos = zf.infolist()
        if len(infos) > budget.limits.max_files:
            raise ExtractionError(f"vượt số file tối đa ({budget.limits.max_files})")
        for info in infos:
            rel = _safe_relpath(info.filename)
            if rel is None:
                result.warnings.append(f"bỏ qua entry có đường dẫn không an toàn: {info.filename!r}")
                continue
            if _zip_is_symlink(info):
                result.warnings.append(f"bỏ qua link: {info.filename!r}")
                continue
            if info.is_dir():
                _prepare_dir(root, rel)
                continue
            mode = info.external_attr >> 16
            if mode and not (stat.S_ISREG(mode) or stat.S_IFMT(mode) == 0):
                result.warnings.append(f"bỏ qua entry đặc biệt: {info.filename!r}")
                continue
            encrypted = bool(info.flag_bits & 0x1)
            if encrypted and password is None:
                result.warnings.append(f"bỏ qua entry bị mã hoá (chưa cấu hình mật khẩu): {info.filename!r}")
                continue
            budget.add_file()
            budget.check_declared(info.filename, info.file_size, info.compress_size)
            dst = _target(root, rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                result.warnings.append(f"bỏ qua entry trùng tên: {info.filename!r}")
                continue
            try:
                with zf.open(info, pwd=password if encrypted else None) as src:
                    budget.write(info.filename, src, dst)
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as e:
                dst.unlink(missing_ok=True)
                raise ExtractionError(f"{info.filename}: lỗi đọc entry: {e}") from e
            result.files.append(rel.as_posix())


def extract_package(
    archive: str | os.PathLike[str],
    temp_root: str | os.PathLike[str] | None = None,
    limits: Limits | None = None,
    password: bytes | None = None,
) -> ExtractResult:
    """Giải nén `archive` vào một thư mục tạm mới. Người gọi chịu trách nhiệm xoá
    (`cleanup(result)`); nên dùng `extracted()` để tự xoá.

    `password`: mật khẩu zip của bộ dữ liệu mẫu (vd. DataDog dùng b"infected"). Chỉ áp dụng
    cho entry bị mã hoá; mọi giới hạn an toàn vẫn giữ nguyên.

    Lỗi bất kỳ thì thư mục tạm bị xoá trước khi ném `ExtractionError`.
    """
    archive = Path(archive)
    if not archive.is_file():
        raise ExtractionError(f"không tìm thấy file: {archive}")
    limits = limits or Limits()
    kind = detect_type(archive)
    root = Path(tempfile.mkdtemp(prefix="cmp198_", dir=temp_root))
    result = ExtractResult(root=root, archive_type=kind)
    budget = _Budget(limits)
    try:
        if kind == "tar":
            _extract_tar(archive, root, budget, result)
        else:
            _extract_zip(archive, root, budget, result, password)
    except ExtractionError:
        shutil.rmtree(root, ignore_errors=True)
        raise
    except Exception as e:  # lỗi bất ngờ vẫn phải dọn thư mục tạm
        shutil.rmtree(root, ignore_errors=True)
        raise ExtractionError(f"lỗi giải nén: {e}") from e
    result.total_bytes = budget.total
    return result


def cleanup(result: ExtractResult) -> None:
    shutil.rmtree(result.root, ignore_errors=True)


@contextlib.contextmanager
def extracted(
    archive: str | os.PathLike[str],
    temp_root: str | os.PathLike[str] | None = None,
    limits: Limits | None = None,
    password: bytes | None = None,
) -> Iterator[ExtractResult]:
    """`with extracted("pkg.tar.gz") as r: ...` — thư mục tạm bị xoá khi thoát."""
    result = extract_package(archive, temp_root, limits, password)
    try:
        yield result
    finally:
        cleanup(result)


def limits_from_config(cfg: dict) -> Limits:
    """Tạo Limits từ mục `extract` của config.yaml."""
    ex = cfg.get("extract", {}) if cfg else {}
    return Limits(
        max_total_bytes=int(ex.get("max_total_bytes", DEFAULT_MAX_TOTAL_BYTES)),
        max_file_bytes=int(ex.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)),
        max_files=int(ex.get("max_files", DEFAULT_MAX_FILES)),
        max_ratio=float(ex.get("max_ratio", DEFAULT_MAX_RATIO)),
    )
