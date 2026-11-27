"""Test tools/safe_extract.py: path traversal, symlink, zip bomb, dọn thư mục tạm.

Mọi archive độc hại đều được dựng tại chỗ trong tmp_path, không dùng mẫu thật.
"""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from tools.safe_extract import (
    ExtractionError,
    Limits,
    extract_package,
    extracted,
)


# ---------- helpers ----------

def make_tar(path: Path, entries: list[tarfile.TarInfo | tuple[str, bytes]], mode: str = "w:gz") -> Path:
    with tarfile.open(path, mode) as tf:
        for e in entries:
            if isinstance(e, tarfile.TarInfo):
                tf.addfile(e)
            else:
                name, data = e
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                ti.mode = 0o755
                tf.addfile(ti, io.BytesIO(data))
    return path


def tar_link(name: str, target: str, hard: bool = False) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.LNKTYPE if hard else tarfile.SYMTYPE
    ti.linkname = target
    return ti


def make_zip(path: Path, entries: list[tuple[str, bytes] | zipfile.ZipInfo | tuple[zipfile.ZipInfo, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for e in entries:
            if isinstance(e[0], zipfile.ZipInfo):
                info, data = e
                zf.writestr(info, data)
            else:
                name, data = e
                zf.writestr(name, data)
    return path


@pytest.fixture
def work(tmp_path: Path) -> dict[str, Path]:
    """`outside` mô phỏng vùng ngoài thư mục giải nén; `temp_root` chứa thư mục tạm."""
    d = {"src": tmp_path / "src", "temp_root": tmp_path / "temp_root", "outside": tmp_path}
    d["src"].mkdir()
    d["temp_root"].mkdir()
    return d


def all_files_under(p: Path) -> set[Path]:
    return {x for x in p.rglob("*")}


# ---------- giải nén bình thường ----------

def test_normal_sdist(work):
    arc = make_tar(work["src"] / "pkg-1.0.tar.gz", [
        ("pkg-1.0/setup.py", b"from setuptools import setup\nsetup()\n"),
        ("pkg-1.0/pkg/__init__.py", b""),
        ("pkg-1.0/PKG-INFO", b"Name: pkg\n"),
    ])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        assert r.archive_type == "tar"
        assert sorted(r.files) == ["pkg-1.0/PKG-INFO", "pkg-1.0/pkg/__init__.py", "pkg-1.0/setup.py"]
        setup = r.root / "pkg-1.0" / "setup.py"
        assert setup.read_text() == "from setuptools import setup\nsetup()\n"
        assert r.warnings == []
        assert r.total_bytes > 0


def test_normal_wheel(work):
    arc = make_zip(work["src"] / "pkg-1.0-py3-none-any.whl", [
        ("pkg/__init__.py", b"x = 1\n"),
        ("pkg-1.0.dist-info/METADATA", b"Name: pkg\n"),
    ])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        assert r.archive_type == "zip"
        assert set(r.files) == {"pkg/__init__.py", "pkg-1.0.dist-info/METADATA"}


def test_exec_bit_removed(work):
    arc = make_tar(work["src"] / "p.tar.gz", [("p/run.sh", b"#!/bin/sh\n")])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        mode = (r.root / "p" / "run.sh").stat().st_mode
        assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# ---------- path traversal ----------

@pytest.mark.parametrize("evil", [
    "../evil.txt",
    "pkg/../../evil.txt",
    "/tmp/evil.txt",
    "..\\evil.txt",
    "pkg\\..\\..\\evil.txt",
    "C:/evil.txt",
    "C:evil.txt",
])
def test_tar_path_traversal(work, evil):
    arc = make_tar(work["src"] / "p.tar.gz", [(evil, b"pwned"), ("p/ok.py", b"ok")])
    before = all_files_under(work["outside"])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        assert r.files == ["p/ok.py"]
        assert any("không an toàn" in w for w in r.warnings)
    # không có file mới nào ngoài temp_root (thư mục tạm đã bị xoá)
    assert all_files_under(work["outside"]) == before
    assert not (work["outside"] / "evil.txt").exists()


@pytest.mark.parametrize("evil", ["../evil.txt", "a/../../evil.txt", "/abs/evil.txt", "..\\evil.txt"])
def test_zip_path_traversal(work, evil):
    arc = make_zip(work["src"] / "p.whl", [(evil, b"pwned"), ("ok.py", b"ok")])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        assert r.files == ["ok.py"]
        assert any("không an toàn" in w for w in r.warnings)
    assert not (work["outside"] / "evil.txt").exists()
    assert not (work["temp_root"] / "evil.txt").exists()


# ---------- symlink / hardlink / file đặc biệt ----------

def test_tar_symlink_skipped(work):
    arc = make_tar(work["src"] / "p.tar.gz", [
        tar_link("p/link", "/etc/passwd"),
        tar_link("p/up", "../../.."),
        ("p/ok.py", b"ok"),
    ])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        assert r.files == ["p/ok.py"]
        assert not (r.root / "p" / "link").exists()
        assert not (r.root / "p" / "up").is_symlink()
        assert sum("link" in w for w in r.warnings) == 2


def test_tar_symlink_then_write_through_it(work):
    """Kỹ thuật cổ điển: tạo symlink trỏ ra ngoài rồi ghi file 'qua' symlink đó."""
    victim = work["outside"] / "victim"
    victim.mkdir()
    arc = make_tar(work["src"] / "p.tar.gz", [
        tar_link("esc", str(victim)),
        ("esc/pwned.txt", b"pwned"),
    ])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        # 'esc' trở thành thư mục thường bên trong root, không phải symlink
        assert (r.root / "esc" / "pwned.txt").is_file()
        assert not (r.root / "esc").is_symlink()
    assert list(victim.iterdir()) == []


def test_tar_hardlink_skipped(work):
    arc = make_tar(work["src"] / "p.tar.gz", [
        ("p/a.py", b"a"),
        tar_link("p/hard", "/etc/passwd", hard=True),
    ])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        assert r.files == ["p/a.py"]
        assert any("link" in w for w in r.warnings)


def test_tar_device_and_fifo_skipped(work):
    dev = tarfile.TarInfo("p/dev")
    dev.type = tarfile.CHRTYPE
    fifo = tarfile.TarInfo("p/fifo")
    fifo.type = tarfile.FIFOTYPE
    arc = make_tar(work["src"] / "p.tar.gz", [dev, fifo, ("p/ok.py", b"ok")])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        assert r.files == ["p/ok.py"]
        assert sum("đặc biệt" in w for w in r.warnings) == 2


def test_zip_symlink_skipped(work):
    info = zipfile.ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    arc = make_zip(work["src"] / "p.whl", [(info, b"/etc/passwd"), ("ok.py", b"ok")])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        assert r.files == ["ok.py"]
        assert not (r.root / "link").exists()
        assert any("link" in w for w in r.warnings)


def test_duplicate_entry_not_overwritten(work):
    arc = make_tar(work["src"] / "p.tar.gz", [("p/a.py", b"first"), ("p/a.py", b"second")])
    with extracted(arc, temp_root=work["temp_root"]) as r:
        assert (r.root / "p" / "a.py").read_bytes() == b"first"
        assert any("trùng" in w for w in r.warnings)


# ---------- zip bomb / giới hạn ----------

def test_zip_bomb_total_size(work):
    big = b"\0" * (2 * 1024 * 1024)
    arc = make_zip(work["src"] / "bomb.zip", [(f"f{i}", big) for i in range(5)])
    limits = Limits(max_total_bytes=5 * 1024 * 1024, max_file_bytes=10 * 1024 * 1024, max_ratio=10_000)
    with pytest.raises(ExtractionError, match="tổng"):
        extract_package(arc, temp_root=work["temp_root"], limits=limits)
    assert list(work["temp_root"].iterdir()) == []  # đã dọn


def test_zip_bomb_ratio(work):
    arc = make_zip(work["src"] / "bomb.whl", [("zeros", b"\0" * (10 * 1024 * 1024))])
    with pytest.raises(ExtractionError, match="tỉ lệ nén"):
        extract_package(arc, temp_root=work["temp_root"])  # mặc định max_ratio=100
    assert list(work["temp_root"].iterdir()) == []


def test_tar_gzip_bomb_file_size(work):
    arc = make_tar(work["src"] / "bomb.tar.gz", [("zeros", b"\0" * (3 * 1024 * 1024))])
    limits = Limits(max_file_bytes=1024 * 1024)
    with pytest.raises(ExtractionError, match="mỗi file"):
        extract_package(arc, temp_root=work["temp_root"], limits=limits)
    assert list(work["temp_root"].iterdir()) == []


def test_lying_zip_header(work):
    """Header khai báo 10 B nhưng dữ liệu thực 4096 B: zipfile chỉ đọc đúng số byte
    khai báo rồi báo sai CRC; safe_extract đổi thành ExtractionError và dọn thư mục.
    (Lớp đếm byte thực trong _Budget.write là lớp phòng thủ thứ hai.)"""
    path = work["src"] / "liar.zip"
    make_zip(path, [("data", b"A" * 4096)])
    raw = bytearray(path.read_bytes())
    # Sửa file_size trong central directory (offset +24) và local header (offset +22) thành 10.
    cd = raw.rfind(b"PK\x01\x02")
    raw[cd + 24:cd + 28] = (10).to_bytes(4, "little")
    raw[22:26] = (10).to_bytes(4, "little")
    path.write_bytes(raw)
    limits = Limits(max_file_bytes=100, max_ratio=10_000)
    with pytest.raises(ExtractionError, match="CRC|vượt"):
        extract_package(path, temp_root=work["temp_root"], limits=limits)
    assert list(work["temp_root"].iterdir()) == []


def test_too_many_files_tar(work):
    arc = make_tar(work["src"] / "many.tar.gz", [(f"p/f{i}.py", b"x") for i in range(20)])
    with pytest.raises(ExtractionError, match="số file"):
        extract_package(arc, temp_root=work["temp_root"], limits=Limits(max_files=10))
    assert list(work["temp_root"].iterdir()) == []


def test_too_many_files_zip(work):
    arc = make_zip(work["src"] / "many.whl", [(f"f{i}.py", b"x") for i in range(20)])
    with pytest.raises(ExtractionError, match="số file"):
        extract_package(arc, temp_root=work["temp_root"], limits=Limits(max_files=10))


# ---------- định dạng và dọn dẹp ----------

def test_unsupported_format(work):
    p = work["src"] / "x.bin"
    p.write_bytes(b"not an archive")
    with pytest.raises(ExtractionError, match="không hỗ trợ"):
        extract_package(p, temp_root=work["temp_root"])


def test_corrupt_archive(work):
    p = work["src"] / "x.tar.gz"
    p.write_bytes(b"\x1f\x8bgarbage")
    with pytest.raises(ExtractionError):
        extract_package(p, temp_root=work["temp_root"])
    assert list(work["temp_root"].iterdir()) == []


def test_missing_file(work):
    with pytest.raises(ExtractionError, match="không tìm thấy"):
        extract_package(work["src"] / "nope.tar.gz", temp_root=work["temp_root"])


def test_each_sample_own_tempdir_and_cleanup(work):
    arc = make_tar(work["src"] / "p.tar.gz", [("p/a.py", b"a")])
    with extracted(arc, temp_root=work["temp_root"]) as r1, extracted(arc, temp_root=work["temp_root"]) as r2:
        assert r1.root != r2.root
        assert r1.root.is_dir() and r2.root.is_dir()
    assert not r1.root.exists() and not r2.root.exists()


def test_cleanup_on_exception_inside_with(work):
    arc = make_tar(work["src"] / "p.tar.gz", [("p/a.py", b"a")])
    with pytest.raises(RuntimeError):
        with extracted(arc, temp_root=work["temp_root"]) as r:
            root = r.root
            raise RuntimeError("phân tích lỗi")
    assert not root.exists()
