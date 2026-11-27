"""Tool `check_typosquat`: so tên gói với danh sách gói PyPI phổ biến lưu offline.

Phát hiện: khoảng cách Levenshtein nhỏ, đảo 2 ký tự kề nhau, đổi ký tự trông giống nhau
(0/o, 1/l, rn/m…), thêm/bớt dấu phân cách, thêm tiền tố/hậu tố (python-, -py, -lib, số).
Tên được chuẩn hoá theo PEP 503 trước khi so.

Cập nhật danh sách (chỉ tải danh sách tên, không tải gói):
    python -m tools.typosquat refresh [--top 5000]
"""

from __future__ import annotations

import re
import sys
from functools import lru_cache
from pathlib import Path

NAME = "check_typosquat"
DESCRIPTION = (
    "So tên gói với danh sách gói PyPI phổ biến (offline): Levenshtein, đảo ký tự, ký tự giống nhau, "
    "tiền tố/hậu tố. Nếu không truyền name, tự đọc tên từ metadata."
)
INPUT_SCHEMA = {"name": "tên gói (tuỳ chọn)"}

DEFAULT_LIST = Path(__file__).resolve().parent.parent / "data" / "top_pypi_packages.txt"
TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"

HOMOGLYPHS = [("0", "o"), ("1", "l"), ("1", "i"), ("l", "i"), ("rn", "m"), ("vv", "w"), ("5", "s"), ("3", "e"),
              ("cl", "d"), ("q", "g")]
AFFIXES = ["python-", "py-", "py", "python", "-python", "-py", "py", "-lib", "lib", "-dev", "-sdk", "-api",
           "-tools", "-utils", "-cli", "-core", "-client", "-v2", "2", "3", "-official", "-latest", "-fix"]


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def levenshtein(a: str, b: str, limit: int = 3) -> int:
    """Khoảng cách Damerau–Levenshtein (OSA), dừng sớm khi vượt limit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


@lru_cache(maxsize=4)
def load_top(path: str = str(DEFAULT_LIST)) -> tuple[str, ...]:
    p = Path(path)
    if not p.is_file():
        return ()
    names = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(normalize(line))
    return tuple(dict.fromkeys(names))


def _variants(n: str) -> set[str]:
    out = {n.replace("-", ""), n}
    for a, b in HOMOGLYPHS:
        if a in n:
            out.add(n.replace(a, b))
        if b in n:
            out.add(n.replace(b, a))
    for af in AFFIXES:
        if af.endswith("-") or not af.startswith("-"):
            if n.startswith(af) and len(n) > len(af) + 2:
                out.add(n[len(af):].strip("-"))
        if af.startswith("-") or not af.endswith("-"):
            if n.endswith(af) and len(n) > len(af) + 2:
                out.add(n[: -len(af)].strip("-"))
    return out


def check(name: str, top: tuple[str, ...]) -> dict:
    n = normalize(name)
    if not n:
        return {"error": "tên rỗng"}
    top_set = set(top)
    if n in top_set:
        return {"name": n, "is_popular_package": True, "suspected_targets": [],
                "note": "tên trùng gói phổ biến; nếu nội dung khác bản gốc thì có thể là gói giả mạo hoặc fork"}

    hits: dict[str, dict] = {}
    nodash = n.replace("-", "")
    for t in top:
        reason = None
        if t.replace("-", "") == nodash:
            reason = "khác dấu phân cách"
        else:
            limit = 1 if len(t) <= 5 else 2
            d = levenshtein(n, t, limit)
            if d <= limit:
                reason = f"levenshtein={d}"
                if d == 1 and len(n) == len(t) and sorted(n) == sorted(t):
                    reason = "đảo ký tự kề nhau"
        if reason:
            hits[t] = {"target": t, "reason": reason}
    for v in _variants(n):
        if v != n and v in top_set and v not in hits:
            hits[v] = {"target": v, "reason": "ký tự giống nhau / thêm tiền tố-hậu tố"}

    targets = sorted(hits.values(), key=lambda h: (top.index(h["target"]), h["target"]))[:5]
    return {
        "name": n,
        "is_popular_package": False,
        "suspected_targets": targets,
        "typosquat_suspected": bool(targets),
        "list_size": len(top),
    }


def run(input: dict) -> dict:
    name = input.get("name")
    if not name:
        from tools import metadata
        name = metadata.run({"path": input.get("path", ".")}).get("name")
    if not name:
        return {"error": "không có tên gói (truyền 'name' hoặc gói thiếu metadata)"}
    top = load_top(str(input.get("_top_list", DEFAULT_LIST)))
    if not top:
        return {"error": "chưa có danh sách gói phổ biến (data/top_pypi_packages.txt)"}
    return check(str(name), top)


def _refresh(top_n: int = 5000, dest: Path = DEFAULT_LIST) -> None:
    import requests
    data = requests.get(TOP_URL, timeout=60).json()
    rows = data.get("rows", [])[:top_n]
    dest.write_text("# top-pypi-packages (hugovk), tải tự động\n" + "\n".join(r["project"] for r in rows) + "\n",
                    encoding="utf-8")
    print(f"đã ghi {len(rows)} tên vào {dest}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "refresh":
        n = int(sys.argv[sys.argv.index("--top") + 1]) if "--top" in sys.argv else 5000
        _refresh(n)
    else:
        print("dùng: python -m tools.typosquat refresh [--top 5000]")
