"""Tool `fuzzy_similarity`: ssdeep (ppdeep) + TLSH của các file mã chính, so với chỉ mục mẫu đã biết họ.

Chỉ mục `data/fuzzy_index.json` dựng từ data/malicious + data/ground_truth:
    python -m tools.fuzzy build [--password infected]

Loại trừ chính gói đang phân tích (cùng SHA-256 gói) để không tự khớp với mình khi đánh giá.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from tools.common import main_code_files, sha256_bytes, sha256_file

NAME = "fuzzy_similarity"
DESCRIPTION = (
    "So độ giống (ssdeep, TLSH) của file mã chính với các mẫu độc đã biết họ. Điểm ssdeep 0-100 "
    "(cao = giống), khoảng cách TLSH (thấp = giống, ≤ 50 là rất gần). Dùng để gom biến thể cùng họ."
)
INPUT_SCHEMA = {"path": "thư mục gói, mặc định '.'"}

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INDEX = PROJECT_ROOT / "data" / "fuzzy_index.json"
SSDEEP_MIN = 40
TLSH_MAX = 100
MIN_BYTES = 64

try:
    import ppdeep
except ImportError:  # pragma: no cover
    ppdeep = None
try:
    import tlsh
except ImportError:  # pragma: no cover
    tlsh = None


def fingerprint(data: bytes) -> dict:
    fp: dict = {"sha256": sha256_bytes(data), "size": len(data)}
    if len(data) >= MIN_BYTES:
        if ppdeep is not None:
            fp["ssdeep"] = ppdeep.hash(data)
        if tlsh is not None:
            h = tlsh.hash(data)
            if h and h != "TNULL":
                fp["tlsh"] = h
    return fp


def fingerprints_of(root: Path, limit: int = 5) -> list[dict]:
    out = []
    for p in main_code_files(root, limit):
        try:
            data = p.read_bytes()
        except OSError:
            continue
        fp = fingerprint(data)
        fp["file"] = p.relative_to(root).as_posix()
        out.append(fp)
    return out


def load_index(path: Path) -> list[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("entries", [])
    except (OSError, json.JSONDecodeError):
        return []


def compare(fps: list[dict], index: list[dict], exclude_package: str = "", top: int = 5) -> list[dict]:
    best: dict[tuple[str, str], dict] = {}
    for fp in fps:
        for e in index:
            if exclude_package and e.get("package_sha256") == exclude_package:
                continue
            score = None
            dist = None
            exact = fp["sha256"] == e.get("sha256")
            if ppdeep is not None and fp.get("ssdeep") and e.get("ssdeep"):
                score = ppdeep.compare(fp["ssdeep"], e["ssdeep"])
            if tlsh is not None and fp.get("tlsh") and e.get("tlsh"):
                try:
                    dist = tlsh.diff(fp["tlsh"], e["tlsh"])
                except ValueError:
                    dist = None
            if not (exact or (score is not None and score >= SSDEEP_MIN) or (dist is not None and dist <= TLSH_MAX)):
                continue
            key = (e.get("sample", ""), fp["file"])
            rank = (1 if exact else 0, score or 0, -(dist if dist is not None else 999))
            cur = best.get(key)
            if cur is None or rank > cur["_rank"]:
                best[key] = {"_rank": rank, "file": fp["file"], "match_sample": e.get("sample"),
                             "match_file": e.get("file"), "family": e.get("family"),
                             "behavior_type": e.get("behavior_type"), "exact": exact,
                             "ssdeep_score": score, "tlsh_distance": dist}
    res = sorted(best.values(), key=lambda x: x["_rank"], reverse=True)[:top]
    for r in res:
        r.pop("_rank")
    return res


def run(input: dict) -> dict:
    root = Path(input.get("path", "."))
    if not root.is_dir():
        return {"error": f"không phải thư mục: {input.get('path')}"}
    if ppdeep is None and tlsh is None:
        return {"error": "chưa cài ppdeep / py-tlsh"}
    index_path = Path(input.get("_index", DEFAULT_INDEX))
    index = load_index(index_path)
    fps = fingerprints_of(root)
    out = {
        "files": [{k: v for k, v in fp.items() if k in ("file", "size", "ssdeep", "tlsh")} for fp in fps],
        "index_size": len(index),
    }
    if not index:
        out["note"] = "chỉ mục mẫu đã biết trống; dựng bằng: python -m tools.fuzzy build"
        out["matches"] = []
        return out
    matches = compare(fps, index, str(input.get("_package_sha256", "")))
    out["matches"] = matches
    fams = sorted({m["family"] for m in matches if m.get("family")})
    out["families_matched"] = fams
    return out


# ---------------- dựng chỉ mục ----------------

def build_index(mal_dir: Path, gt_dir: Path, out: Path, password: bytes | None = None) -> int:
    from tools.samples import family_of, iter_samples, load_ground_truth, open_sample
    gts = load_ground_truth(gt_dir)
    entries = []
    for sid, p in iter_samples(mal_dir):
        fam, beh = family_of(gts.get(sid))
        pkg_sha = sha256_file(p) if p.is_file() else ""
        try:
            with open_sample(p, password) as root:
                for fp in fingerprints_of(root):
                    entries.append({"sample": sid, "package_sha256": pkg_sha, "family": fam,
                                    "behavior_type": beh, **fp})
        except Exception as e:
            print(f"bỏ qua {sid}: {e}", file=sys.stderr)
    out.write_text(json.dumps({"entries": entries}, ensure_ascii=False, indent=1), encoding="utf-8")
    return len(entries)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "build":
        pw = sys.argv[sys.argv.index("--password") + 1].encode() if "--password" in sys.argv else None
        n = build_index(PROJECT_ROOT / "data" / "malicious", PROJECT_ROOT / "data" / "ground_truth", DEFAULT_INDEX, pw)
        print(f"đã ghi {n} dấu vân tay vào {DEFAULT_INDEX}")
    else:
        print("dùng: python -m tools.fuzzy build [--password infected]")
