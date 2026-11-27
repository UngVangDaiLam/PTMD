"""Tool `yara_generate_test`: agent đề xuất luật YARA -> biên dịch -> chạy trên gói hiện tại,
bộ mẫu độc (lọc theo họ / loại hành vi nếu có) và bộ gói sạch -> trả TPR / FPR.

- Luật lỗi cú pháp: trả thông báo lỗi để agent tự sửa.
- `include` bị tắt khi biên dịch (luật không đọc được file khác trên máy).
- Mỗi mẫu được giải nén an toàn (tools.samples.open_sample) và quét từng file dạng byte;
  một gói "khớp" nếu có ít nhất một file khớp. Nội dung mẫu được cache trong RAM.
- Mục tiêu (CLAUDE.md mục 6): TPR ≥ 90% trên mẫu cùng họ, FPR = 0 trên bộ sạch;
  tên luật CMP198_PyPI_<họ>, có meta (description, author = "agent", date, hash mẫu nguồn).
"""

from __future__ import annotations

import re
from pathlib import Path

from tools.common import iter_files
from tools.samples import family_of, iter_samples, load_ground_truth, open_sample

NAME = "yara_generate_test"
DESCRIPTION = (
    "Kiểm tra luật YARA bạn viết: biên dịch, chạy trên gói hiện tại, bộ mẫu độc và bộ gói sạch, "
    "trả TPR/FPR và danh sách mẫu bỏ sót / báo nhầm. Luật nên kết hợp IOC với mẫu mã đặc trưng "
    "(vd. cmdclass + os.environ + requests.post). Tên CMP198_PyPI_<họ>, có meta. Mục tiêu TPR≥0.9, FPR=0."
)
INPUT_SCHEMA = {"rule": "toàn văn luật YARA", "family": "họ hoặc loại hành vi để lọc bộ mẫu độc (tuỳ chọn)"}

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAX_RULE_CHARS = 20_000
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_CACHE_BYTES = 300 * 1024 * 1024
SCAN_TIMEOUT_S = 10

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

# cache nội dung mẫu: path -> (mtime, [(relpath, bytes)])
_CACHE: dict[str, tuple[float, list[tuple[str, bytes]]]] = {}
_CACHE_BYTES = 0


def _load_files(root: Path) -> list[tuple[str, bytes]]:
    out = []
    for p in iter_files(root, None, MAX_FILE_BYTES):
        try:
            out.append((p.relative_to(root).as_posix(), p.read_bytes()))
        except OSError:
            continue
    return out


def sample_files(p: Path, password: bytes | None) -> list[tuple[str, bytes]]:
    global _CACHE_BYTES
    key = str(p.resolve())
    mtime = p.stat().st_mtime
    hit = _CACHE.get(key)
    if hit and hit[0] == mtime:
        return hit[1]
    with open_sample(p, password) as root:
        files = _load_files(root)
    size = sum(len(b) for _, b in files)
    if _CACHE_BYTES + size <= MAX_CACHE_BYTES:
        _CACHE[key] = (mtime, files)
        _CACHE_BYTES += size
    return files


def _string_hits(matches, limit: int = 5) -> list[dict]:
    out = []
    for m in matches:
        for s in getattr(m, "strings", []):
            if hasattr(s, "instances"):  # yara-python >= 4.3
                for inst in s.instances[:2]:
                    out.append({"rule": m.rule, "string": s.identifier, "offset": inst.offset,
                                "data": inst.matched_data[:60].decode("latin-1")})
            elif isinstance(s, tuple):  # bản cũ: (offset, identifier, data)
                out.append({"rule": m.rule, "string": s[1], "offset": s[0], "data": s[2][:60].decode("latin-1")})
            if len(out) >= limit:
                return out
    return out


def match_files(rules, files: list[tuple[str, bytes]]) -> tuple[bool, list[dict]]:
    for rel, data in files:
        try:
            ms = rules.match(data=data, timeout=SCAN_TIMEOUT_S)
        except Exception:
            continue
        if ms:
            return True, [dict(h, file=rel) for h in _string_hits(ms)]
    return False, []


def lint(rule: str) -> list[str]:
    warns = []
    names = re.findall(r"^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_]\w*)", rule, flags=re.M)
    if not names:
        warns.append("không thấy khai báo rule")
    for n in names:
        if not n.startswith("CMP198_PyPI_"):
            warns.append(f"tên luật '{n}' nên theo dạng CMP198_PyPI_<họ>")
    if "meta:" not in rule:
        warns.append("thiếu phần meta (description, author = \"agent\", date, hash)")
    else:
        for k in ("description", "author", "date", "hash"):
            if not re.search(rf"\b{k}\w*\s*=", rule):
                warns.append(f"meta thiếu '{k}'")
    strings = re.findall(r"\$\w*\s*=\s*\"([^\"]*)\"", rule)
    if strings and all(re.search(r"https?://|\d+\.\d+\.\d+\.\d+|webhooks", s) for s in strings):
        warns.append("luật chỉ dựa vào IOC (URL/IP/webhook); thêm mẫu mã đặc trưng để không hỏng khi tác giả đổi URL")
    return warns


def run(input: dict) -> dict:
    if yara is None:
        return {"error": "chưa cài yara-python"}
    rule = input.get("rule")
    if not isinstance(rule, str) or not rule.strip():
        return {"error": "thiếu 'rule' (toàn văn luật YARA)"}
    if len(rule) > MAX_RULE_CHARS:
        return {"error": f"luật quá dài (> {MAX_RULE_CHARS} ký tự)"}
    if re.search(r"^\s*include\s+\"", rule, flags=re.M):
        return {"error": "không cho phép 'include' trong luật"}
    try:
        rules = yara.compile(source=rule, includes=False)
    except yara.SyntaxError as e:
        return {"error": f"lỗi cú pháp YARA: {e}", "hint": "sửa luật rồi gọi lại"}
    except yara.Error as e:
        return {"error": f"lỗi biên dịch YARA: {e}"}

    mal_dir = Path(input.get("_malicious_dir", PROJECT_ROOT / "data" / "malicious"))
    ben_dir = Path(input.get("_benign_dir", PROJECT_ROOT / "data" / "benign"))
    gts = load_ground_truth(Path(input.get("_ground_truth", PROJECT_ROOT / "data" / "ground_truth")))
    pw = input.get("_password")
    password = pw.encode() if isinstance(pw, str) and pw else None
    family = str(input.get("family") or "").strip().lower()

    out: dict = {"compiled": True, "lint_warnings": lint(rule)}

    root = Path(input.get("path", "."))
    if root.is_dir():
        hit, hits = match_files(rules, _load_files(root))
        out["current_package"] = {"matched": hit, "hits": hits}

    def scan(d: Path, want_family: str | None) -> tuple[list[str], list[str], list[str]]:
        matched, missed, errors = [], [], []
        for sid, p in iter_samples(d):
            if want_family:
                fam, beh = family_of(gts.get(sid))
                if want_family not in (fam.lower(), beh.lower()):
                    continue
            try:
                hit, _ = match_files(rules, sample_files(p, password))
            except Exception as e:
                errors.append(f"{sid}: {type(e).__name__}")
                continue
            (matched if hit else missed).append(sid)
        return matched, missed, errors

    mal_hit, mal_miss, mal_err = scan(mal_dir, family or None)
    if family and not (mal_hit or mal_miss):
        out["note"] = f"không có mẫu độc nào thuộc họ/loại '{family}' trong ground_truth; dùng toàn bộ bộ độc"
        mal_hit, mal_miss, mal_err = scan(mal_dir, None)
    ben_hit, ben_ok, ben_err = scan(ben_dir, None)

    n_mal, n_ben = len(mal_hit) + len(mal_miss), len(ben_hit) + len(ben_ok)
    tpr = round(len(mal_hit) / n_mal, 3) if n_mal else None
    fpr = round(len(ben_hit) / n_ben, 3) if n_ben else None
    out.update({
        "malicious": {"total": n_mal, "matched": len(mal_hit), "missed": mal_miss[:10], "family_filter": family or None},
        "benign": {"total": n_ben, "false_positives": ben_hit[:10]},
        "tpr": tpr,
        "fpr": fpr,
        "meets_target": bool(tpr is not None and tpr >= 0.9 and fpr == 0),
        "errors": (mal_err + ben_err)[:5],
    })
    if not n_mal or not n_ben:
        out["warning"] = "bộ mẫu độc hoặc bộ sạch trống, TPR/FPR chưa có ý nghĩa"
    return out
