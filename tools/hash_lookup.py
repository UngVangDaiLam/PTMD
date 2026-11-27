"""Tool `hash_lookup`: SHA-256 của gói và các file chính; tra VirusTotal, MalwareBazaar, OSV.

RÀNG BUỘC (CLAUDE.md mục 2, slide bài 2 mục 2.5):
- VirusTotal và MalwareBazaar: CHỈ gửi chuỗi hash SHA-256. Module này không có code
  upload file; không có endpoint /files POST nào.
- OSV: chỉ gửi tên gói + phiên bản (thông tin công khai), không gửi nội dung.
- Có cache trên đĩa (ghi ngày tra), tôn trọng 4 req/phút của VT free (đếm cả giữa các lần chạy).
- API key chỉ đọc từ biến môi trường VT_API_KEY, MALWAREBAZAAR_API_KEY.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from tools.common import main_code_files, sha256_file

NAME = "hash_lookup"
DESCRIPTION = (
    "Tính SHA-256 của gói và các file mã chính; tra VirusTotal (chỉ bằng hash), MalwareBazaar, "
    "OSV (mã MAL- = gói độc đã biết). Trả số engine phát hiện, nhãn đề xuất, họ, ngày thấy lần đầu. "
    "VT 0 phát hiện KHÔNG có nghĩa là sạch."
)
INPUT_SCHEMA = {"name": "tên gói (tuỳ chọn, cho OSV)", "version": "phiên bản (tuỳ chọn)",
                "include_files": "true để tra cả hash file mã chính (tốn lượt VT)"}

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = PROJECT_ROOT / ".cache" / "hash_lookup"
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
MB_URL = "https://mb-api.abuse.ch/api/v1/"
OSV_URL = "https://api.osv.dev/v1/query"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HTTP_TIMEOUT = 30


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------- cache + rate limit ----------------

class Cache:
    def __init__(self, root: Path, ttl_days: float = 7) -> None:
        self.root = root
        self.ttl = ttl_days * 86400

    def _p(self, service: str, key: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", key)[:150]
        return self.root / service / f"{safe}.json"

    def get(self, service: str, key: str) -> dict | None:
        p = self._p(service, key)
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if time.time() - rec.get("_ts", 0) > self.ttl:
            return None
        out = rec["data"]
        out["cached"] = True
        return out

    def put(self, service: str, key: str, data: dict) -> None:
        p = self._p(service, key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"_ts": time.time(), "data": data}, ensure_ascii=False), encoding="utf-8")


class RateLimiter:
    """Cửa sổ trượt 60 giây, lưu dấu thời gian ra file để đúng cả giữa các lần chạy."""

    def __init__(self, state_file: Path, per_minute: int, max_wait_s: float = 65,
                 sleep=time.sleep, clock=time.time) -> None:
        self.state_file = state_file
        self.per_minute = per_minute
        self.max_wait_s = max_wait_s
        self.sleep, self.clock = sleep, clock

    def _load(self) -> list[float]:
        try:
            return [float(x) for x in json.loads(self.state_file.read_text())]
        except (OSError, ValueError, TypeError):
            return []

    def acquire(self) -> bool:
        now = self.clock()
        stamps = [t for t in self._load() if now - t < 60]
        if len(stamps) >= self.per_minute:
            wait = 60 - (now - stamps[0]) + 0.5
            if wait > self.max_wait_s:
                return False
            self.sleep(wait)
            now = self.clock()
            stamps = [t for t in stamps if now - t < 60]
        stamps.append(now)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(stamps))
        return True


# ---------------- các dịch vụ ----------------

def _http(method: str, url: str, **kw) -> requests.Response:
    return requests.request(method, url, timeout=HTTP_TIMEOUT, **kw)


def vt_lookup(sha256: str, api_key: str, limiter: RateLimiter) -> dict:
    if not SHA256_RE.match(sha256):
        return {"error": "chỉ tra bằng SHA-256"}
    if not limiter.acquire():
        return {"error": "hết lượt VT trong phút này (4 req/phút), thử lại sau"}
    r = _http("GET", VT_URL.format(sha256), headers={"x-apikey": api_key, "accept": "application/json"})
    if r.status_code == 404:
        return {"found": False, "note": "VT chưa có hash này (không có nghĩa là sạch)"}
    if r.status_code == 429:
        return {"error": "VT báo vượt hạn mức (429)"}
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}
    a = r.json().get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    results = a.get("last_analysis_results", {}) or {}
    labels = sorted({v.get("result") for v in results.values()
                     if v.get("category") == "malicious" and v.get("result")})[:12]
    ptc = a.get("popular_threat_classification", {}) or {}
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "suggested_label": ptc.get("suggested_threat_label"),
        "popular_category": [c.get("value") for c in ptc.get("popular_threat_category", [])][:3],
        "popular_name": [c.get("value") for c in ptc.get("popular_threat_name", [])][:3],
        "engine_labels": labels,  # dùng cho AVClass offline
        "names": (a.get("names") or [])[:5],
        "tags": (a.get("tags") or [])[:10],
        "first_submission": datetime.fromtimestamp(a["first_submission_date"], timezone.utc).date().isoformat()
        if a.get("first_submission_date") else None,
    }


def mb_lookup(sha256: str, api_key: str) -> dict:
    if not SHA256_RE.match(sha256):
        return {"error": "chỉ tra bằng SHA-256"}
    r = _http("POST", MB_URL, data={"query": "get_info", "hash": sha256}, headers={"Auth-Key": api_key})
    if r.status_code != 200:
        return {"error": f"MalwareBazaar HTTP {r.status_code}"}
    j = r.json()
    status = j.get("query_status")
    if status in ("hash_not_found", "no_results"):
        return {"found": False}
    if status != "ok":
        return {"error": f"MalwareBazaar: {status}"}
    d = (j.get("data") or [{}])[0]
    return {"found": True, "signature": d.get("signature"), "tags": (d.get("tags") or [])[:10],
            "file_type": d.get("file_type"), "first_seen": d.get("first_seen"),
            "file_name": d.get("file_name")}


def osv_lookup(name: str, version: str | None) -> dict:
    body: dict = {"package": {"name": name, "ecosystem": "PyPI"}}
    if version:
        body["version"] = version
    r = _http("POST", OSV_URL, json=body)
    if r.status_code != 200:
        return {"error": f"OSV HTTP {r.status_code}"}
    vulns = r.json().get("vulns", []) or []
    items = [{"id": v.get("id"), "summary": (v.get("summary") or "")[:160],
              "aliases": (v.get("aliases") or [])[:3]} for v in vulns[:10]]
    mal = [v["id"] for v in items if str(v["id"]).startswith("MAL-")]
    return {"found": bool(items), "malicious_ids": mal, "known_malicious": bool(mal), "vulns": items}


# ---------------- tool ----------------

def run(input: dict) -> dict:
    root = Path(input.get("path", "."))
    pkg_sha = str(input.get("_package_sha256", "") or "").lower()
    cache = Cache(Path(input.get("_cache_dir", DEFAULT_CACHE)), float(input.get("_ttl_days", 7)))
    offline = bool(input.get("_offline", False))
    limiter = RateLimiter(Path(input.get("_cache_dir", DEFAULT_CACHE)) / "vt_rate.json",
                          int(input.get("_vt_rpm", 4)), sleep=input.get("_sleep", time.sleep))
    vt_key = os.environ.get("VT_API_KEY", "")
    mb_key = os.environ.get("MALWAREBAZAAR_API_KEY", "")

    files = []
    if root.is_dir():
        for p in main_code_files(root, limit=5):
            files.append({"file": p.relative_to(root).as_posix(), "sha256": sha256_file(p)})

    targets: list[tuple[str, str]] = []
    if SHA256_RE.match(pkg_sha):
        targets.append(("package", pkg_sha))
    if str(input.get("include_files", "")).lower() in ("true", "1", "yes"):
        targets += [(f["file"], f["sha256"]) for f in files[:3]]

    out: dict = {"queried_at": _now(), "package_sha256": pkg_sha or None, "files": files, "lookups": {}}

    def cached(service: str, key: str, fn) -> dict:
        hit = cache.get(service, key)
        if hit is not None:
            return hit
        if offline:
            return {"skipped": "chế độ offline"}
        try:
            res = fn()
        except requests.RequestException as e:
            return {"error": f"lỗi mạng: {type(e).__name__}"}
        if "error" not in res:
            res["queried_at"] = _now()
            cache.put(service, key, dict(res))
        return res

    for label, h in targets:
        entry: dict = {"sha256": h}
        entry["virustotal"] = cached("vt", h, lambda h=h: vt_lookup(h, vt_key, limiter)) if vt_key \
            else {"skipped": "chưa đặt VT_API_KEY"}
        entry["malwarebazaar"] = cached("mb", h, lambda h=h: mb_lookup(h, mb_key)) if mb_key \
            else {"skipped": "chưa đặt MALWAREBAZAAR_API_KEY"}
        out["lookups"][label] = entry

    name, version = input.get("name"), input.get("version")
    if not name and root.is_dir():
        from tools import metadata
        meta = metadata.run({"path": str(root)})
        name, version = meta.get("name"), version or meta.get("version")
    if name:
        key = f"{name}=={version or '*'}"
        out["osv"] = cached("osv", key, lambda: osv_lookup(str(name), str(version) if version else None))
        out["osv"]["query"] = key
    else:
        out["osv"] = {"skipped": "không có tên gói"}
    return out
