"""Tool `semgrep_scan`: chạy Semgrep với bộ rule LOCAL (rules/semgrep) trên thư mục gói đã giải nén.

`--metrics=off`, không tải rule từ registry, không gửi gì ra ngoài. Gọi subprocess không qua shell.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

NAME = "semgrep_scan"
DESCRIPTION = (
    "Quét gói bằng Semgrep với rule tự viết: cmdclass gọi mạng/chạy lệnh, exec trên base64/zlib, "
    "biến môi trường hoặc thông tin máy gửi qua HTTP, tải rồi chạy, webhook Discord/Telegram, "
    "đường dẫn credential, blob base64 dài. Mỗi phát hiện kèm gợi ý ATT&CK và loại hành vi."
)
INPUT_SCHEMA = {"path": "thư mục hoặc file, mặc định '.'"}

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = PROJECT_ROOT / "rules" / "semgrep"
DEFAULT_TIMEOUT_S = 300
MAX_FINDINGS_PER_RULE = 3
MAX_CODE = 200


def _s(v: object, n: int) -> str:
    s = " ".join(str(v).split())
    return s if len(s) <= n else s[:n] + "…"


def _rel(p: str, root: Path) -> str:
    try:
        return Path(p).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(p).as_posix()


def summarize(raw: dict, root: Path, max_per_rule: int = MAX_FINDINGS_PER_RULE) -> dict:
    by_rule: dict[str, dict] = {}
    for r in raw.get("results", []):
        rid = str(r.get("check_id", "?")).split(".")[-1]
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        e = by_rule.setdefault(rid, {
            "rule": rid,
            "severity": extra.get("severity", ""),
            "message": _s(extra.get("message", ""), 160),
            "attack": meta.get("attack", []),
            "behavior": meta.get("behavior", ""),
            "count": 0,
            "findings": [],
        })
        e["count"] += 1
        if len(e["findings"]) < max_per_rule:
            e["findings"].append({
                "file": _rel(r.get("path", ""), root if root.is_dir() else root.parent),
                "line": (r.get("start") or {}).get("line", 0),
                "code": _s(extra.get("lines", ""), MAX_CODE),
            })
    errors = [_s(e.get("message", e), 200) for e in raw.get("errors", [])][:5]
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    rules = sorted(by_rule.values(), key=lambda x: (order.get(x["severity"], 3), -x["count"], x["rule"]))
    return {"total_findings": sum(x["count"] for x in rules), "rules": rules, "errors": errors}


def run(input: dict) -> dict:
    path = Path(input.get("path", "."))
    if not path.exists():
        return {"error": f"không tồn tại: {input.get('path')}"}
    exe = input.get("_semgrep_bin") or shutil.which("semgrep")
    if not exe:
        return {"error": "không tìm thấy lệnh semgrep (pip install semgrep trong VM)"}
    configs = input.get("_configs") or [str(DEFAULT_RULES)]
    timeout = int(input.get("_timeout_s", DEFAULT_TIMEOUT_S))
    cmd = [exe, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
           "--no-git-ignore", "--timeout", "30", "--max-target-bytes", "5000000"]
    for c in configs:
        cmd += ["--config", str(c)]
    cmd.append(str(path))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", shell=False)
    except subprocess.TimeoutExpired:
        return {"error": f"semgrep quá thời gian {timeout}s"}
    except OSError as e:
        return {"error": f"không chạy được semgrep: {e}"}
    out = proc.stdout
    start = out.find("{")
    try:
        raw = json.loads(out[start:]) if start >= 0 else None
    except json.JSONDecodeError:
        raw = None
    if raw is None:
        return {"error": f"không đọc được JSON của semgrep (exit {proc.returncode})", "stderr": _s(proc.stderr, 400)}
    return summarize(raw, path)
