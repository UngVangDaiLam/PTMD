"""Tool `guarddog_scan`: chạy `guarddog pypi scan <path> --output-format json` trên thư mục
gói ĐÃ GIẢI NÉN, rút gọn kết quả theo rule bị kích hoạt.

GuardDog chỉ phân tích tĩnh (Semgrep + kiểm tra metadata), không cài hay chạy gói.
Gọi subprocess với danh sách tham số (không qua shell), có timeout.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

NAME = "guarddog_scan"
DESCRIPTION = (
    "Quét gói bằng GuardDog (luật phát hiện mã độc PyPI: exec base64, tải và chạy file, "
    "gửi dữ liệu ra ngoài, cmdclass cài đặt, làm rối mã...). Trả danh sách rule bị kích hoạt "
    "kèm vị trí file:dòng và đoạn mã."
)
INPUT_SCHEMA = {"path": "thư mục gói, mặc định '.'"}

DEFAULT_TIMEOUT_S = 300
MAX_FINDINGS_PER_RULE = 3
MAX_CODE = 160


def _s(v: object, n: int) -> str:
    s = str(v).strip()
    return s if len(s) <= n else s[:n] + "…"


def _parse_json(stdout: str) -> dict:
    """GuardDog có thể in log trước JSON; lấy từ dấu '{' đầu tiên."""
    start = stdout.find("{")
    if start < 0:
        raise ValueError("không thấy JSON trong output")
    return json.loads(stdout[start:])


def _rel(location: str, root: Path) -> str:
    loc = location.replace("\\", "/")
    root_s = root.as_posix().rstrip("/") + "/"
    return loc[len(root_s):] if loc.startswith(root_s) else loc


def summarize(raw: dict, root: Path, max_per_rule: int = MAX_FINDINGS_PER_RULE) -> dict:
    results = raw.get("results") or {}
    triggered: list[dict] = []
    for rule, value in sorted(results.items()):
        if not value:
            continue
        entry: dict[str, object] = {"rule": rule}
        if isinstance(value, list):
            entry["count"] = len(value)
            findings = []
            for f in value[:max_per_rule]:
                if isinstance(f, dict):
                    loc = _rel(str(f.get("location", "")), root)
                    file, _, line = loc.rpartition(":")
                    findings.append({
                        "file": file or loc,
                        "line": int(line) if line.isdigit() else 0,
                        "code": _s(f.get("code", ""), MAX_CODE),
                        "message": _s(f.get("message", ""), MAX_CODE),
                    })
                else:
                    findings.append({"message": _s(f, MAX_CODE)})
            entry["findings"] = findings
        elif isinstance(value, dict):
            entry["detail"] = {k: _s(v, MAX_CODE) for k, v in list(value.items())[:5]}
        else:
            entry["message"] = _s(value, MAX_CODE)
        triggered.append(entry)
    errors = raw.get("errors") or {}
    return {
        "issues": raw.get("issues", sum(e.get("count", 1) for e in triggered)),
        "triggered_rules": triggered,
        "errors": {k: _s(v, MAX_CODE) for k, v in list(errors.items())[:5]},
    }


def run(input: dict) -> dict:
    path = Path(input.get("path", "."))
    if not path.exists():
        return {"error": f"không tồn tại: {input.get('path')}"}
    exe = input.get("_guarddog_bin") or shutil.which("guarddog")
    if not exe:
        return {"error": "không tìm thấy lệnh guarddog (pip install guarddog trong VM)"}
    timeout = int(input.get("_timeout_s", DEFAULT_TIMEOUT_S))
    cmd = [exe, "pypi", "scan", str(path), "--output-format", "json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", shell=False)
    except subprocess.TimeoutExpired:
        return {"error": f"guarddog quá thời gian {timeout}s"}
    except OSError as e:
        return {"error": f"không chạy được guarddog: {e}"}
    try:
        raw = _parse_json(proc.stdout)
    except (ValueError, json.JSONDecodeError) as e:
        return {"error": f"không đọc được JSON của guarddog (exit {proc.returncode}): {e}",
                "stderr": _s(proc.stderr, 400)}
    return summarize(raw, path)
