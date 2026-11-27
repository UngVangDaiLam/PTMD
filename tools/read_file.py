"""Tool `read_file`: đọc một đoạn file trong gói dưới dạng text, có số dòng, giới hạn
số dòng và độ dài mỗi dòng. Kèm IOC tìm thấy trong đoạn đã đọc.

Chỉ đọc, không thực thi. Nội dung trả về là dữ liệu không tin cậy (vòng ReAct bọc <data>).
"""

from __future__ import annotations

from pathlib import Path

from tools.common import extract_iocs, is_binary, trunc

NAME = "read_file"
DESCRIPTION = (
    "Đọc một file trong gói (text, có số dòng). Dùng để xem đoạn mã cụ thể mà tool khác "
    "đã chỉ ra (vd. setup.py dòng 10). Trả kèm IOC (URL, IP, webhook, token, path) trong đoạn đọc."
)
INPUT_SCHEMA = {"path": "file tương đối so với gốc gói", "start_line": "dòng bắt đầu, mặc định 1",
                "max_lines": "số dòng, mặc định 80"}

DEFAULT_LINES = 80
HARD_MAX_LINES = 200
MAX_LINE_CHARS = 300
MAX_BYTES = 5 * 1024 * 1024


def run(input: dict) -> dict:
    p = Path(input.get("path", ""))
    if not p.is_file():
        return {"error": f"không phải file: {input.get('path')} (dùng read_metadata để xem danh sách file)"}
    if p.stat().st_size > MAX_BYTES:
        return {"error": f"file quá lớn ({p.stat().st_size} B)"}
    raw = p.read_bytes()
    if is_binary(raw):
        return {"error": "file nhị phân, không đọc dạng text", "size": len(raw), "head_hex": raw[:32].hex()}

    hard_max = int(input.get("_max_lines", HARD_MAX_LINES))
    try:
        start = max(1, int(input.get("start_line", 1)))
        n = min(max(1, int(input.get("max_lines", DEFAULT_LINES))), hard_max)
    except (TypeError, ValueError):
        return {"error": "start_line/max_lines phải là số nguyên"}

    lines = raw.decode("utf-8", errors="replace").splitlines()
    chunk = lines[start - 1:start - 1 + n]
    long_lines = 0
    view = []
    for i, line in enumerate(chunk, start):
        if len(line) > MAX_LINE_CHARS:
            long_lines += 1
        view.append(f"{i}: {trunc(line, MAX_LINE_CHARS)}")

    iocs = extract_iocs("\n".join(chunk), max_items=15)
    for ioc in iocs:
        ioc["line"] += start - 1
    return {
        "file_lines": len(lines),
        "range": [start, start + len(chunk) - 1] if chunk else [],
        "content": "\n".join(view),
        "long_lines_truncated": long_lines,
        "iocs_in_view": iocs,
        "has_more": start - 1 + n < len(lines),
    }
