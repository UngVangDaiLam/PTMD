"""Allowlist tool của agent. Agent CHỈ gọi được tool có tên trong `TOOLS`;
không có tool chạy shell tuỳ ý (CLAUDE.md mục 2).

Registry còn làm hai việc an toàn trước khi gọi tool:
1. Bỏ mọi khoá bắt đầu bằng "_" trong action_input của mô hình (khoá nội bộ như
   `_guarddog_bin`, `_timeout_s` chỉ do cấu hình đặt), rồi mới thêm cấu hình.
2. Ép `path` nằm trong thư mục gói đã giải nén (chặn `../`, đường dẫn tuyệt đối).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from tools import (
    decode_string,
    fuzzy,
    guarddog_tool,
    hash_lookup,
    metadata,
    ml_classify,
    read_file,
    semgrep_tool,
    typosquat,
    yara_tool,
)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict
    run: Callable[[dict], dict]


TOOLS: dict[str, ToolSpec] = {
    m.NAME: ToolSpec(m.NAME, m.DESCRIPTION, m.INPUT_SCHEMA, m.run)
    for m in (metadata, typosquat, guarddog_tool, semgrep_tool, read_file, decode_string,
              hash_lookup, fuzzy, ml_classify, yara_tool)
}


def tool_config_from(cfg: dict) -> dict[str, dict]:
    """Ánh xạ mục `tools` / `extract` của config.yaml thành tham số nội bộ (khoá "_") cho từng tool."""
    t = (cfg or {}).get("tools", {})
    root = Path(__file__).resolve().parent.parent

    def p(v: object, default: str) -> str:
        q = Path(str(v or default))
        return str(q if q.is_absolute() else root / q)

    pw = (cfg or {}).get("extract", {}).get("sample_zip_password")
    hl, yr, sg = t.get("hash_lookup", {}), t.get("yara", {}), t.get("semgrep", {})
    sg_cfgs = sg.get("config") or ["rules/semgrep"]
    if isinstance(sg_cfgs, str):
        sg_cfgs = [sg_cfgs]
    return {
        "guarddog_scan": {"_timeout_s": t.get("guarddog", {}).get("timeout_s", 300)},
        "semgrep_scan": {"_timeout_s": sg.get("timeout_s", 300), "_configs": [p(c, c) for c in sg_cfgs]},
        "read_file": {"_max_lines": t.get("read_file", {}).get("max_lines", 200)},
        "check_typosquat": {"_top_list": p((cfg or {}).get("paths", {}).get("top_packages"),
                                           "data/top_pypi_packages.txt")},
        "hash_lookup": {"_cache_dir": p(hl.get("cache_dir"), ".cache/hash_lookup"),
                        "_vt_rpm": hl.get("virustotal_rpm", 4), "_ttl_days": hl.get("cache_ttl_days", 7),
                        "_offline": bool(hl.get("offline", False))},
        "fuzzy_similarity": {"_index": p(t.get("fuzzy", {}).get("index"), "data/fuzzy_index.json")},
        "ml_classify": {"_model_path": p(t.get("ml_classify", {}).get("model_path"), "ml/model.joblib")},
        "yara_generate_test": {"_malicious_dir": p(yr.get("malicious_dir"), "data/malicious"),
                               "_benign_dir": p(yr.get("benign_dir"), "data/benign"),
                               "_ground_truth": p((cfg or {}).get("paths", {}).get("ground_truth"),
                                                  "data/ground_truth"),
                               "_password": pw or ""},
    }


class PathEscapeError(ValueError):
    pass


def resolve_in_root(root: Path, p: object) -> Path:
    """Đường dẫn tương đối so với gốc gói; không cho thoát ra ngoài."""
    raw = str(p if p not in (None, "") else ".").replace("\\", "/")
    root_r = root.resolve()
    target = (root_r / raw.lstrip("/")).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
    if target != root_r and root_r not in target.parents:
        raise PathEscapeError(f"đường dẫn nằm ngoài thư mục gói: {p}")
    return target


@dataclass
class ToolResult:
    ok: bool
    output: dict
    ms: int


@dataclass
class Registry:
    root: Path
    tools: dict[str, ToolSpec] = field(default_factory=lambda: dict(TOOLS))
    tool_config: dict[str, dict] = field(default_factory=dict)  # {tool_name: {"_timeout_s": ..}}
    runtime: dict = field(default_factory=dict)  # thông tin của lần chạy, vd. {"_package_sha256": ...}

    def names(self) -> list[str]:
        return list(self.tools)

    def describe(self) -> str:
        lines = []
        for t in self.tools.values():
            args = ", ".join(f'"{k}": {v}' for k, v in t.input_schema.items())
            lines.append(f"- {t.name}: {t.description}\n  action_input: {{{args}}}")
        return "\n".join(lines)

    def call(self, name: str, action_input: object) -> ToolResult:
        t0 = time.perf_counter()
        spec = self.tools.get(name)
        if spec is None:
            return ToolResult(False, {"error": f"tool '{name}' không có trong allowlist: {self.names()}"}, 0)
        if action_input is None:
            action_input = {}
        if not isinstance(action_input, dict):
            return ToolResult(False, {"error": "action_input phải là object JSON"}, 0)
        args = {k: v for k, v in action_input.items() if not str(k).startswith("_")}
        try:
            args["path"] = str(resolve_in_root(self.root, args.get("path")))
        except PathEscapeError as e:
            return ToolResult(False, {"error": str(e)}, 0)
        args.update(self.runtime)
        args.update(self.tool_config.get(name, {}))
        try:
            out = spec.run(args)
        except Exception as e:  # tool lỗi -> trả vào Observation, không crash vòng lặp
            out = {"error": f"{type(e).__name__}: {e}"}
        ms = int((time.perf_counter() - t0) * 1000)
        if not isinstance(out, dict):
            out = {"error": "tool trả về không phải dict"}
        return ToolResult("error" not in out, self._relativize(out), ms)

    def _relativize(self, out: dict) -> dict:
        """Không lộ đường dẫn thư mục tạm cho mô hình (giữ log gọn, ổn định giữa các lần chạy)."""
        root_s = str(self.root.resolve())
        def fix(v: object) -> object:
            if isinstance(v, str):
                return v.replace(root_s + "\\", "").replace(root_s + "/", "").replace(root_s, ".")
            if isinstance(v, list):
                return [fix(x) for x in v]
            if isinstance(v, dict):
                return {k: fix(x) for k, x in v.items()}
            return v
        return fix(out)  # type: ignore[return-value]
