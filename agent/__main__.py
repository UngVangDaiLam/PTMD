"""CLI: python -m agent analyze <đường dẫn gói>

Chỉ chạy trong VM cô lập (CLAUDE.md mục 2). Để tránh lỡ chạy trên máy thật, CLI từ chối
chạy nếu biến môi trường CMP198_SANDBOX khác "1" (đặt biến này trong VM, vd. ~/.bashrc).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _load_config(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        return {}
    import yaml
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze", help="phân tích một gói PyPI (.tar.gz / .whl)")
    p.add_argument("package", help="đường dẫn tới file gói")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--model", help="ghi đè llm.model, vd. qwen2.5:3b")
    p.add_argument("--max-steps", type=int)
    p.add_argument("--no-guard", action="store_true", help="tắt lớp bọc <data> (chỉ dùng cho thí nghiệm so sánh)")
    args = parser.parse_args(argv)

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    if os.environ.get("CMP198_SANDBOX") != "1":
        print("Từ chối chạy: chưa đặt CMP198_SANDBOX=1. Agent chỉ được chạy trong VM cô lập.", file=sys.stderr)
        return 3

    from agent.llm import OllamaClient
    from agent.react_loop import AgentConfig, ReactAgent

    cfg = _load_config(args.config)
    if args.model:
        cfg.setdefault("llm", {})["model"] = args.model
    acfg = AgentConfig.from_config(cfg)
    if args.max_steps:
        acfg.max_steps = args.max_steps
    if args.no_guard:
        acfg.prompt_injection_guard = False

    result = ReactAgent(OllamaClient.from_config(cfg), acfg).analyze(args.package)
    r = result.report
    print(json.dumps({"verdict": r["verdict"], "package": r["package"], "stats": r["stats"]},
                     ensure_ascii=False, indent=2))
    print(f"log: {result.log_path}")
    print(f"report: {result.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
