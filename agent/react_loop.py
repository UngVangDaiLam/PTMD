"""Vòng ReAct tối thiểu: Thought -> Action -> Observation, giới hạn số bước, ghi log .jsonl.

Luồng một lần chạy:
1. Tính SHA-256 gói (đọc byte, không chạy), giải nén an toàn vào thư mục tạm riêng.
2. Lặp tối đa `max_steps`: gọi LLM -> parse JSON {thought, action, action_input}
   -> gọi tool qua Registry (allowlist) -> rút gọn output -> bọc <data> -> Observation.
3. Khi mô hình trả `final_answer` (hoặc hết bước) -> chuẩn hoá báo cáo, loại nhận định
   không có bằng chứng sang `unknowns`, ghi báo cáo JSON.
4. Mỗi bước ghi một dòng vào logs/<timestamp>_<package>.jsonl:
   {step, thought, action, action_input, observation_summary, tokens, ms}.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from agent import prompts
from agent.llm import LLM
from tools.registry import Registry
from tools.safe_extract import ExtractionError, Limits, extracted

FINAL = "final_answer"
VERDICTS = {"malicious", "suspicious", "benign"}
CONFIDENCES = {"high", "medium", "low"}
KEEP_FULL_OBSERVATIONS = 3     # các Observation cũ hơn bị cắt ngắn để vừa ctx của SLM
OLD_OBSERVATION_CHARS = 400


# ---------------- tiện ích ----------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_name(s: str) -> str:
    s = re.sub(r"\.(tar\.gz|tgz|tar\.bz2|tar\.xz|tar|whl|zip)$", "", s, flags=re.I)
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:80] or "package"


def parse_action(text: str) -> dict:
    """Parse phản hồi của mô hình thành {thought, action, action_input}. Ném ValueError nếu hỏng."""
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    start, end = t.find("{"), t.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("không có object JSON")
    try:
        obj = json.loads(t[start:end + 1])
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON lỗi: {e.msg}") from e
    if not isinstance(obj, dict):
        raise ValueError("JSON không phải object")
    action = obj.get("action")
    if not isinstance(action, str) or not action:
        raise ValueError("thiếu khoá 'action'")
    ai = obj.get("action_input", {})
    if ai is None:
        ai = {}
    return {"thought": str(obj.get("thought", "")), "action": action.strip(), "action_input": ai}


def compact(obj: object, max_chars: int, max_lines: int) -> str:
    """Rút gọn output tool trước khi đưa lại cho SLM: mỗi khoá cấp 1 một dòng JSON gọn
    (tiết kiệm token hơn indent), mỗi dòng tối đa nửa ngân sách, rồi giới hạn dòng/ký tự."""
    def dump(v: object) -> str:
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"), default=str)

    per_line = max(max_chars // 2, 80)
    if isinstance(obj, dict):
        lines = []
        for k, v in obj.items():
            ln = f"{dump(k)}: {dump(v)}"
            lines.append(ln if len(ln) <= per_line else ln[:per_line] + "…(cắt)")
    else:
        lines = [dump(obj)]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... (cắt {len(lines) - max_lines} dòng)"]
    s = "\n".join(lines)
    if len(s) > max_chars:
        s = s[:max_chars] + "… (cắt)"
    return s


# ---------------- agent ----------------

@dataclass
class AgentConfig:
    max_steps: int = 12
    observation_max_chars: int = 2000
    observation_max_lines: int = 40
    prompt_injection_guard: bool = True
    logs_dir: Path = Path("logs")
    reports_dir: Path = Path("reports")
    temp_root: Path | None = None
    limits: Limits = field(default_factory=Limits)
    tool_config: dict[str, dict] = field(default_factory=dict)
    zip_password: bytes | None = None

    @classmethod
    def from_config(cls, cfg: dict) -> "AgentConfig":
        from tools.registry import tool_config_from
        from tools.safe_extract import limits_from_config
        a, paths = cfg.get("agent", {}), cfg.get("paths", {})
        pw = cfg.get("extract", {}).get("sample_zip_password")
        tr = cfg.get("extract", {}).get("temp_root")
        return cls(
            max_steps=int(a.get("max_steps", 12)),
            observation_max_chars=int(a.get("observation_max_chars", 2000)),
            observation_max_lines=int(a.get("observation_max_lines", 40)),
            prompt_injection_guard=bool(a.get("prompt_injection_guard", True)),
            logs_dir=Path(paths.get("logs", "logs")),
            reports_dir=Path(paths.get("reports", "reports")),
            temp_root=Path(tr) if tr else None,
            limits=limits_from_config(cfg),
            tool_config=tool_config_from(cfg),
            zip_password=str(pw).encode() if pw else None,
        )


@dataclass
class RunResult:
    report: dict
    log_path: Path
    report_path: Path | None


class ReactAgent:
    def __init__(self, llm: LLM, config: AgentConfig | None = None, registry_factory=Registry) -> None:
        self.llm = llm
        self.cfg = config or AgentConfig()
        self.registry_factory = registry_factory

    # ----- log -----
    def _open_log(self, pkg: str) -> tuple[Path, object]:
        self.cfg.logs_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        path = self.cfg.logs_dir / f"{ts}_{pkg}.jsonl"
        return path, open(path, "w", encoding="utf-8")

    @staticmethod
    def _log(fh, **rec) -> None:
        fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        fh.flush()

    # ----- chạy -----
    def analyze(self, package_path: str | Path) -> RunResult:
        package_path = Path(package_path)
        pkg = safe_name(package_path.name)
        t_start = time.perf_counter()
        log_path, fh = self._open_log(pkg)
        try:
            sha = sha256_file(package_path) if package_path.is_file() else ""
            try:
                with extracted(package_path, self.cfg.temp_root, self.cfg.limits, self.cfg.zip_password) as ex:
                    report = self._loop(ex.root, package_path.name, fh, ex.warnings, sha)
                    report["package"]["files_count"] = len(ex.files)
            except ExtractionError as e:
                self._log(fh, step=0, thought="", action="safe_extract", action_input={"file": package_path.name},
                          observation_summary=f"error: {e}", tokens=0, ms=0)
                report = self._empty_report(unknowns=[f"không giải nén được gói: {e}"])
                report["verdict"] = {"label": "suspicious", "confidence": "low"}
            report["package"]["sha256"] = sha
            report["stats"]["seconds"] = round(time.perf_counter() - t_start, 2)
            report["log_file"] = str(log_path)
        finally:
            fh.close()
        report_path = self._write_report(report, log_path)
        return RunResult(report, log_path, report_path)

    def _loop(self, root: Path, filename: str, fh, extract_warnings: list[str], sha: str = "") -> dict:
        reg = self.registry_factory(root=root, tool_config=self.cfg.tool_config,
                                    runtime={"_package_sha256": sha})
        guard = self.cfg.prompt_injection_guard
        messages: list[dict] = [
            {"role": "system", "content": prompts.system_prompt(reg.describe())},
            {"role": "user", "content": prompts.task_prompt(filename, guard)},
        ]
        if extract_warnings:
            messages[-1]["content"] += "\n" + prompts.observation_prompt(
                compact({"extract_warnings": extract_warnings[:20]}, 1000, 25), guard)

        stats = {"steps": 0, "tool_calls": 0, "tool_errors": 0, "format_errors": 0, "tokens": 0, "seconds": 0}
        called_ok: set[str] = set()
        cache: dict[str, str] = {}
        facts: dict = {}
        yara_runs: list[dict] = []
        final: dict | None = None

        for step in range(1, self.cfg.max_steps + 1):
            stats["steps"] = step
            if step == self.cfg.max_steps:
                messages.append({"role": "user", "content": prompts.last_step_prompt()})
            t0 = time.perf_counter()
            try:
                reply = self.llm.chat(self._context(messages))
            except Exception as e:  # LLM lỗi mạng/timeout: ghi log rồi dừng
                self._log(fh, step=step, thought="", action="llm_error", action_input={},
                          observation_summary=f"{type(e).__name__}: {e}", tokens=0,
                          ms=int((time.perf_counter() - t0) * 1000))
                break
            stats["tokens"] += reply.tokens
            messages.append({"role": "assistant", "content": reply.content})

            try:
                act = parse_action(reply.content)
            except ValueError as e:
                stats["format_errors"] += 1
                obs = prompts.format_error_prompt(str(e))
                messages.append({"role": "user", "content": obs})
                self._log(fh, step=step, thought="", action="parse_error", action_input={},
                          observation_summary=f"{e}; raw={reply.content[:300]}", tokens=reply.tokens,
                          ms=int((time.perf_counter() - t0) * 1000))
                continue

            if act["action"] == FINAL:
                final = act["action_input"] if isinstance(act["action_input"], dict) else {}
                self._log(fh, step=step, thought=act["thought"], action=FINAL, action_input=final,
                          observation_summary="", tokens=reply.tokens, ms=int((time.perf_counter() - t0) * 1000))
                break

            key = json.dumps([act["action"], act["action_input"]], sort_keys=True, ensure_ascii=False, default=str)
            if key in cache:
                summary = compact({"note": "đã gọi tool này với cùng tham số; dùng kết quả cũ hoặc làm bước khác"},
                                  500, 5)
                tool_ms = 0
            else:
                stats["tool_calls"] += 1
                res = reg.call(act["action"], act["action_input"])
                tool_ms = res.ms
                if res.ok:
                    called_ok.add(act["action"])
                    if act["action"] == "read_metadata":
                        facts = res.output
                    elif act["action"] == "yara_generate_test" and isinstance(act["action_input"], dict):
                        yara_runs.append({"rule": str(act["action_input"].get("rule", "")),
                                          "tpr": res.output.get("tpr"), "fpr": res.output.get("fpr"),
                                          "meets_target": res.output.get("meets_target", False)})
                else:
                    stats["tool_errors"] += 1
                summary = compact(res.output, self.cfg.observation_max_chars, self.cfg.observation_max_lines)
                cache[key] = summary
            messages.append({"role": "user", "content": prompts.observation_prompt(summary, guard)})
            self._log(fh, step=step, thought=act["thought"], action=act["action"], action_input=act["action_input"],
                      observation_summary=summary, tokens=reply.tokens,
                      ms=int((time.perf_counter() - t0) * 1000), tool_ms=tool_ms)

        report = self.finalize(final, called_ok, facts, yara_runs)
        report["stats"].update(stats)
        if final is None:
            report["unknowns"].append("agent không trả final_answer trong giới hạn bước")
        return report

    def _context(self, messages: list[dict]) -> list[dict]:
        """Giữ nguyên system + task; Observation cũ hơn KEEP_FULL_OBSERVATIONS bị cắt ngắn."""
        obs_idx = [i for i, m in enumerate(messages) if m["role"] == "user" and m["content"].startswith("Observation")]
        old = set(obs_idx[:-KEEP_FULL_OBSERVATIONS])
        out = []
        for i, m in enumerate(messages):
            if i in old and len(m["content"]) > OLD_OBSERVATION_CHARS:
                c = m["content"][:OLD_OBSERVATION_CHARS] + "\n... (Observation cũ đã rút gọn)"
                if "<data>" in c and "</data>" not in c:
                    c += "\n</data>"
                out.append({"role": m["role"], "content": c})
            else:
                out.append(m)
        return out

    # ----- báo cáo -----
    @staticmethod
    def _empty_report(unknowns: list[str] | None = None) -> dict:
        return {
            "package": {"name": "", "version": "", "sha256": "", "files_count": 0},
            "verdict": {"label": "suspicious", "confidence": "low"},
            "family": {"name": "", "behavior_type": "", "confidence": "", "sources": []},
            "behaviors": [], "iocs": [], "attack": [],
            "yara_rule": "", "yara_test": {"tpr": None, "fpr": None},
            "unknowns": list(unknowns or []),
            "stats": {"steps": 0, "tool_calls": 0, "tool_errors": 0, "format_errors": 0,
                      "unsupported_claims": 0, "tokens": 0, "seconds": 0},
        }

    @classmethod
    def finalize(cls, final: dict | None, called_ok: set[str], facts: dict,
                 yara_runs: list[dict] | None = None) -> dict:
        """Chuẩn hoá báo cáo theo schema; nhận định không có bằng chứng từ tool đã gọi
        thành công bị chuyển sang `unknowns` (CLAUDE.md mục 5)."""
        r = cls._empty_report()
        f = final or {}

        pkg = f.get("package") if isinstance(f.get("package"), dict) else {}
        r["package"]["name"] = str(facts.get("name") or pkg.get("name") or "")
        r["package"]["version"] = str(facts.get("version") or pkg.get("version") or "")

        v = f.get("verdict") if isinstance(f.get("verdict"), dict) else {}
        label, conf = str(v.get("label", "")).lower(), str(v.get("confidence", "")).lower()
        r["verdict"] = {"label": label if label in VERDICTS else "suspicious",
                        "confidence": conf if conf in CONFIDENCES else "low"}

        fam = f.get("family") if isinstance(f.get("family"), dict) else {}
        r["family"] = {
            "name": str(fam.get("name", "")),
            "behavior_type": str(fam.get("behavior_type", "")),
            "confidence": str(fam.get("confidence", "")) if str(fam.get("confidence", "")) in CONFIDENCES else "low",
            "sources": [str(s) for s in fam.get("sources", [])] if isinstance(fam.get("sources"), list) else [],
        }

        unknowns = [str(u) for u in f.get("unknowns", [])] if isinstance(f.get("unknowns"), list) else []
        dropped = 0

        def ok_ev(ev: object) -> bool:
            return isinstance(ev, dict) and str(ev.get("tool", "")) in called_ok

        for key, label_field in (("behaviors", "description"), ("iocs", "value")):
            items = f.get(key) if isinstance(f.get(key), list) else []
            for it in items:
                if isinstance(it, dict) and ok_ev(it.get("evidence")):
                    r[key].append(it)
                else:
                    dropped += 1
                    desc = it.get(label_field, it) if isinstance(it, dict) else it
                    unknowns.append(f"[không có bằng chứng từ tool] {key}: {str(desc)[:150]}")

        for it in f.get("attack", []) if isinstance(f.get("attack"), list) else []:
            if isinstance(it, dict) and it.get("id") and str(it.get("evidence", "")).strip():
                r["attack"].append({"id": str(it["id"]), "name": str(it.get("name", "")), "evidence": str(it["evidence"])})
            else:
                dropped += 1
                unknowns.append(f"[không có bằng chứng từ tool] attack: {str(it)[:150]}")

        # Luật YARA: chỉ nhận luật ĐÃ được yara_generate_test kiểm tra; chọn luật tốt nhất.
        if yara_runs:
            best = max(yara_runs, key=lambda y: (bool(y["meets_target"]), y["fpr"] == 0,
                                                 y["tpr"] if y["tpr"] is not None else -1))
            r["yara_rule"] = best["rule"]
            r["yara_test"] = {"tpr": best["tpr"], "fpr": best["fpr"]}
            proposed = str(f.get("yara_rule") or "").strip()
            if proposed and proposed != best["rule"].strip():
                unknowns.append("luật YARA trong final_answer khác luật đã kiểm tra; báo cáo dùng luật đã kiểm tra")
        elif str(f.get("yara_rule") or "").strip():
            unknowns.append("luật YARA mô hình đề xuất chưa được kiểm tra bằng yara_generate_test, không đưa vào báo cáo")

        r["unknowns"] = unknowns
        r["stats"]["unsupported_claims"] = dropped
        return r

    def _write_report(self, report: dict, log_path: Path) -> Path | None:
        try:
            self.cfg.reports_dir.mkdir(parents=True, exist_ok=True)
            p = self.cfg.reports_dir / (log_path.stem + ".json")
            p.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            return p
        except OSError:
            return None
