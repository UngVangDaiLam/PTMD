"""Tool `read_metadata`: đọc setup.py, pyproject.toml, setup.cfg, PKG-INFO/METADATA;
liệt kê file, cmdclass, entry point và các lời gọi/import đáng chú ý trong setup.py.

AN TOÀN: setup.py chỉ được PHÂN TÍCH CÚ PHÁP bằng `ast.parse` (không compile/exec,
không import). Mọi giá trị trả về là dữ liệu không tin cậy; vòng ReAct sẽ bọc
trong <data> trước khi đưa vào prompt.
"""

from __future__ import annotations

import ast
import configparser
import email.parser
import tomllib
from pathlib import Path

NAME = "read_metadata"
DESCRIPTION = (
    "Đọc metadata của gói: setup.py (phân tích AST, không chạy), pyproject.toml, setup.cfg, "
    "PKG-INFO/METADATA. Trả tên, phiên bản, cmdclass, entry point, phụ thuộc, danh sách file, "
    "import và lời gọi đáng ngờ trong setup.py. Nên gọi đầu tiên."
)
INPUT_SCHEMA = {"path": "thư mục gói, mặc định '.' (gốc gói)"}

MAX_FILES_LISTED = 80
MAX_STR = 200
MAX_FILE_BYTES = 1024 * 1024  # bỏ qua file metadata lớn bất thường

SUSPICIOUS_CALLS = {
    "exec", "eval", "compile", "__import__",
    "os.system", "os.popen", "os.execv", "os.execve", "os.spawnl",
    "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
    "base64.b64decode", "base64.b85decode", "base64.a85decode", "codecs.decode", "zlib.decompress", "marshal.loads",
    "requests.get", "requests.post", "urllib.request.urlopen", "urlopen", "socket.socket", "socket.create_connection",
    "os.getenv", "os.environ.get", "getpass.getuser", "platform.node",
}
SUSPICIOUS_MODULES = {
    "subprocess", "socket", "requests", "urllib", "urllib.request", "http.client", "base64", "zlib", "marshal",
    "ctypes", "getpass", "platform", "shutil", "tempfile", "browser_cookie3", "win32crypt", "pynput", "discord",
}
INSTALL_BASES = {"install", "develop", "egg_info", "build_py", "build_ext", "sdist", "bdist_wheel", "build"}


def _s(v: object, n: int = MAX_STR) -> str:
    s = str(v)
    return s if len(s) <= n else s[:n] + "…"


def _read_text(p: Path) -> str | None:
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _literal(node: ast.AST | None) -> object:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)  # chỉ hằng số, không thực thi
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return f"<biểu thức: {_s(ast.unparse(node), 120)}>"


def analyze_setup_py(source: str) -> dict:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
        return {"parse_error": _s(e)}

    imports: set[str] = set()
    calls: dict[str, list[int]] = {}
    custom_commands: list[dict] = []
    setup_kwargs: dict[str, object] = {}
    environ_access: list[int] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
            for a in node.names:
                imports.add(f"{node.module}.{a.name}")
        elif isinstance(node, ast.ClassDef):
            bases = [(_dotted(b) or "").split(".")[-1] for b in node.bases]
            if any(b in INSTALL_BASES for b in bases):
                methods = [f.name for f in node.body if isinstance(f, ast.FunctionDef)]
                custom_commands.append({"class": node.name, "bases": bases, "line": node.lineno, "methods": methods})
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name is None:
                continue
            if name in SUSPICIOUS_CALLS or name.split(".")[-1] in {"b64decode", "urlopen", "system", "Popen"}:
                calls.setdefault(name, []).append(node.lineno)
            if name.split(".")[-1] == "setup" and not setup_kwargs:
                for kw in node.keywords:
                    if kw.arg in {"name", "version", "author", "author_email", "url", "description",
                                  "install_requires", "entry_points", "packages", "py_modules", "scripts"}:
                        setup_kwargs[kw.arg] = _literal(kw.value)
                    elif kw.arg == "cmdclass":
                        if isinstance(kw.value, ast.Dict):
                            setup_kwargs["cmdclass"] = {
                                _s(_literal(k)): _dotted(v) or _s(ast.unparse(v), 80)
                                for k, v in zip(kw.value.keys, kw.value.values) if k is not None
                            }
                        else:
                            setup_kwargs["cmdclass"] = f"<biểu thức: {_s(ast.unparse(kw.value), 120)}>"
                    elif kw.arg is None:
                        setup_kwargs["**kwargs"] = _s(ast.unparse(kw.value), 120)
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            if _dotted(node.value if isinstance(node, ast.Subscript) else node) == "os.environ":
                environ_access.append(node.lineno)

    return {
        "setup_kwargs": {k: _s(v, 300) if not isinstance(v, (dict, list)) else v for k, v in setup_kwargs.items()},
        "custom_install_commands": custom_commands,
        "suspicious_imports": sorted(i for i in imports if i in SUSPICIOUS_MODULES or i.split(".")[0] in SUSPICIOUS_MODULES),
        "suspicious_calls": {k: v[:10] for k, v in sorted(calls.items())},
        "os_environ_lines": sorted(set(environ_access))[:20],
        "lines": source.count("\n") + 1,
    }


def _pyproject(text: str) -> dict:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return {"parse_error": _s(e)}
    proj = data.get("project", {})
    return {
        "build_backend": data.get("build-system", {}).get("build-backend"),
        "build_requires": data.get("build-system", {}).get("requires"),
        "name": proj.get("name"),
        "version": proj.get("version"),
        "dependencies": proj.get("dependencies"),
        "scripts": proj.get("scripts"),
        "entry_points": proj.get("entry-points"),
        "setuptools_cmdclass": data.get("tool", {}).get("setuptools", {}).get("cmdclass"),
    }


def _setup_cfg(text: str) -> dict:
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read_string(text)
    except configparser.Error as e:
        return {"parse_error": _s(e)}
    out: dict[str, object] = {}
    if cp.has_section("metadata"):
        out.update({k: _s(cp.get("metadata", k)) for k in ("name", "version") if cp.has_option("metadata", k)})
    if cp.has_section("options"):
        if cp.has_option("options", "install_requires"):
            out["install_requires"] = _s(cp.get("options", "install_requires"), 300)
    if cp.has_section("options.entry_points"):
        out["entry_points"] = {k: _s(v) for k, v in cp.items("options.entry_points")}
    return out


def _pkg_info(text: str) -> dict:
    msg = email.parser.Parser().parsestr(text, headersonly=True)
    keys = ("Name", "Version", "Summary", "Author", "Author-email", "Home-page", "Requires-Dist")
    out: dict[str, object] = {}
    for k in keys:
        vals = msg.get_all(k)
        if vals:
            out[k] = [_s(v) for v in vals][:15] if k == "Requires-Dist" else _s(vals[0])
    return out


def _shallowest(root: Path, names: set[str]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for p in sorted(root.rglob("*"), key=lambda x: (len(x.parts), str(x))):
        if p.is_file() and not p.is_symlink() and p.name in names and p.name not in found:
            found[p.name] = p
    return found


def run(input: dict) -> dict:
    root = Path(input.get("path", "."))
    if not root.is_dir():
        return {"error": f"không phải thư mục: {input.get('path')}"}

    files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    out: dict[str, object] = {
        "files_count": len(files),
        "files": files[:MAX_FILES_LISTED],
        "files_truncated": len(files) > MAX_FILES_LISTED,
        "python_files": sum(f.endswith(".py") for f in files),
        "non_python_binaries": [f for f in files if f.rsplit(".", 1)[-1].lower() in {"exe", "dll", "so", "dylib", "bin", "pyc"}][:20],
    }

    found = _shallowest(root, {"setup.py", "pyproject.toml", "setup.cfg", "PKG-INFO", "METADATA"})
    for fname, key, parser in (
        ("setup.py", "setup_py", analyze_setup_py),
        ("pyproject.toml", "pyproject", _pyproject),
        ("setup.cfg", "setup_cfg", _setup_cfg),
        ("PKG-INFO", "pkg_info", _pkg_info),
        ("METADATA", "wheel_metadata", _pkg_info),
    ):
        p = found.get(fname)
        if p is None:
            continue
        text = _read_text(p)
        if text is None:
            out[key] = {"error": "file quá lớn hoặc không đọc được", "file": p.relative_to(root).as_posix()}
            continue
        res = parser(text)
        res["file"] = p.relative_to(root).as_posix()
        out[key] = res

    # entry_points.txt trong .dist-info / .egg-info
    for p in root.rglob("entry_points.txt"):
        text = _read_text(p)
        if text:
            out.setdefault("entry_points_txt", {})[p.relative_to(root).as_posix()] = _s(text, 400)

    name = (out.get("pkg_info") or out.get("wheel_metadata") or {}).get("Name") \
        or (out.get("pyproject") or {}).get("name") \
        or (out.get("setup_py") or {}).get("setup_kwargs", {}).get("name")
    version = (out.get("pkg_info") or out.get("wheel_metadata") or {}).get("Version") \
        or (out.get("pyproject") or {}).get("version") \
        or (out.get("setup_py") or {}).get("setup_kwargs", {}).get("version")
    # Thứ tự khoá: thông tin quan trọng trước, danh sách file sau cùng (bị cắt trước nếu quá dài).
    head = {"name": name, "version": version}
    tail_keys = ("files_count", "python_files", "non_python_binaries", "files_truncated", "files")
    body = {k: v for k, v in out.items() if k not in tail_keys}
    return {**head, **body, **{k: out[k] for k in tail_keys}}
