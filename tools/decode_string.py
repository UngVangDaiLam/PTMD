"""Tool `decode_string`: giải base64 / base32 / base85 / hex / zlib / gzip / bz2 / lzma / rot13 /
đảo ngược chuỗi, có thể nối nhiều lớp (vd. "base64,zlib") hoặc "auto" tự dò tối đa 5 lớp.

TUYỆT ĐỐI không thực thi kết quả: chỉ trả bản xem trước dạng text + IOC tìm thấy.
Không có bước nào gọi exec/eval/marshal.loads/pickle.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import io
import lzma
import re
import zlib

from tools.common import extract_iocs, is_binary

NAME = "decode_string"
DESCRIPTION = (
    "Giải mã một chuỗi bị làm rối (base64, base32, base85, hex, zlib, gzip, bz2, lzma, rot13, reverse). "
    "methods: danh sách theo thứ tự, vd. [\"base64\",\"zlib\"], hoặc \"auto\" để tự dò. "
    "Kết quả chỉ để đọc, KHÔNG bao giờ chạy."
)
INPUT_SCHEMA = {"data": "chuỗi cần giải (bỏ dấu nháy)", "methods": "\"auto\" hoặc danh sách cách giải"}

MAX_INPUT = 200_000
MAX_OUTPUT = 5 * 1024 * 1024  # chặn decompression bomb
PREVIEW = 1500
AUTO_MAX_LAYERS = 5

_B64 = re.compile(rb"^[A-Za-z0-9+/=\s_-]+$")
_HEX = re.compile(rb"^(?:0x)?[0-9a-fA-F\s]+$")


def _bounded_decompress(data: bytes, kind: str) -> bytes:
    if kind == "zlib":
        d = zlib.decompressobj(wbits=47)  # tự nhận zlib/gzip header
        out = d.decompress(data, MAX_OUTPUT + 1)
    elif kind == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
            out = g.read(MAX_OUTPUT + 1)
    elif kind == "bz2":
        d = bz2.BZ2Decompressor()
        out = d.decompress(data, MAX_OUTPUT + 1)
    elif kind == "lzma":
        d = lzma.LZMADecompressor()
        out = d.decompress(data, MAX_OUTPUT + 1)
    else:
        raise ValueError(kind)
    if len(out) > MAX_OUTPUT:
        raise ValueError("kết quả giải nén vượt 5 MB (nghi decompression bomb)")
    return out


def _decode(data: bytes, method: str) -> bytes:
    m = method.lower().strip()
    if m == "base64":
        s = re.sub(rb"\s+", b"", data)
        s = s.replace(b"-", b"+").replace(b"_", b"/")
        return base64.b64decode(s + b"=" * (-len(s) % 4), validate=True)
    if m == "base32":
        s = re.sub(rb"\s+", b"", data).upper()
        return base64.b32decode(s + b"=" * (-len(s) % 8))
    if m == "base85":
        return base64.b85decode(re.sub(rb"\s+", b"", data))
    if m == "a85":
        return base64.a85decode(re.sub(rb"\s+", b"", data))
    if m == "hex":
        s = re.sub(rb"\s+|0x|\\x", b"", data)
        return binascii.unhexlify(s)
    if m in {"zlib", "gzip", "bz2", "lzma"}:
        return _bounded_decompress(data, m)
    if m == "rot13":
        return codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")
    if m == "reverse":
        return data[::-1]
    raise ValueError(f"cách giải không hỗ trợ: {method}")


def _auto_next(data: bytes) -> list[str]:
    """Các cách thử theo thứ tự, dựa trên hình dạng dữ liệu."""
    if data[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e"):
        return ["zlib"]
    if data[:2] == b"\x1f\x8b":
        return ["gzip"]
    if data[:3] == b"BZh":
        return ["bz2"]
    if data[:6] == b"\xfd7zXZ\x00":
        return ["lzma"]
    s = data.strip()
    if len(s) >= 8 and _HEX.match(s) and len(re.sub(rb"\s+|0x", b"", s)) % 2 == 0:
        return ["hex", "base64"]
    if len(s) >= 8 and _B64.match(s):
        return ["base64"]
    if s.startswith(b"=") and _B64.match(s):  # base64 bị đảo ngược
        return ["reverse"]
    return []


def _preview(b: bytes) -> dict:
    if is_binary(b):
        return {"kind": "binary", "size": len(b), "head_hex": b[:48].hex()}
    text = b.decode("utf-8", errors="replace")
    return {"kind": "text", "size": len(b), "text": text[:PREVIEW] + ("…" if len(text) > PREVIEW else "")}


def run(input: dict) -> dict:
    data = input.get("data")
    if not isinstance(data, str) or not data:
        return {"error": "thiếu 'data' (chuỗi cần giải)"}
    if len(data) > MAX_INPUT:
        return {"error": f"chuỗi quá dài ({len(data)} ký tự, tối đa {MAX_INPUT})"}
    cur = data.strip().strip("'\"").encode("utf-8", errors="replace")
    if cur[:2] in (b"b'", b'b"'):
        cur = cur[2:].rstrip(b"'\"")
    methods = input.get("methods", "auto")

    applied: list[str] = []
    errors: list[str] = []
    if methods == "auto" or methods == ["auto"]:
        for _ in range(AUTO_MAX_LAYERS):
            for m in _auto_next(cur):
                try:
                    nxt = _decode(cur, m)
                except Exception as e:  # thử cách khác
                    errors.append(f"{m}: {type(e).__name__}")
                    continue
                if not nxt or nxt == cur:
                    continue
                # base64/hex "giải được" nhưng ra rác nhị phân không nén -> không phải lớp mã hoá thật
                if m in {"base64", "hex"} and is_binary(nxt) and not _auto_next(nxt):
                    errors.append(f"{m}: ra dữ liệu rác")
                    continue
                cur = nxt
                applied.append(m)
                break
            else:
                break
    else:
        if isinstance(methods, str):
            methods = [x for x in re.split(r"[,\s+>|]+", methods) if x]
        if not isinstance(methods, list) or len(methods) > 10:
            return {"error": "methods phải là 'auto' hoặc danh sách ≤ 10 cách giải"}
        for m in methods:
            try:
                cur = _decode(cur, str(m))
                applied.append(str(m))
            except Exception as e:
                return {"error": f"giải '{m}' thất bại sau {applied}: {type(e).__name__}: {e}",
                        "partial": _preview(cur)}

    result = _preview(cur)
    out = {"applied": applied, "result": result}
    if result["kind"] == "text":
        out["iocs"] = extract_iocs(cur.decode("utf-8", errors="replace"), max_items=15)
        low = result["text"].lower()
        out["looks_like_code"] = any(k in low for k in ("import ", "exec(", "eval(", "def ", "subprocess", "os.system"))
    if not applied:
        out["note"] = "không nhận ra lớp mã hoá nào" + (f" (thử: {errors[:5]})" if errors else "")
    return out
