# CMP198: Agent ReAct phân tích gói PyPI độc hại

Agent chạy local (Ollama, `qwen2.5:7b`) điều phối GuardDog, Semgrep, tra hash, fuzzy hash, mô hình học máy và YARA để phân tích một gói PyPI (`.tar.gz` / `.whl`). Chi tiết đề tài, ràng buộc và kiến trúc: xem [CLAUDE.md](CLAUDE.md).

> **An toàn:** chỉ chạy trong máy ảo cô lập. Không cài, import hay chạy mã của mẫu. Không gửi file mẫu lên dịch vụ đám mây; VirusTotal chỉ tra bằng SHA-256.

## Cài đặt (trong VM)

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # điền VT_API_KEY nếu dùng
ollama pull qwen2.5:7b
```

## Sử dụng

```bash
export CMP198_SANDBOX=1                      # CLI từ chối chạy nếu không có biến này (chỉ đặt trong VM)
python -m agent analyze <đường dẫn gói>
python -m eval.run_eval --runs 3
pytest
```

Chuẩn bị dữ liệu cho các tool (chạy trong VM, sau khi có `data/malicious`, `data/benign`, `data/ground_truth`):

```bash
python -m tools.typosquat refresh --top 5000         # cập nhật danh sách gói phổ biến (chỉ tải danh sách tên)
python -m tools.fuzzy build --password infected      # chỉ mục ssdeep/TLSH của mẫu độc đã biết họ
python -m ml.train --password infected               # huấn luyện TF-IDF + Random Forest, in cross-validation
```

Mẫu DataDog là zip có mật khẩu: đặt `extract.sample_zip_password: infected` trong `config.yaml`.

## Tool của agent (allowlist trong `tools/registry.py`)

| Tool | Việc làm |
|---|---|
| `read_metadata` | setup.py (phân tích AST, không chạy), pyproject, setup.cfg, PKG-INFO; cmdclass, entry point, lời gọi đáng ngờ |
| `check_typosquat` | so tên với danh sách gói phổ biến offline (Levenshtein, đảo ký tự, ký tự giống nhau, tiền tố/hậu tố) |
| `guarddog_scan` | GuardDog, rút gọn theo rule bị kích hoạt |
| `semgrep_scan` | Semgrep với rule local `rules/semgrep/` (`--metrics=off`) |
| `read_file` | đọc đoạn file có số dòng, kèm IOC trong đoạn |
| `decode_string` | giải base64/hex/zlib/rot13… nhiều lớp, không bao giờ chạy kết quả |
| `hash_lookup` | SHA-256; VirusTotal (chỉ hash), MalwareBazaar, OSV; cache + 4 req/phút |
| `fuzzy_similarity` | ssdeep + TLSH so với chỉ mục mẫu đã biết họ |
| `ml_classify` | TF-IDF + Random Forest dự đoán loại hành vi |
| `yara_generate_test` | biên dịch luật YARA, chạy trên bộ độc và bộ sạch, trả TPR/FPR |

## Cấu trúc

| Thư mục | Nội dung |
|---|---|
| `agent/` | vòng ReAct, prompt, client Ollama, xuất báo cáo |
| `tools/` | các tool trong allowlist, `safe_extract.py` |
| `rules/semgrep/` | rule Semgrep tự viết |
| `ml/` | trích đặc trưng, huấn luyện mô hình phân loại |
| `data/` | mẫu (không commit `malicious/`, `injection/`) và `ground_truth/` |
| `eval/` | chạy đánh giá, tính chỉ số |
| `logs/` | nhật ký ReAct `.jsonl` |
| `reports/` | báo cáo JSON + Markdown |
| `tests/` | test pytest |
