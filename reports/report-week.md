# Báo cáo tiến độ tuần 1 – Đồ án CMP198

**Đề tài:** Agent ReAct phân tích gói PyPI độc hại bằng GuardDog/Semgrep và tự sinh luật YARA
**Thời gian:** 23/11/2026 – 27/11/2026
**Repo:** https://github.com/UngVangDaiLam/PTMD (đã liên kết `origin`, **chưa commit, chưa push**)

---

## 1. Tóm tắt nhanh

- Phần code đang đi **nhanh hơn kế hoạch**: các tool của tuần 1 và tuần 2, cùng phần lớn tool của tuần 3 và tuần 4 trong mục 11 của CLAUDE.md, đã viết xong và có test.
- Nhưng tất cả mới chạy trên Windows với **LLM giả và GuardDog giả**. Chưa chạy lần nào trên VM với Ollama thật và mẫu độc thật.
- Bên cạnh đó thì VM Kali đang setup dở: đã nới ổ 80 GB và chuyển swap sang swapfile, còn Ollama, thư viện Python và bộ mẫu thì chưa cài.
- Tóm lại thì việc cần làm ngay là **push code → cài VM → chạy thử agent trên 2–3 mẫu thật**, để đạt mốc "agent gọi được ≥ 2 công cụ" của Buổi 4.

## 2. Đối chiếu với kế hoạch 5 tuần (mục 11)

| Tuần | Việc theo kế hoạch | Trạng thái |
|---|---|---|
| 1 | Môi trường VM, Ollama | ⏳ Đang làm (đã nới ổ đĩa và chuyển swap; chưa cài Ollama) |
| 1 | Bộ mẫu + đáp án | ❌ Chưa làm |
| 1 | `safe_extract`, `read_metadata`, `guarddog_tool` | ✅ Xong, có test |
| 1 | Vòng ReAct gọi được ≥ 2 tool | ✅ Xong về code, ⚠️ chưa chạy với Ollama thật |
| 2 | Semgrep + rule tự viết, typosquat, `read_file`, `decode_string` | ✅ Xong (làm trước) |
| 2 | Schema báo cáo | ✅ Có JSON trong `react_loop.finalize`; ❌ chưa xuất Markdown |
| 3 | `hash_lookup` (VT/OSV/MalwareBazaar), fuzzy hash | ✅ Xong code (làm trước) |
| 3 | Phân loại họ, chạy ≥ 3 mẫu có nhật ký | ⏳ Có tool, chưa có mẫu để chạy |
| 4 | `ml_classify`, `yara_generate_test` | ✅ Xong code (làm trước); ❌ chưa có mô hình đã huấn luyện |
| 4 | Lớp chống prompt injection | ✅ Đã có lớp bọc `<data>`; ❌ chưa có bộ thử injection |
| 4 | `run_eval` + `metrics` | ❌ Mới có file trống |
| 5 | Đánh giá 3 lần, báo cáo, slide, video | ❌ Chưa tới |

## 3. Những gì đã làm

### 3.1. Khung repo (mục 13, việc 1)
- Dựng đúng cấu trúc ở mục 9: `agent/`, `tools/`, `rules/semgrep/`, `ml/`, `data/`, `eval/`, `logs/`, `reports/`, `tests/`.
- Đã có `.gitignore` chặn `data/malicious/`, `data/injection/`, `.env` và mọi file nén, nên không lo lỡ tay đẩy mẫu độc lên GitHub.
- `config.yaml` gom hết cấu hình: model, số bước tối đa, giới hạn giải nén, đường dẫn bộ mẫu, mật khẩu zip DataDog. API key chỉ đọc từ `.env` (có sẵn `.env.example`).

### 3.2. Giải nén an toàn – `tools/safe_extract.py` (mục 13, việc 2)
- Không dùng `extractall`: tự đọc từng file rồi ghi ra, đồng thời bỏ quyền thực thi.
- Chặn path traversal (`../`, đường dẫn tuyệt đối, ổ `C:`, `\`). Bỏ qua symlink, hardlink, file thiết bị, nhưng ghi lại vào `warnings`, vì bản thân chúng đã là dấu hiệu đáng ngờ.
- Chống zip bomb bằng giới hạn số file, kích thước từng file, tổng dung lượng và tỉ lệ nén. Vượt giới hạn thì xoá thư mục tạm và báo lỗi.
- Giải được zip có mật khẩu của bộ DataDog (`infected`). Zip mà bên trong chỉ có một file nén khác thì giải tiếp một lớp.
- Có 31 test riêng cho phần này.

### 3.3. Vòng ReAct – `agent/react_loop.py` (mục 13, việc 3)
- Mỗi bước: mô hình trả JSON `{thought, action, action_input}` → gọi tool qua allowlist → rút gọn kết quả → bọc `<data>` → trả lại làm Observation. Tối đa 12 bước, bước cuối bắt buộc `final_answer`.
- Mô hình trả JSON hỏng, gọi tool không có, tool lỗi hay Ollama sập đều được ghi log rồi chạy tiếp, không crash.
- Mỗi lần chạy ghi `logs/<timestamp>_<gói>.jsonl` (mỗi dòng một bước) và `reports/<…>.json`.
- **Chặn bịa:** hành vi hoặc IOC nào có `evidence.tool` không phải tool đã chạy thành công thì bị chuyển sang `unknowns` và đếm vào `stats.unsupported_claims`. Số này dùng luôn cho chỉ số "Bịa" ở mục 8.
- Luật YARA trong báo cáo chỉ lấy luật **đã qua** `yara_generate_test`. Mô hình tự viết mà chưa kiểm tra thì không nhận.
- CLI `python -m agent analyze <gói>` từ chối chạy nếu chưa đặt `CMP198_SANDBOX=1`, để không lỡ chạy ngoài VM.

### 3.4. Đủ 10 tool trong allowlist

| Tool | Làm gì |
|---|---|
| `read_metadata` | Đọc `setup.py` bằng AST (không chạy), cùng pyproject, setup.cfg, PKG-INFO; tìm cmdclass, entry point, lời gọi đáng ngờ |
| `check_typosquat` | So tên gói với khoảng 300 gói phổ biến (offline): sai 1–2 ký tự, đảo ký tự, `0/o`, `rn/m`, thêm `python-`/`-py`… |
| `guarddog_scan` | Chạy GuardDog, rút gọn theo rule bị kích hoạt |
| `semgrep_scan` | Chạy Semgrep với 10 rule tự viết, tắt gửi thống kê |
| `read_file` | Đọc đoạn file có số dòng, kèm IOC tìm thấy trong đoạn đó |
| `decode_string` | Giải base64/hex/zlib/rot13… nhiều lớp, không bao giờ chạy kết quả |
| `hash_lookup` | SHA-256 rồi tra VirusTotal (**chỉ hash**), MalwareBazaar, OSV (`MAL-`); có cache, giới hạn 4 req/phút |
| `fuzzy_similarity` | So ssdeep/TLSH với mẫu đã biết họ |
| `ml_classify` | TF-IDF + Random Forest dự đoán loại hành vi |
| `yara_generate_test` | Biên dịch luật YARA, quét bộ độc và bộ sạch, trả TPR/FPR |

- Rule Semgrep (mục 13, việc 5) nằm ở `rules/semgrep/pypi_malicious.yml`, gồm: cmdclass gọi mạng/chạy lệnh, `exec` trên base64/zlib, biến môi trường gửi qua HTTP, beacon thông tin máy, tải rồi chạy, webhook Discord/Telegram, đường dẫn credential, blob base64 dài, `setup.py` chạy lệnh hệ thống.
- Đã có `ml/train.py` để huấn luyện mô hình và `python -m tools.fuzzy build` để dựng chỉ mục fuzzy, nhưng chưa có dữ liệu để chạy.

### 3.5. Kết quả test
- Chạy trong venv có semgrep 1.186, yara-python, ppdeep, scikit-learn thật: **78/78 test qua**.
- Riêng Python hệ thống trên Windows: 73 qua, 5 bỏ qua (thiếu thư viện).
- Trong đó có test kiểm tra đúng từng rule Semgrep bắt được mẫu giả độc, và gói sạch không bị báo mức ERROR.
- Như vậy phần an toàn đã được test kỹ: không chạy `setup.py`, không giải ra ngoài thư mục, không upload file lên VT, payload giải mã không bị thực thi.

### 3.6. VM Kali
- Cấu hình: 6 GB RAM, 4 CPU, ổ đã nới từ 60 GB lên 80 GB, mạng NAT.
- Đã xoá phân vùng swap cũ (`sda2`/`sda5`), nới `sda1`, tạo swapfile 4 GB và sửa `fstab` cùng `resume`.
- ⚠️ Cần kiểm tra lại sau khi reboot: `df -h /` phải khoảng 79G, `free -h` phải thấy Swap 4.0Gi.

## 4. Còn thiếu / chưa kiểm chứng

- **Chưa chạy thật lần nào:** chưa có Ollama, GuardDog chạy trên Linux và mẫu độc thật, nên chưa biết `qwen2.5` có trả JSON ổn định không, cũng như 12 bước có đủ cho 10 tool không.
- **RAM 6 GB không đủ cho `qwen2.5:7b`.** Nếu không tăng lên 12–16 GB được thì tạm dùng `qwen2.5:3b`.
- **Chưa test được:** giải zip có mật khẩu (thư viện chuẩn của Python không tạo được zip mã hoá để test) và TLSH (không build được trên Windows). Hai phần này phải thử trong VM.
- Chưa có bộ mẫu (20–30 độc, 20–30 sạch), đáp án `ground_truth/` và bộ thử prompt injection.
- Mấy file còn trống: `agent/report.py` (xuất Markdown), `eval/metrics.py`, `eval/run_eval.py`.
- **Rủi ro điểm ảo:** nếu mô hình ML và chỉ mục fuzzy dựng từ chính bộ mẫu dùng để đánh giá agent thì điểm sẽ đẹp giả. Báo cáo cuối phải dùng cross-validation hoặc tách riêng tập train và tập test.
- Cần hỏi thầy: có được chạy Ollama trên máy thật rồi để VM gọi sang không (máy thật có GPU nên nhanh hơn nhiều, mô hình cũng chỉ nhận đặc trưng chứ không nhận file).

## 5. Việc tuần sau

| Việc | Ai | Ghi chú |
|---|---|---|
| Commit + push code lên GitHub | A | Cả nhóm `git clone` về VM |
| Cài VM: Ollama (`qwen2.5:3b`, nếu đủ RAM thì thêm `7b`), venv, `pip install -r requirements.txt`, `pytest` | A | Đặt `CMP198_SANDBOX=1`, chụp snapshot `PTMD-clean` |
| Chạy thử agent trên 2–3 mẫu thật, đọc log `.jsonl` để chỉnh prompt | A | Mốc Buổi 4: agent gọi được ≥ 2 tool |
| Kiểm tra lại rule Semgrep và GuardDog trên mẫu thật, đặt VT key vào `.env` | B | Thêm rule nếu thấy mẫu nào lọt |
| Tải phần PyPI của bộ DataDog (sparse checkout), chọn 20–30 mẫu, viết `ground_truth/*.json` | C | Mật khẩu zip `infected` |
| Tải 20–30 gói sạch "giống độc": nhỏ, `setup.py` tuỳ biến, có gọi HTTP, đọc biến môi trường | C | `pip download --no-deps --no-binary :all: <tên>` |
| Viết `agent/report.py` (xuất Markdown) và `eval/metrics.py` | A + C | Theo công thức mục 8 |

## 6. Lệnh hay dùng

```bash
export CMP198_SANDBOX=1
python -m agent analyze data/malicious/<gói>.zip --model qwen2.5:3b
python -m tools.fuzzy build --password infected
python -m ml.train --password infected
pytest -q
```
