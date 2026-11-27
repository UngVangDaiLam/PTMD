# Quy ước git khi làm với Claude Code

- **Không tự `git push`.** Push do người trong nhóm tự làm (`.claude/settings.json` cũng chặn lệnh này). Chỉ commit khi được yêu cầu.
- **Mỗi lượt có thay đổi code** (thêm/sửa/xoá file trong repo), cuối lượt đề xuất một commit message sẵn để chép, theo dạng:

  ```
  <loại>(<phạm vi>): <tóm tắt ngắn, tiếng Việt>

  - ý chính 1
  - ý chính 2
  ```

  `loại`: `feat` (tính năng mới), `fix` (sửa lỗi), `test`, `docs`, `refactor`, `chore` (cấu hình, dọn dẹp). `phạm vi`: thư mục hoặc tool chính, vd. `tools/yara`, `agent`, `rules`. Bỏ `(<phạm vi>)` nếu thay đổi trải nhiều nơi.
- Không commit `.env`, mẫu độc, file nén, `ml/model.joblib`.
