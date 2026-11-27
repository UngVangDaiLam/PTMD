"""Tool `ml_classify`: mô hình TF-IDF + Random Forest (ml/train.py) dự đoán loại hành vi của gói.

Mô hình là MỘT công cụ của agent, không phải trọng tài: kết quả kèm xác suất và các token
quan trọng có mặt trong gói để agent đối chiếu với bằng chứng từ tool khác.
File mô hình do nhóm tự huấn luyện (joblib); chỉ nạp file từ đường dẫn trong config.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

NAME = "ml_classify"
DESCRIPTION = (
    "Mô hình học máy (TF-IDF trên token mã + Random Forest) dự đoán loại hành vi: benign, stealer, "
    "downloader_dropper, reverse_shell, cryptominer, dependency_confusion_beacon, other. Trả xác suất "
    "và token đặc trưng. Chỉ là một nguồn tham khảo, cần đối chiếu bằng chứng."
)
INPUT_SCHEMA = {"path": "thư mục gói, mặc định '.'"}

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL = PROJECT_ROOT / "ml" / "model.joblib"


@lru_cache(maxsize=2)
def _load(path: str, mtime: float) -> dict:
    import joblib
    return joblib.load(path)


def run(input: dict) -> dict:
    root = Path(input.get("path", "."))
    if not root.is_dir():
        return {"error": f"không phải thư mục: {input.get('path')}"}
    model_path = Path(input.get("_model_path", DEFAULT_MODEL))
    if not model_path.is_file():
        return {"error": f"chưa có mô hình ({model_path.name}); huấn luyện bằng: python -m ml.train"}
    try:
        bundle = _load(str(model_path), model_path.stat().st_mtime)
    except Exception as e:
        return {"error": f"không nạp được mô hình: {type(e).__name__}"}

    from ml.features import FEATURE_VERSION, tokens_of_package
    if bundle.get("feature_version") != FEATURE_VERSION:
        return {"error": "mô hình cũ không khớp phiên bản đặc trưng, cần huấn luyện lại"}
    text = tokens_of_package(root)
    if not text:
        return {"error": "gói không có mã Python để phân loại"}
    pipe = bundle["pipeline"]
    proba = pipe.predict_proba([text])[0]
    classes = list(pipe.classes_)
    ranked = sorted(zip(classes, proba), key=lambda x: -x[1])

    # token quan trọng (theo feature_importances_) có mặt trong gói
    top_tokens: list[str] = []
    try:
        tfidf, rf = pipe.named_steps["tfidf"], pipe.named_steps["rf"]
        vec = tfidf.transform([text])
        present = vec.nonzero()[1]
        names = tfidf.get_feature_names_out()
        imp = rf.feature_importances_
        top_tokens = [str(names[i]) for i in sorted(present, key=lambda i: -imp[i])[:12]]
    except Exception:
        pass

    best, p = ranked[0]
    return {
        "prediction": best,
        "probability": round(float(p), 3),
        "confidence": "high" if p >= 0.75 else "medium" if p >= 0.5 else "low",
        "top3": [{"label": c, "p": round(float(q), 3)} for c, q in ranked[:3]],
        "important_tokens_present": top_tokens,
        "model": {"trained_at": bundle.get("trained_at"), "n_samples": bundle.get("n_samples"),
                  "label_counts": bundle.get("label_counts")},
    }
