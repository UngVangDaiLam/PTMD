"""Huấn luyện mô hình phân loại hành vi: TF-IDF trên token mã + Random Forest.

    python -m ml.train [--data data] [--out ml/model.joblib] [--password infected]

Nhãn: mẫu trong data/benign -> "benign"; mẫu trong data/malicious -> family.behavior_type
trong data/ground_truth/<id>.json (thiếu thì "other"). In kết quả cross-validation
(precision/recall theo lớp) để đưa vào báo cáo.

Lưu ý đánh giá: mô hình huấn luyện trên chính bộ mẫu dùng để chạy agent sẽ cho điểm ảo;
khi báo cáo, dùng số liệu cross-validation hoặc tách tập train/test.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from ml.features import FEATURE_VERSION, tokens_of_package
from tools.samples import family_of, iter_samples, load_ground_truth, open_sample

BEHAVIORS = ["stealer", "downloader_dropper", "reverse_shell", "cryptominer", "dependency_confusion_beacon", "other"]


def build_pipeline():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline
    return Pipeline([
        ("tfidf", TfidfVectorizer(tokenizer=str.split, lowercase=False, token_pattern=None,
                                  ngram_range=(1, 2), min_df=1, max_features=20000, sublinear_tf=True)),
        ("rf", RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1)),
    ])


def collect(data_dir: Path, password: bytes | None) -> tuple[list[str], list[str], list[str]]:
    gts = load_ground_truth(data_dir / "ground_truth")
    X, y, ids = [], [], []
    for sub, default in (("benign", "benign"), ("malicious", None)):
        for sid, p in iter_samples(data_dir / sub):
            label = default
            if label is None:
                _, beh = family_of(gts.get(sid))
                label = beh if beh in BEHAVIORS else "other"
            try:
                with open_sample(p, password) as root:
                    X.append(tokens_of_package(root))
            except Exception as e:
                print(f"bỏ qua {sid}: {e}", file=sys.stderr)
                continue
            y.append(label)
            ids.append(sid)
    return X, y, ids


def train(data_dir: Path, out: Path, password: bytes | None = None, cv: int = 5) -> dict:
    import joblib
    from sklearn.metrics import classification_report
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    X, y, ids = collect(data_dir, password)
    if len(set(y)) < 2:
        raise SystemExit(f"cần ít nhất 2 lớp để huấn luyện, hiện có: {sorted(set(y))}")
    report = None
    min_class = min(y.count(c) for c in set(y))
    folds = min(cv, min_class)
    if folds >= 2:
        pred = cross_val_predict(build_pipeline(), X, y, cv=StratifiedKFold(folds, shuffle=True, random_state=0))
        report = classification_report(y, pred, zero_division=0)
        print(f"Cross-validation {folds} fold:\n{report}")
    else:
        print("ít mẫu quá, bỏ qua cross-validation", file=sys.stderr)

    pipe = build_pipeline().fit(X, y)
    bundle = {
        "pipeline": pipe,
        "classes": list(pipe.classes_),
        "feature_version": FEATURE_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "n_samples": len(y),
        "label_counts": {c: y.count(c) for c in sorted(set(y))},
        "train_ids": ids,
        "cv_report": report,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out)
    print(f"đã lưu mô hình: {out} ({len(y)} mẫu, lớp {bundle['label_counts']})")
    return bundle


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ml.train")
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="ml/model.joblib")
    ap.add_argument("--password", help="mật khẩu zip của bộ mẫu (vd. infected)")
    ap.add_argument("--cv", type=int, default=5)
    a = ap.parse_args(argv)
    train(Path(a.data), Path(a.out), a.password.encode() if a.password else None, a.cv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
