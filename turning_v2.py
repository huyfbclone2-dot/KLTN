#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
finetune_cicids_zeek_multiclass.py

Fine-tune (tiếp tục train) một model multi-class 4 lớp từ train_cicids_zeek.py
trên một CSV mới (dataset tự tấn công & gắn nhãn).

- Yêu cầu: model gốc được train bằng train_cicids_zeek.py bản 4 lớp:
    0: benign
    1: dos
    2: portscan
    3: ftp_bruteforce

- CSV fine-tune phải có:
    + Các cột feature tương thích Zeek/CIC-IDS (FlowDuration, TotLenFwdPkts, ...)
    + Một cột label (Label / label / Class / Attack ...) được
      build_features_zeekmin() hiểu và map sang 4 lớp trên.

Artifacts trong --outdir:
  - model.keras (model sau fine-tune)
  - metrics.json (accuracy)
  - classification_report_val.txt
  - confusion_matrix_val.csv
"""

import os
import json
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

import tensorflow as tf
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)
from sklearn.model_selection import train_test_split

# Import helper từ script train multi-class
from train_cicids_zeek_v2 import (
    normalize_columns,
    build_features_zeekmin,
    to_dataset,
    CLASS_NAMES,
)

# ----------------------------------------------------
# helpers
# ----------------------------------------------------
def ensure_outdir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def make_inputs(X: pd.DataFrame):
    """Tạo dict input cho Keras từ DataFrame feature."""
    return {c: X[c].values for c in X.columns}


def evaluate_and_save_multiclass(
    model,
    X_eval: pd.DataFrame,
    y_eval: np.ndarray,
    outdir: str,
    tag: str = "val",
    batch_size: int = 8192,
):
    """
    Đánh giá model multi-class trên tập eval và lưu báo cáo.
    Dùng argmax trên softmax output để lấy nhãn dự đoán.
    """
    inputs_eval = make_inputs(X_eval)
    probs = model.predict(inputs_eval, batch_size=batch_size, verbose=0)
    y_pred = np.argmax(probs, axis=1)

    acc = float(accuracy_score(y_eval, y_pred))

    # Lưu metrics đơn giản
    (Path(outdir) / "metrics.json").write_text(
        json.dumps(
            {
                "accuracy": acc,
                "num_classes": int(probs.shape[1]),
                "class_names": list(CLASS_NAMES),
            },
            indent=2,
        )
    )

    # classification report + confusion matrix
    try:
        report = classification_report(
            y_eval,
            y_pred,
            digits=4,
            target_names=CLASS_NAMES[: probs.shape[1]],
        )
        (Path(outdir) / f"classification_report_{tag}.txt").write_text(report)

        cm = confusion_matrix(
            y_eval,
            y_pred,
            labels=list(range(probs.shape[1])),
        )
        cm_df = pd.DataFrame(
            cm,
            index=[f"true_{n}" for n in CLASS_NAMES[: probs.shape[1]]],
            columns=[f"pred_{n}" for n in CLASS_NAMES[: probs.shape[1]]],
        )
        cm_df.to_csv(Path(outdir) / f"confusion_matrix_{tag}.csv")
    except Exception as e:
        print("[WARN] Không thể tạo report/confusion matrix:", e)

    return acc


# ----------------------------------------------------
# main
# ----------------------------------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True, help="Đường dẫn tới model gốc (.keras)")
    p.add_argument("--finetune_csv", required=True, help="CSV mới để fine-tune")
    p.add_argument("--outdir", required=True, help="Thư mục lưu model mới & metrics")

    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch", type=int, default=2048)
    p.add_argument("--lr", type=float, default=5e-4)
    p.add_argument("--val_split", type=float, default=0.15, help="Tỉ lệ validation")
    p.add_argument("--seed", type=int, default=44)

    args = p.parse_args()

    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)

    ensure_outdir(args.outdir)

    # 1) Load base model
    print(f"[INFO] Loading base model: {args.model}")
    model = tf.keras.models.load_model(args.model)

    # cố gắng set learning rate mới
    try:
        tf.keras.backend.set_value(model.optimizer.lr, args.lr)
    except Exception:
        try:
            tf.keras.backend.set_value(model.optimizer.learning_rate, args.lr)
        except Exception:
            print("[WARN] Không set được LR; dùng LR cũ của model.")

    # kiểm tra số lớp output
    out_shape = model.output_shape
    if isinstance(out_shape, tuple):
        num_classes_model = out_shape[-1]
    else:
        num_classes_model = out_shape[0][-1]
    print(f"[INFO] Model output classes: {num_classes_model}")

    # 2) Load CSV fine-tune
    print(f"[INFO] Loading finetune CSV: {args.finetune_csv}")
    df = pd.read_csv(args.finetune_csv)
    df = normalize_columns(df)

    # 3) Build features + labels (multi-class 4 lớp)
    #    build_features_zeekmin sẽ tự map label và bỏ các nhãn không thuộc 4 lớp.
    X_all, y_all, num_names, cat_names = build_features_zeekmin(df)
    y_all = np.asarray(y_all, dtype=np.int32)

    print(f"[INFO] Tổng số mẫu sau khi build & lọc: {len(y_all)}")
    print("[INFO] Phân bố label trong batch fine-tune:")
    print(pd.Series(y_all).value_counts().sort_index())
    print("Mapping lớp (theo CLASS_NAMES):")
    for i, name in enumerate(CLASS_NAMES):
        print(f"  {i}: {name}")

    if len(y_all) == 0:
        raise RuntimeError("Không còn mẫu nào sau khi lọc label – kiểm tra lại cột Label & giá trị nhãn.")

    # 4) Train/Val split
    cols = list(X_all.columns)
    stratify_arg = y_all if len(np.unique(y_all)) > 1 else None
    idx_tr, idx_va = train_test_split(
        np.arange(len(y_all)),
        test_size=args.val_split,
        random_state=args.seed,
        shuffle=True,
        stratify=stratify_arg,
    )

    X_tr, y_tr = X_all.iloc[idx_tr], y_all[idx_tr]
    X_va, y_va = X_all.iloc[idx_va], y_all[idx_va]

    print(f"[INFO] Train size: {len(y_tr)}, Val size: {len(y_va)}")

    # convert sang Series để dùng to_dataset
    y_tr_series = pd.Series(y_tr)
    y_va_series = pd.Series(y_va)

    ds_tr = to_dataset(X_tr[cols], y_tr_series, batch=args.batch, shuffle=True)
    ds_va = to_dataset(X_va[cols], y_va_series, batch=args.batch, shuffle=False)

    # 5) Fine-tune
    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_accuracy",
            mode="max",
            patience=3,
            restore_best_weights=True,
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor="val_accuracy",
            mode="max",
            patience=2,
            factor=0.5,
            min_lr=1e-6,
        ),
        tf.keras.callbacks.ModelCheckpoint(
            filepath=str(Path(args.outdir) / "checkpoint.keras"),
            monitor="val_accuracy",
            mode="max",
            save_best_only=True,
        ),
    ]

    print("[INFO] Bắt đầu fine-tune...")
    model.fit(
        ds_tr,
        validation_data=ds_va,
        epochs=args.epochs,
        verbose=2,
        callbacks=callbacks,
    )

    # 6) Evaluate & save reports trên val
    print("[INFO] Đánh giá trên tập validation (held-out)...")
    acc_val = evaluate_and_save_multiclass(
        model,
        X_va[cols],
        y_va,
        args.outdir,
        tag="val",
        batch_size=args.batch,
    )
    print(f"[INFO] Val accuracy sau fine-tune: {acc_val:.4f}")

    # 7) Save updated model
    out_model = Path(args.outdir) / "model.keras"
    model.save(out_model)
    print(f"[OK] Đã lưu model sau fine-tune vào: {out_model}")


if __name__ == "__main__":
    main()
