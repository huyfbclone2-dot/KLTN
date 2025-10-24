#!/usr/bin/env python3
"""
finetune_cicids_zeek.py (updated)

Fine-tune (continue training) an existing model from train_cicids_zeek.py
on a new CSV batch exported from Zeek conn.log (or any compatible source).

Modes:
  1) Supervised (recommended): CSV has a label column -> fine-tune with true labels
  2) Pseudo-label: If labels are missing or you pass --pseudo_label, we generate labels
     from the base model's current predictions using a decision threshold (default 0.5)
     and/or a top-k% fallback if no positives at the threshold.

Artifacts written to --outdir:
  - model.keras
  - metrics.json
  - metrics_threshold.json
  - classification_report_val.txt
  - confusion_matrix_val.csv

Requires: train_cicids_zeek.py in PYTHONPATH providing
  normalize_columns, build_features_zeekmin, to_dataset, maximin_threshold
"""

import os
import json
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

import tensorflow as tf
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score
from sklearn.model_selection import train_test_split

# Import helpers from your training script
from train_cicids_zeek import (
    normalize_columns,
    build_features_zeekmin,
    to_dataset,
    maximin_threshold,
)


def ensure_outdir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def make_inputs(X: pd.DataFrame):
    """Builds Keras input dict from a (numeric+categorical) feature frame."""
    return {c: X[c].values for c in X.columns}


def evaluate_and_save(model, X_eval: pd.DataFrame, y_eval: np.ndarray, outdir: str, tag: str = "val"):
    inputs_eval = make_inputs(X_eval)
    y_score = model.predict(inputs_eval, batch_size=8192, verbose=0).ravel()

    # Basic metrics
    metrics = {}
    try:
        metrics["auc"] = float(roc_auc_score(y_eval, y_score))
    except Exception:
        metrics["auc"] = None

    # Tune threshold by maximin (uses same set as both train/val for simplicity here)
    thr, a_tr, a_va = maximin_threshold(y_eval, y_score, y_eval, y_score, max_points=512)
    y_pred = (y_score >= thr).astype(int)
    acc = float(accuracy_score(y_eval, y_pred))

    # Save reports
    (Path(outdir) / f"metrics_threshold.json").write_text(json.dumps({
        "threshold": float(thr),
        "acc_tuned": acc,
        "acc_train_proxy": float(a_tr),
        "acc_val_proxy": float(a_va),
    }, indent=2))

    (Path(outdir) / f"metrics.json").write_text(json.dumps({
        "auc": metrics["auc"],
        f"acc@{thr:.3f}": acc,
    }, indent=2))

    try:
        report = classification_report(y_eval, y_pred, digits=4)
        (Path(outdir) / f"classification_report_{tag}.txt").write_text(report)
        cm = confusion_matrix(y_eval, y_pred)
        pd.DataFrame(cm, index=["neg","pos"], columns=["pred_neg","pred_pos"]).to_csv(Path(outdir)/f"confusion_matrix_{tag}.csv")
    except Exception:
        pass

    return thr, y_score


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True, help="Path to base model .keras")
    p.add_argument("--finetune_csv", required=True, help="New batch CSV (from conn.log export)")
    p.add_argument("--outdir", required=True, help="Output dir for updated model and metrics")

    p.add_argument("--epochs", type=int, default=2)
    p.add_argument("--batch", type=int, default=2048)
    p.add_argument("--lr", type=float, default=5e-4)
    p.add_argument("--val_split", type=float, default=0.15, help="Validation split for the new batch")
    p.add_argument("--seed", type=int, default=44)

    p.add_argument("--label_col", default="Label", help="Name of label column if present")
    p.add_argument("--pseudo_label", action="store_true", help="Use pseudo-labels from current model if labels are missing or to force pseudo-labeling")
    p.add_argument("--threshold", type=float, default=0.5, help="Threshold to create pseudo-labels (if --pseudo_label or labels missing)")
    p.add_argument("--pseudo_topk", type=float, default=0.0, help="If no positives at --threshold, label top-k percent as positive (e.g., 1.0 = top 1%). 0 disables.")

    args = p.parse_args()

    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)

    ensure_outdir(args.outdir)

    # 1) Load base model
    print(f"[INFO] Loading model: {args.model}")
    model = tf.keras.models.load_model(args.model)

    # Set learning rate if possible
    try:
        tf.keras.backend.set_value(model.optimizer.lr, args.lr)
    except Exception:
        try:
            tf.keras.backend.set_value(model.optimizer.learning_rate, args.lr)
        except Exception:
            print("[WARN] Could not set model LR; continuing with existing LR")

    # 2) Load new CSV batch
    print(f"[INFO] Loading batch: {args.finetune_csv}")
    df = pd.read_csv(args.finetune_csv)
    df = normalize_columns(df)

    has_label = (args.label_col in df.columns) and (not args.pseudo_label)

    # 3) Build features
    if has_label:
        X_all, y_all, num_names, cat_names = build_features_zeekmin(df)
        print(f"[INFO] Supervised fine-tune with {len(y_all)} labeled rows.")
    else:
        print("[INFO] Pseudo-label mode: generating labels from current model predictions.")
        if args.label_col not in df.columns:
            df[args.label_col] = 0  # dummy to satisfy builder
        X_all, _y_dummy, num_names, cat_names = build_features_zeekmin(df)
        inputs = make_inputs(X_all)
        # speed up prediction with large batch
        scores = model.predict(inputs, batch_size=args.batch, verbose=0).ravel()
        y_all = (scores >= args.threshold).astype(int)
        pos = int(y_all.sum())
        print(f"[INFO] Pseudo labels created with threshold={args.threshold:.3f} → pos={pos} / {len(y_all)}")
        if pos == 0 and args.pseudo_topk > 0:
            k = max(int(len(scores) * (args.pseudo_topk / 100.0)), 1)
            thr_topk = np.partition(scores, -k)[-k]
            y_all = (scores >= thr_topk).astype(int)
            print(f"[INFO] No positives at threshold; using top-{args.pseudo_topk}% rule (thr≈{thr_topk:.6f}) → pos={int(y_all.sum())}")
        elif pos == 0:
            auto_thr = max(args.threshold * 0.5, 0.2)
            y_all = (scores >= auto_thr).astype(int)
            print(f"[INFO] No positives at threshold; fallback to {auto_thr:.3f} → pos={int(y_all.sum())}")

    # 4) Train/Val split on the new batch
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

    # Ensure y is pandas Series for to_dataset
    y_tr = pd.Series(y_tr)
    y_va = pd.Series(y_va)

    ds_tr = to_dataset(X_tr[cols], y_tr, batch=args.batch, shuffle=True)
    ds_va = to_dataset(X_va[cols], y_va, batch=args.batch, shuffle=False)

    # 5) Fine-tune
    callbacks = [
        tf.keras.callbacks.EarlyStopping(monitor="val_binary_accuracy", mode="max", patience=3, restore_best_weights=True),
        tf.keras.callbacks.ReduceLROnPlateau(monitor="val_binary_accuracy", mode="max", patience=2, factor=0.5, min_lr=1e-6),
        tf.keras.callbacks.ModelCheckpoint(filepath=str(Path(args.outdir)/"checkpoint.keras"), monitor="val_binary_accuracy", mode="max", save_best_only=True)
    ]

    print("[INFO] Starting fine-tune...")
    model.fit(ds_tr, validation_data=ds_va, epochs=args.epochs, verbose=2, callbacks=callbacks)

    # 6) Evaluate on the (held-out) val split and tune threshold
    tuned_thr, _scores = evaluate_and_save(model, X_va[cols], y_va.values, args.outdir, tag="val")

    # 7) Save updated model
    out_model = Path(args.outdir) / "model.keras"
    model.save(out_model)
    print(f"[OK] Saved updated model to: {out_model}")


if __name__ == "__main__":
    main()
