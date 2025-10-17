#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zeek-min DL for high ACC (realtime-compatible)
- Chỉ dùng field có trong Zeek conn.log (+ features dẫn xuất an toàn)
- Kỹ thuật đặc trưng: totals, ratios, log1p, port bucket + embedding
- Huấn luyện vì ACC: thêm binary_accuracy, EarlyStopping theo val_binary_accuracy
- Tuning ngưỡng kiểu maximin (TRAIN & VAL) với lưới quantile (nhanh)
- Fix: tách dataset TRAIN cho fit (shuffle=True) và eval (shuffle=False) để predict khớp thứ tự

Artifacts:
  train_val_loss.png, train_val_auc.png
  classification_report(_val)(_tuned).txt
  confusion_matrix(_val)(_tuned).csv
  metrics.json, metrics_threshold.json
  model.keras, saved_model/
"""

import os, json, argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    roc_curve, auc, precision_recall_curve, average_precision_score
)

import tensorflow as tf
from tensorflow.keras import layers, models, callbacks


# ----------------- Utils & Aliases -----------------
def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    new_cols = []
    for c in df.columns:
        c2 = str(c).replace(" ", "").replace("/", "").replace("-", "").replace(".", "")
        c2 = c2.replace("\\ufeff", "")
        new_cols.append(c2)
    df.columns = new_cols
    return df

ALIASES = {
    "SourcePort": [
        "SourcePort","Source Port","SrcPort","Src Port","Sport","src_port","id.orig_p","idorig_p","srcport"
    ],
    "DestinationPort": [
        "DestinationPort","Destination Port","DstPort","Dst Port","Dport","dest_port","id.resp_p","idresp_p","dstport"
    ],
    "Protocol": ["Protocol","Proto","protocol","proto","L4Protocol","ProtocolName"],
    "FlowDuration": ["FlowDuration","Flow Duration","Flow_Duration","FlowDurationusec","FlowDurationus"],
    "TotalLengthofFwdPackets": [
        "TotalLengthofFwdPackets","Total Length of Fwd Packets","TotLenFwdPkts","Fwd_Packet_Length_Total","FwdPacketLengthTotal"
    ],
    "TotalLengthofBwdPackets": [
        "TotalLengthofBwdPackets","Total Length of Bwd Packets","TotLenBwdPkts","Bwd_Packet_Length_Total","BwdPacketLengthTotal"
    ],
    "TotalFwdPackets": ["TotalFwdPackets","Total Fwd Packets","FwdPackets","Fwd_Packets_Tot","TotalFwdPkt"],
    "TotalBackwardPackets": ["TotalBackwardPackets","Total Bwd Packets","BwdPackets","Bwd_Packets_Tot","TotalBwdPkt"],
    "Label": ["Label","Class","Attack","label","class","attack"],
}

def pick_col(df: pd.DataFrame, candidates):
    norm = {c.lower().replace(" ","").replace("/","").replace("-","").replace(".",""): c for c in df.columns}
    for name in candidates:
        k = name.lower().replace(" ","").replace("/","").replace("-","").replace(".","")
        if k in norm: return norm[k]
    return None

def map_proto_number_to_str(v):
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("tcp","udp","icmp"): return s
        try: v = int(float(s))
        except: return "other"
    if isinstance(v, (int,float,np.integer,np.floating)):
        n = int(v)
        return "tcp" if n==6 else "udp" if n==17 else "icmp" if n==1 else "other"
    return "other"

def make_binary_labels(series: pd.Series) -> pd.Series:
    s = series.copy()
    s_num = pd.to_numeric(s, errors="coerce")
    uniq = set(s_num.dropna().unique().tolist())
    if len(uniq)>0 and uniq.issubset({0,1}):
        return s_num.fillna(0).astype(int).clip(0,1)
    s_str = s.astype(str).str.strip().str.lower()
    benign = {"benign","normal","0"}
    if len(set(s_str.unique()) & benign)>0:
        return (~s_str.isin(benign)).astype(int)
    pos_tok = {"1","attack","ddos","dos","portscan","bot","infiltration","ftp-patator","ssh-patator",
               "web attack - brute force","web attack - xss","web attack - sql injection","heartbleed"}
    return s_str.isin(pos_tok).astype(int)


# -------------- Feature engineering (ZEEK-MIN LOCKED) --------------
ZEEK_MIN_NUM = [
    "id.resp_p",  # dest port
    "duration",
    "orig_bytes","resp_bytes",
    "orig_pkts","resp_pkts",
    # engineered:
    "total_bytes","total_pkts",
    "byte_ratio","pkt_ratio",
    "bytes_per_pkt","pkts_per_sec","bytes_per_sec",
    # log1p:
    "log_total_bytes","log_total_pkts",
    "log_bytes_per_pkt","log_pkts_per_sec","log_bytes_per_sec",
]
ZEEK_MIN_CAT = ["proto","resp_port_bucket"]

def port_bucket(p):
    try:
        p = int(p)
    except:
        return "p_unk"
    if p <= 1023: return "p_well_known"
    if p <= 49151: return "p_registered"
    return "p_dynamic"

def build_features_zeekmin(df: pd.DataFrame):
    have = {k: pick_col(df, ALIASES[k]) for k in ALIASES}
    label_col = have["Label"]
    if label_col is None:
        raise ValueError("Không tìm thấy cột label; thử: %s" % ALIASES["Label"])

    req = {
        "DestinationPort": have["DestinationPort"],
        "FlowDuration": have["FlowDuration"],
        "TotalLengthofFwdPackets": have["TotalLengthofFwdPackets"],
        "TotalLengthofBwdPackets": have["TotalLengthofBwdPackets"],
        "TotalFwdPackets": have["TotalFwdPackets"],
        "TotalBackwardPackets": have["TotalBackwardPackets"],
    }
    miss = [k for k,v in req.items() if v is None]
    if miss:
        raise ValueError(f"Thiếu cột bắt buộc: {miss}. Columns: {list(df.columns)[:30]}")

    out = {}

    # dest port
    out["id.resp_p"] = pd.to_numeric(df[have["DestinationPort"]], errors="coerce").fillna(0).astype(int)

    # proto optional
    if have["Protocol"] is not None:
        out["proto"] = df[have["Protocol"]].apply(map_proto_number_to_str)
    else:
        out["proto"] = "other"

    # duration → auto-scale to seconds
    dur_raw = pd.to_numeric(df[have["FlowDuration"]], errors="coerce").fillna(0).astype(float)
    med = float(np.nanmedian(dur_raw))
    denom = 1_000_000.0 if med>1e5 else 1_000.0 if med>1e2 else 1.0
    out["duration"] = dur_raw/denom

    # bytes/pkts
    out["orig_bytes"] = pd.to_numeric(df[have["TotalLengthofFwdPackets"]], errors="coerce").fillna(0).astype(float)
    out["resp_bytes"] = pd.to_numeric(df[have["TotalLengthofBwdPackets"]], errors="coerce").fillna(0).astype(float)
    out["orig_pkts"]  = pd.to_numeric(df[have["TotalFwdPackets"]], errors="coerce").fillna(0).astype(float)
    out["resp_pkts"]  = pd.to_numeric(df[have["TotalBackwardPackets"]], errors="coerce").fillna(0).astype(float)

    X = pd.DataFrame(out)

    # engineered realtime-safe
    X["total_bytes"] = X["orig_bytes"] + X["resp_bytes"]
    X["total_pkts"]  = X["orig_pkts"]  + X["resp_pkts"]

    X["byte_ratio"] = X["orig_bytes"] / np.clip(X["resp_bytes"], 1.0, None)
    X["pkt_ratio"]  = X["orig_pkts"]  / np.clip(X["resp_pkts"], 1.0, None)

    X["bytes_per_pkt"] = X["total_bytes"] / np.clip(X["total_pkts"], 1.0, None)
    X["pkts_per_sec"]  = X["total_pkts"]  / np.clip(X["duration"], 1e-6, None)
    X["bytes_per_sec"] = X["total_bytes"] / np.clip(X["duration"], 1e-6, None)

    # log1p
    for c in ["total_bytes","total_pkts","bytes_per_pkt","pkts_per_sec","bytes_per_sec"]:
        X[f"log_{c}"] = np.log1p(np.clip(X[c], 0, None))

    # resp_port_bucket (categorical)
    X["resp_port_bucket"] = pd.Series([port_bucket(p) for p in X["id.resp_p"]], index=X.index)

    # Labels
    y = make_binary_labels(df[label_col])

    numeric_names = ZEEK_MIN_NUM
    categorical_names = [c for c in ZEEK_MIN_CAT if c in X.columns]
    for c in numeric_names:
        if c not in X.columns:
            X[c] = 0.0
    X = X[numeric_names + categorical_names].replace([np.inf,-np.inf], np.nan).fillna(0)

    return X, y, numeric_names, categorical_names


# ----------------- TF Dataset & Model -----------------
def to_dataset(dfX: pd.DataFrame, y: pd.Series, batch: int, shuffle: bool):
    d = {k: dfX[k].values for k in dfX.columns}
    ds = tf.data.Dataset.from_tensor_slices((d, y.values.astype(np.int32)))
    if shuffle:
        ds = ds.shuffle(min(len(dfX), 100_000), reshuffle_each_iteration=True)
    return ds.batch(batch).prefetch(tf.data.AUTOTUNE)

def make_model(numeric_names, categorical_names, vocabularies, stats,
               width=384, depth=5, dropout=0.25):
    inputs, parts = {}, []

    # numeric
    if numeric_names:
        for n in numeric_names:
            inputs[n] = layers.Input(name=n, shape=(1,), dtype=tf.float32)
        means = [stats["means"][n] for n in numeric_names]
        vars_ = [stats["vars"][n] for n in numeric_names]
        num_stack = layers.Concatenate(name="num_stack")([inputs[n] for n in numeric_names])
        norm = layers.Normalization(axis=-1, mean=means, variance=vars_, name="num_norm")
        parts.append(norm(num_stack))

    # categorical
    for c in categorical_names:
        inputs[c] = layers.Input(name=c, shape=(), dtype=tf.string)
        lookup = layers.StringLookup(vocabulary=vocabularies[c], mask_token=None, num_oov_indices=1, name=f"{c}_lookup")
        ids = lookup(inputs[c])
        emb_dim = 6 if c=="proto" else 4
        emb = layers.Embedding(input_dim=len(vocabularies[c]) + 1, output_dim=emb_dim, name=f"{c}_emb")(ids)
        parts.append(emb)

    x = parts[0] if len(parts)==1 else layers.Concatenate(name="concat")(parts)

    # wide/deep residual MLP
    for _ in range(depth):
        h = layers.Dense(width, kernel_initializer="he_normal")(x)
        h = layers.BatchNormalization()(h)
        h = layers.Activation("relu")(h)
        h = layers.Dropout(dropout)(h)
        h = layers.Dense(width//2, activation="relu")(h)
        if x.shape[-1] != h.shape[-1]:
            x = layers.Dense(int(h.shape[-1]))(x)
        x = layers.Add()([x, h])

    x = layers.Dense(96, activation="relu")(x)
    out = layers.Dense(1, activation="sigmoid", name="prob")(x)

    model = models.Model(inputs=inputs, outputs=out)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(1e-3),
        loss=tf.keras.losses.BinaryCrossentropy(),
        metrics=[tf.keras.metrics.BinaryAccuracy(name="binary_accuracy"),
                 tf.keras.metrics.AUC(name="auc")]
    )
    return model


# ----------------- Plot helpers -----------------
def plot_history(history, outdir):
    hist = history.history
    plt.figure(); plt.plot(hist.get("loss", [])); plt.plot(hist.get("val_loss", []))
    plt.xlabel("Epoch"); plt.ylabel("Loss"); plt.title("Train vs Val Loss")
    plt.legend(["Train","Val"]); plt.tight_layout()
    plt.savefig(os.path.join(outdir,"train_val_loss.png")); plt.close()

    if "auc" in hist and "val_auc" in hist:
        plt.figure(); plt.plot(hist["auc"]); plt.plot(hist["val_auc"])
        plt.xlabel("Epoch"); plt.ylabel("AUC"); plt.title("Train vs Val AUC")
        plt.legend(["Train","Val"]); plt.tight_layout()
        plt.savefig(os.path.join(outdir,"train_val_auc.png")); plt.close()

def safe_curves(y_true, y_score, outdir, prefix=""):
    uniq = set(np.asarray(y_true).tolist())
    if len(uniq) < 2: return None, None
    fpr,tpr,_ = roc_curve(y_true, y_score); roc_auc = auc(fpr,tpr)
    plt.figure(); plt.plot(fpr,tpr); plt.plot([0,1],[0,1],"--"); plt.xlabel("FPR"); plt.ylabel("TPR")
    plt.title(f"ROC (AUC={roc_auc:.4f})"); plt.tight_layout()
    plt.savefig(os.path.join(outdir, f"{prefix}roc_curve.png")); plt.close()
    pr, rc, _ = precision_recall_curve(y_true, y_score); ap = average_precision_score(y_true, y_score)
    plt.figure(); plt.plot(rc,pr); plt.xlabel("Recall"); plt.ylabel("Precision")
    plt.title(f"PR (AP={ap:.4f})"); plt.tight_layout()
    plt.savefig(os.path.join(outdir, f"{prefix}pr_curve.png")); plt.close()
    return float(roc_auc), float(ap)


# ----------------- Threshold (maximin, quantile grid) -----------------
def sweep_thresholds_from(scores, max_points=1024):
    qs = np.linspace(0.0, 1.0, num=max_points)
    thr = np.unique(np.quantile(scores, qs))
    return np.r_[thr[0]-1e-12, (thr[:-1]+thr[1:])/2.0, thr[-1]+1e-12]

def maximin_threshold(y_tr, s_tr, y_va, s_va, max_points=1024):
    thr = np.unique(np.r_[sweep_thresholds_from(s_tr, max_points),
                          sweep_thresholds_from(s_va, max_points)])
    best = None
    for t in thr:
        acc_tr = accuracy_score(y_tr, (s_tr>=t).astype(int))
        acc_va = accuracy_score(y_va, (s_va>=t).astype(int))
        score  = min(acc_tr, acc_va)
        tie    = (acc_tr + acc_va)/2.0
        cand   = (score, tie, float(t), acc_tr, acc_va)
        if best is None or cand > best:
            best = cand
    return best[2], best[3], best[4]


# ----------------- Main -----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train_csv", required=True)
    ap.add_argument("--test_csv", required=False)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--batch", type=int, default=4096)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    # LOAD
    df_tr = pd.read_csv(args.train_csv)
    df_tr = normalize_columns(df_tr)
    X_all, y_all, numeric_names, categorical_names = build_features_zeekmin(df_tr)

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
    )

    X_te = y_te = None
    if args.test_csv:
        df_te = pd.read_csv(args.test_csv)
        df_te = normalize_columns(df_te)
        X_te, y_te, _, _ = build_features_zeekmin(df_te)

    # stats + vocabs
    stats = {"means":{}, "vars":{}}
    for n in numeric_names:
        v = X_tr[n].astype(np.float32).values
        stats["means"][n] = float(v.mean())
        var = float(v.var())
        stats["vars"][n] = var if var>0 else 1.0
    vocabs = {}
    for c in categorical_names:
        vocabs[c] = sorted(list(pd.Index(X_tr[c].astype(str).unique()).astype(str)))

    # === DATASETS (FIX: tách fit/eval) ===
    cols = numeric_names + categorical_names
    ds_tr_fit  = to_dataset(X_tr[cols],  y_tr,  args.batch, shuffle=True)   # dùng để huấn luyện
    ds_tr_eval = to_dataset(X_tr[cols],  y_tr,  args.batch, shuffle=False)  # dùng để predict/eval (không shuffle)
    ds_val     = to_dataset(X_val[cols], y_val, args.batch, shuffle=False)
    ds_te = None
    if X_te is not None:
        ds_te = to_dataset(X_te[cols], y_te, args.batch, shuffle=False)

    # model
    model = make_model(numeric_names, categorical_names, vocabs, stats,
                       width=384, depth=5, dropout=0.25)

    # fit (KHÔNG dùng class_weight để tối ưu ACC)
    cbs = [
        callbacks.EarlyStopping(monitor="val_binary_accuracy", mode="max",
                                patience=5, min_delta=1e-4, restore_best_weights=True),
        callbacks.ReduceLROnPlateau(monitor="val_binary_accuracy", mode="max",
                                    patience=2, factor=0.5, min_lr=1e-5, verbose=1),
        callbacks.ModelCheckpoint(os.path.join(args.outdir, "best.keras"),
                                  monitor="val_binary_accuracy", mode="max",
                                  save_best_only=True)
    ]
    history = model.fit(ds_tr_fit, validation_data=ds_val,
                        epochs=args.epochs, verbose=2, callbacks=cbs)

    plot_history(history, args.outdir)

    # scores (DÙNG ds_tr_eval để giữ thứ tự)
    y_tr_score  = model.predict(ds_tr_eval, verbose=0).ravel()
    y_val_score = model.predict(ds_val,     verbose=0).ravel()

    # sanity check
    print("ACC@0.5 TRAIN:", accuracy_score(y_tr,  (y_tr_score >= 0.5).astype(int)))
    print("ACC@0.5 VAL  :", accuracy_score(y_val, (y_val_score >= 0.5).astype(int)))

    # threshold maximin (nhanh)
    try:
        thr_final, tr_acc, va_acc = maximin_threshold(y_tr, y_tr_score, y_val, y_val_score, max_points=1024)
    except KeyboardInterrupt:
        # fallback: dùng VAL-opt nếu bị Ctrl+C
        qs = np.linspace(0.0, 1.0, num=1024)
        thr_grid = np.unique(np.quantile(y_val_score, qs))
        accs = [accuracy_score(y_val, (y_val_score>=t).astype(int)) for t in thr_grid]
        thr_final = float(thr_grid[int(np.argmax(accs))])
        tr_acc = accuracy_score(y_tr,  (y_tr_score >= thr_final).astype(int))
        va_acc = accuracy_score(y_val, (y_val_score >= thr_final).astype(int))
    print(f"[Maximin] thr={thr_final:.6f}  TRAIN acc={tr_acc:.4f}  VAL acc={va_acc:.4f}")

    # save reports (VAL @ tuned)
    y_val_pred_tuned = (y_val_score>=thr_final).astype(int)
    with open(os.path.join(args.outdir,"classification_report_val.txt"), "w") as f:
        f.write(classification_report(y_val, (y_val_score>=0.5).astype(int), digits=4))
    with open(os.path.join(args.outdir,"classification_report_val_tuned.txt"), "w") as f:
        f.write(classification_report(y_val, y_val_pred_tuned, digits=4))
    np.savetxt(os.path.join(args.outdir,"confusion_matrix_val.csv"),
               confusion_matrix(y_val, (y_val_score>=0.5).astype(int), labels=[0,1]), fmt="%d", delimiter=",")
    np.savetxt(os.path.join(args.outdir,"confusion_matrix_val_tuned.csv"),
               confusion_matrix(y_val, y_val_pred_tuned, labels=[0,1]), fmt="%d", delimiter=",")

    roc_auc_val, ap_val = safe_curves(y_val, y_val_score, args.outdir, prefix="val_")

    # TEST
    test_acc_tuned = None; roc_auc_te = ap_te = None
    if ds_te is not None:
        y_te_score = model.predict(ds_te, verbose=0).ravel()
        y_te_pred_tuned = (y_te_score>=thr_final).astype(int)
        test_acc_tuned = accuracy_score(y_te, y_te_pred_tuned)

        with open(os.path.join(args.outdir,"classification_report.txt"), "w") as f:
            f.write(classification_report(y_te, (y_te_score>=0.5).astype(int), digits=4))
        with open(os.path.join(args.outdir,"classification_report_tuned.txt"), "w") as f:
            f.write(classification_report(y_te, y_te_pred_tuned, digits=4))

        np.savetxt(os.path.join(args.outdir,"confusion_matrix.csv"),
                   confusion_matrix(y_te, (y_te_score>=0.5).astype(int), labels=[0,1]),
                   fmt="%d", delimiter=",")
        np.savetxt(os.path.join(args.outdir,"confusion_matrix_tuned.csv"),
                   confusion_matrix(y_te, y_te_pred_tuned, labels=[0,1]),
                   fmt="%d", delimiter=",")
        roc_auc_te, ap_te = safe_curves(y_te, y_te_score, args.outdir, prefix="")

    # save model
    model.save(os.path.join(args.outdir,"model.keras"))
    try:
        model.export(os.path.join(args.outdir,"saved_model"))
    except Exception as e:
        print("SavedModel export skipped:", e)

    # metrics
    with open(os.path.join(args.outdir,"metrics.json"),"w") as f:
        json.dump({
            "numeric_names": numeric_names,
            "categorical_names": categorical_names,
            "val_roc_auc": None if roc_auc_val is None else float(roc_auc_val),
            "val_ap": None if ap_val is None else float(ap_val),
            "test_roc_auc": None if roc_auc_te is None else float(roc_auc_te),
            "test_ap": None if ap_te is None else float(ap_te),
        }, f, indent=2)

    with open(os.path.join(args.outdir,"metrics_threshold.json"),"w") as f:
        json.dump({
            "threshold_final": float(thr_final),
            "train_acc_tuned": float(tr_acc),
            "val_acc_tuned": float(va_acc),
            "test_acc_tuned": None if test_acc_tuned is None else float(test_acc_tuned),
        }, f, indent=2)

    print("== Tuned accuracies ==")
    print(f"TRAIN acc: {tr_acc:.4f}")
    print(f"VAL   acc: {va_acc:.4f}")
    if test_acc_tuned is not None:
        print(f"TEST  acc: {test_acc_tuned:.4f}")
    print("Artifacts in:", args.outdir)


if __name__ == "__main__":
    main()
