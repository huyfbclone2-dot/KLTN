#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zeek-min DL for CIC-IDS 2017 (4-class)
Classes:
    0: benign
    1: dos            (DoS Hulk, DoS GoldenEye, Slowloris, Slowhttptest, DDoS, ...)
    2: portscan
    3: ftp_bruteforce (FTP-Patator)

Các nhãn KHÁC (web attack, ssh-patator, bot, infiltration, heartbleed, ...)
sẽ bị BỎ QUA (không dùng để train).
"""

import os, json, argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
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
        if k in norm: 
            return norm[k]
    return None


def map_proto_number_to_str(v):
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("tcp","udp","icmp"): 
            return s
        try:
            v = int(float(s))
        except:
            return "other"
    if isinstance(v, (int,float,np.integer,np.floating)):
        n = int(v)
        if n == 6:
            return "tcp"
        if n == 17:
            return "udp"
        if n == 1:
            return "icmp"
        return "other"
    return "other"


# ----------------- 4-class labels -----------------
# 0: benign, 1: dos, 2: portscan, 3: ftp_bruteforce
CLASS_NAMES = ["benign", "dos", "portscan", "ftp_bruteforce"]


# 0: benign, 1: dos, 2: portscan, 3: ftp_bruteforce
CLASS_NAMES = ["benign", "dos", "portscan", "ftp_bruteforce"]

def make_multiclass_labels(series: pd.Series) -> pd.Series:
    """
    Hỗ trợ 2 kiểu nhãn:
      - Số: 0,1,2,3  (bạn tự gắn)
      - Text CICIDS: 'Benign', 'DoS Hulk', 'DDoS', 'PortScan', 'FTP-Patator', ...
      - Text tự đặt: 'dos', 'ddos', 'portscan', 'ftp_bruteforce', ...
    """

    # 1) Nếu là số 0..3 thì dùng luôn
    s_raw = series.copy()
    s_num = pd.to_numeric(s_raw, errors="coerce")
    uniq = set(s_num.dropna().unique().tolist())
    if len(uniq) > 0 and uniq.issubset({0, 1, 2, 3}):
        return s_num.fillna(0).astype(int)

    # 2) Nếu là text thì map
    s = s_raw.astype(str).str.strip().str.lower()

    def map_one(v: str) -> int:
        # benign
        if v in {"benign", "normal", "0"}:
            return 0
        # cho trường hợp bạn ghi thẳng "benign" / "dos" / "portscan" / "ftp_bruteforce"
        if v == "dos":
            return 1
        if v in {"portscan", "port_scan"}:
            return 2
        if v in {"ftp_bruteforce", "ftp-bruteforce", "ftp brute force"}:
            return 3

        # pattern CIC-IDS gốc
        if "portscan" in v:
            return 2
        if "ftp-patator" in v or ("ftp" in v and "brute" in v):
            return 3
        if v.startswith("dos") or "ddos" in v or \
           "hulk" in v or "goldeneye" in v or \
           "slowloris" in v or "slowhttptest" in v:
            return 1

        # nhãn khác -> bỏ
        return -1

    y = s.map(map_one).astype(int)
    return y


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
    if p <= 1023: 
        return "p_well_known"
    if p <= 49151: 
        return "p_registered"
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
    if med > 1e5:
        denom = 1_000_000.0
    elif med > 1e2:
        denom = 1_000.0
    else:
        denom = 1.0
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

    # Labels (multi-class 4 lớp)
    y = make_multiclass_labels(df[label_col])

    # Lọc bỏ các nhãn = -1 (loại khác 3 attack + benign)
    mask = y != -1
    dropped = int((~mask).sum())
    if dropped > 0:
        print(f"[build_features] Bỏ {dropped} dòng với nhãn không thuộc {{benign, dos, portscan, ftp_bruteforce}}.")
    X = X.loc[mask].reset_index(drop=True)
    y = y.loc[mask].reset_index(drop=True)

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
               num_classes,
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
        lookup = layers.StringLookup(
            vocabulary=vocabularies[c],
            mask_token=None,
            num_oov_indices=1,
            name=f"{c}_lookup"
        )
        ids = lookup(inputs[c])
        emb_dim = 6 if c=="proto" else 4
        emb = layers.Embedding(
            input_dim=len(vocabularies[c]) + 1,
            output_dim=emb_dim,
            name=f"{c}_emb"
        )(ids)
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
    out = layers.Dense(num_classes, activation="softmax", name="prob")(x)

    model = models.Model(inputs=inputs, outputs=out)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(1e-3),
        loss=tf.keras.losses.SparseCategoricalCrossentropy(),
        metrics=[tf.keras.metrics.SparseCategoricalAccuracy(name="accuracy")]
    )
    return model


# ----------------- Plot helpers -----------------
def plot_history(history, outdir):
    hist = history.history
    plt.figure()
    plt.plot(hist.get("loss", []))
    plt.plot(hist.get("val_loss", []))
    plt.xlabel("Epoch"); plt.ylabel("Loss"); plt.title("Train vs Val Loss")
    plt.legend(["Train","Val"]); plt.tight_layout()
    plt.savefig(os.path.join(outdir,"train_val_loss.png"))
    plt.close()


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

    # LOAD train
    df_tr = pd.read_csv(args.train_csv)
    df_tr = normalize_columns(df_tr)
    X_all, y_all, numeric_names, categorical_names = build_features_zeekmin(df_tr)

    print("Label counts (train+val) sau khi lọc:")
    print(pd.Series(y_all).value_counts().sort_index())
    print("Mapping lớp:", {i: n for i,n in enumerate(CLASS_NAMES)})

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
    )

    # LOAD test (optional)
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

    # DATASETS
    cols = numeric_names + categorical_names
    ds_tr_fit  = to_dataset(X_tr[cols],  y_tr,  args.batch, shuffle=True)
    ds_tr_eval = to_dataset(X_tr[cols],  y_tr,  args.batch, shuffle=False)
    ds_val     = to_dataset(X_val[cols], y_val, args.batch, shuffle=False)
    ds_te = None
    if X_te is not None:
        ds_te = to_dataset(X_te[cols], y_te, args.batch, shuffle=False)

    # model
    num_classes = 4  # cố định theo CLASS_NAMES
    model = make_model(
        numeric_names, categorical_names, vocabs, stats,
        num_classes=num_classes,
        width=384, depth=5, dropout=0.25
    )

    # fit
    cbs = [
        callbacks.EarlyStopping(
            monitor="val_accuracy", mode="max",
            patience=5, min_delta=1e-4, restore_best_weights=True
        ),
        callbacks.ReduceLROnPlateau(
            monitor="val_accuracy", mode="max",
            patience=2, factor=0.5, min_lr=1e-5, verbose=1
        ),
        callbacks.ModelCheckpoint(
            os.path.join(args.outdir, "best.keras"),
            monitor="val_accuracy", mode="max",
            save_best_only=True
        )
    ]
    history = model.fit(
        ds_tr_fit, validation_data=ds_val,
        epochs=args.epochs, verbose=2, callbacks=cbs
    )

    plot_history(history, args.outdir)

    # --------- EVAL MULTI-CLASS ---------
    y_tr_prob = model.predict(ds_tr_eval, verbose=0)
    y_val_prob = model.predict(ds_val, verbose=0)

    y_tr_pred = np.argmax(y_tr_prob, axis=1)
    y_val_pred = np.argmax(y_val_prob, axis=1)

    train_acc = accuracy_score(y_tr, y_tr_pred)
    val_acc   = accuracy_score(y_val, y_val_pred)

    print("TRAIN acc:", train_acc)
    print("VAL   acc:", val_acc)

    # save reports (VAL)
    with open(os.path.join(args.outdir,"classification_report_val.txt"), "w") as f:
        f.write(classification_report(
            y_val, y_val_pred,
            digits=4,
            target_names=CLASS_NAMES
        ))

    np.savetxt(
        os.path.join(args.outdir,"confusion_matrix_val.csv"),
        confusion_matrix(y_val, y_val_pred, labels=list(range(len(CLASS_NAMES)))),
        fmt="%d", delimiter=","
    )

    # TEST (nếu có)
    test_acc = None
    if ds_te is not None:
        y_te_prob = model.predict(ds_te, verbose=0)
        y_te_pred = np.argmax(y_te_prob, axis=1)

        test_acc = accuracy_score(y_te, y_te_pred)
        print("TEST  acc:", test_acc)

        with open(os.path.join(args.outdir,"classification_report_test.txt"), "w") as f:
            f.write(classification_report(
                y_te, y_te_pred,
                digits=4,
                target_names=CLASS_NAMES
            ))

        np.savetxt(
            os.path.join(args.outdir,"confusion_matrix_test.csv"),
            confusion_matrix(y_te, y_te_pred, labels=list(range(len(CLASS_NAMES)))),
            fmt="%d", delimiter=","
        )

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
            "class_names": CLASS_NAMES,
            "train_acc": float(train_acc),
            "val_acc": float(val_acc),
            "test_acc": None if test_acc is None else float(test_acc),
        }, f, indent=2)

    print("== Accuracies ==")
    print(f"TRAIN acc: {train_acc:.4f}")
    print(f"VAL   acc: {val_acc:.4f}")
    if test_acc is not None:
        print(f"TEST  acc: {test_acc:.4f}")
    print("Artifacts in:", args.outdir)


if __name__ == "__main__":
    main()
