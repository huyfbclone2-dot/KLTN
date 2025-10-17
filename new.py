#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zeek conn.log realtime scorer (Keras multi-input, JSON/TSV auto-detect).
- Hỗ trợ tf.string cho 'proto'
- Input theo dict {input_name: tf.Tensor} để tránh lỗi optree
"""

import argparse, json, os, time
from typing import Dict, List, Optional
import numpy as np

# Ép CPU & giảm log TF (CUDA warnings có thể vẫn in, nhưng vô hại)
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

# ---------- Aliases ----------
ZEEK_ALIASES = {
    "id.resp_p": ["id.resp_p", "resp_p", "dst_port", "destination_port", "dest_port", "dport"],
    "duration": ["duration", "flowduration", "flow_duration", "dur", "DURATION"],
    "orig_bytes": ["orig_bytes", "orig_ip_bytes", "totlen_fwd", "TotalLengthofFwdPackets", "fwd_bytes"],
    "resp_bytes": ["resp_bytes", "resp_ip_bytes", "totlen_bwd", "TotalLengthofBwdPackets", "bwd_bytes"],
    "orig_pkts":  ["orig_pkts",  "tot_fwd_pkts", "TotalFwdPackets", "fwd_pkts"],
    "resp_pkts":  ["resp_pkts",  "tot_bwd_pkts", "TotalBackwardPackets", "bwd_pkts"],
    "proto":      ["proto", "Protocol", "protocol"],  # optional
}
REQ_BASE = ["id.resp_p","duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts"]
OPT_BASE = ["proto"]

def _find_name(cols: Dict[str,int], aliases: List[str]) -> Optional[str]:
    for a in aliases:
        if a in cols: return a
    return None

def _parse_float(x):
    try:
        if x in ("-", "", None): return np.nan
        return float(x)
    except Exception:
        return np.nan

def bucket_port(p: float) -> int:
    if np.isnan(p): return 0
    p = int(p)
    if p < 1024: return 1
    if p < 49152: return 2
    return 3

def norm_proto(s: str) -> str:
    if not s or s == "-": return "other"
    s = str(s).lower()
    if "tcp" in s: return "tcp"
    if "udp" in s: return "udp"
    if "icmp" in s: return "icmp"
    return "other"

def build_colmap(field_names: List[str]) -> Dict[str,str]:
    cols = {name: i for i, name in enumerate(field_names)}
    colmap = {}
    for key, alias in ZEEK_ALIASES.items():
        name = _find_name(cols, alias)
        if key in OPT_BASE:
            if name: colmap[key] = name
        else:
            if not name:
                raise ValueError(f"Missing required field for {key}. Aliases: {alias}")
            colmap[key] = name
    return colmap

# ---------- Zeek reader: JSON/TSV ----------
def zeek_stream_rows(path: str):
    """Tail -F Zeek conn.log. Tự nhận JSON (NDJSON) hoặc TSV (#fields...)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        fields = None
        mode = None  # "json" | "tsv"
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25); continue
            line = line.rstrip("\n")
            if not line:
                continue

            if mode is None and line[:1] == "{":
                mode = "json"
            if mode == "json":
                if line[:1] != "{":
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
                continue

            # TSV
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    mode = "tsv"
                continue
            if fields is None:
                continue
            parts = line.split("\t")
            if len(parts) < len(fields):
                parts += [""] * (len(fields) - len(parts))
            yield {fields[i]: parts[i] for i in range(len(fields))}

# ---------- Feature engineering: đúng tên 20 input ----------
def features_from_row(row: Dict[str,str], colmap: Dict[str,str]) -> Dict[str, float]:
    resp_p = _parse_float(row.get(colmap["id.resp_p"], np.nan))
    duration = _parse_float(row.get(colmap["duration"], np.nan))
    o_b = _parse_float(row.get(colmap["orig_bytes"], np.nan))
    r_b = _parse_float(row.get(colmap["resp_bytes"], np.nan))
    o_p = _parse_float(row.get(colmap["orig_pkts"], np.nan))
    r_p = _parse_float(row.get(colmap["resp_pkts"], np.nan))
    proto = norm_proto(row.get(colmap["proto"], "other")) if colmap.get("proto") else "other"

    # chuẩn hoá duration về giây nếu cần
    if not np.isnan(duration) and duration > 0:
        if duration > 1e6:      # us -> s
            duration = duration / 1e6
        elif 1e3 < duration < 2e6:  # ms -> s
            duration = duration / 1e3

    total_bytes = (o_b if not np.isnan(o_b) else 0.0) + (r_b if not np.isnan(r_b) else 0.0)
    total_pkts  = (o_p if not np.isnan(o_p) else 0.0) + (r_p if not np.isnan(r_p) else 0.0)
    byte_ratio  = (o_b / (r_b + 1e-6)) if (not np.isnan(o_b) and not np.isnan(r_b)) else np.nan
    pkt_ratio   = (o_p / (r_p + 1e-6)) if (not np.isnan(o_p) and not np.isnan(r_p)) else np.nan
    bytes_per_pkt = (total_bytes / (total_pkts + 1e-6)) if total_pkts > 0 else np.nan
    pkts_per_sec  = (total_pkts / (duration + 1e-6)) if duration and duration > 0 else np.nan
    bytes_per_sec = (total_bytes / (duration + 1e-6)) if duration and duration > 0 else np.nan

    def L(x): return float(np.log1p(x)) if (x is not None and not np.isnan(x)) else np.nan

    # 20 keys đúng như model report
    return {
        "byte_ratio": byte_ratio,
        "bytes_per_pkt": bytes_per_pkt,
        "bytes_per_sec": bytes_per_sec,
        "duration": duration,
        "id.resp_p": resp_p,
        "log_bytes_per_pkt": L(bytes_per_pkt),
        "log_bytes_per_sec": L(bytes_per_sec),
        "log_pkts_per_sec": L(pkts_per_sec),
        "log_total_bytes": L(total_bytes),
        "log_total_pkts": L(total_pkts),
        "orig_bytes": o_b,
        "orig_pkts": o_p,
        "pkt_ratio": pkt_ratio,
        "pkts_per_sec": pkts_per_sec,
        "proto": proto,  # tf.string
        "resp_bytes": r_b,
        "resp_pkts": r_p,
        "resp_port_bucket": bucket_port(resp_p),
        "total_bytes": total_bytes,
        "total_pkts": total_pkts,
    }

# ---------- Threshold ----------
def read_threshold(thr_json:str, override:Optional[float]=None) -> float:
    if override is not None:
        return float(override)
    with open(thr_json) as f:
        obj = json.load(f)
    if isinstance(obj, (int, float, str)):
        try: return float(obj)
        except: pass
    if isinstance(obj, dict):
        for k in ["threshold","best_threshold","threshold_final",
                  "thr","thr_val","thr_tuned","best_thr","decision_threshold"]:
            if k in obj:
                return float(obj[k])
        for v in obj.values():
            try: return float(v)
            except: pass
    raise ValueError(f"Không tìm thấy ngưỡng trong {thr_json}")

# ---------- Keras wrapper ----------
class InferenceModel:
    def __init__(self, model_path:str, threshold:float):
        import tensorflow as _tf
        global tf
        tf = _tf
        self.threshold = float(threshold)
        try:
            self.model = tf.keras.models.load_model(model_path)
        except Exception:
            self.model = tf.keras.models.load_model(model_path, compile=False)

        self.multi_input = isinstance(self.model.inputs, (list, tuple))
        if self.multi_input:
            try:
                self.input_names = list(self.model.input_names)
            except Exception:
                self.input_names = [t.name.split(":")[0] for t in self.model.inputs]
            self.input_dtypes = [inp.dtype for inp in self.model.inputs]
            print(f"[INFO] Keras model expects {len(self.input_names)} inputs: {self.input_names}", flush=True)
        else:
            self.input_names, self.input_dtypes = [], []
            print("[INFO] Keras model expects a single vector input", flush=True)
        self._warned_missing = False

    def _vectorize_multi(self, feats: List[Dict[str, float]]):
        """Trả về dict {input_name: tf.Tensor} theo đúng dtype của model."""
        batch = len(feats)
        inputs_dict = {}
        missing = []

        for name, dtype in zip(self.input_names, self.input_dtypes):
            # robust string detection
            try:
                is_string = (dtype == tf.string) \
                            or (getattr(dtype, "name", "").lower() in ("string","tf.string","dt_string")) \
                            or (str(dtype).lower().endswith("string"))
            except Exception:
                is_string = False

            col = []
            for row in feats:
                v = row.get(name, None)
                if v is None:
                    v = "" if is_string else 0.0
                    missing.append(name)

                if is_string:
                    sval = "other" if (v is None or v == "" or v == "-") else str(v).lower()
                    col.append(sval)
                else:
                    if isinstance(v, str):
                        try: v = float(v)
                        except Exception: v = 0.0
                    col.append(np.nan_to_num(v if v is not None else np.nan,
                                             nan=0.0, posinf=0.0, neginf=0.0))

            # tạo TF tensor (batch,1)
            if is_string:
                t = tf.constant(col, dtype=tf.string)
            else:
                t = tf.convert_to_tensor(col, dtype=tf.float32)
            t = tf.reshape(t, (batch, 1))
            inputs_dict[name] = t

        if missing and not self._warned_missing:
            uniq = sorted(set(missing))
            print(f"[WARN] Some inputs absent in rows, filled default (0 or ''): "
                  f"{uniq[:10]}{' ...' if len(uniq)>10 else ''}", flush=True)
            self._warned_missing = True

        return inputs_dict

    def _vectorize_single(self, feats: List[Dict[str, float]]) -> np.ndarray:
        # nếu model là single-input, đặt thứ tự feature tại đây
        order = [
            "byte_ratio","bytes_per_pkt","bytes_per_sec","duration","id.resp_p",
            "log_bytes_per_pkt","log_bytes_per_sec","log_pkts_per_sec","log_total_bytes","log_total_pkts",
            "orig_bytes","orig_pkts","pkt_ratio","pkts_per_sec","resp_bytes","resp_pkts",
            "resp_port_bucket","total_bytes","total_pkts",
        ]
        X = []
        for f in feats:
            vec = [np.nan_to_num(f.get(k, np.nan), nan=0.0, posinf=0.0, neginf=0.0) for k in order]
            X.append(vec)
        return np.asarray(X, dtype=np.float32)

    def score(self, feats: List[Dict[str, float]]):
        if self.multi_input:
            model_in = self._vectorize_multi(feats)     # <-- DICT
            probs = self.model.predict(model_in, verbose=0).reshape(-1)
        else:
            X = self._vectorize_single(feats)
            probs = self.model.predict(X, verbose=0).reshape(-1)
        return probs

    def predict_label(self, probs: np.ndarray) -> np.ndarray:
        return (probs >= self.threshold).astype(int)

# ---------- Batch runner ----------
def _process_batch(buffer_rows, field_map, model:InferenceModel, out_f, scores_f, args):
    rows, feats = zip(*buffer_rows)
    probs = model.score(list(feats))
    preds = model.predict_label(probs)
    t = int(time.time())
    for r, p, pr in zip(rows, preds, probs):
        record = {
            "ts": t,
            "score": float(pr),
            "pred": int(p),
            "uid": r.get("uid", None),
            "id.orig_h": r.get("id.orig_h", None),
            "id.resp_h": r.get("id.resp_h", None),
            "id.resp_p": r.get(field_map["id.resp_p"], None),
            "duration": r.get(field_map["duration"], None),
            "proto": r.get(field_map.get("proto","proto"), "other"),
        }
        # alert
        if p == 1:
            out_f.write(json.dumps(record) + "\n")
            if args.print_alerts:
                print(json.dumps(record), flush=True)
        # stream all
        if args.stream_all:
            if scores_f:
                scores_f.write(json.dumps(record) + "\n")
            else:
                print(json.dumps(record), flush=True)

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn_log", required=True)
    ap.add_argument("--model_path", required=True)
    ap.add_argument("--threshold_json", required=True)
    ap.add_argument("--override_threshold", type=float)
    ap.add_argument("--out_jsonl", default="./alerts.jsonl")
    ap.add_argument("--batch", type=int, default=256)
    ap.add_argument("--print_alerts", action="store_true")
    ap.add_argument("--stream_all", action="store_true")
    ap.add_argument("--scores_jsonl", help="Ghi toàn bộ score/pred (JSONL) nếu set")
    args = ap.parse_args()

    thr = read_threshold(args.threshold_json, args.override_threshold)
    model = InferenceModel(args.model_path, thr)

    os.makedirs(os.path.dirname(args.out_jsonl) or ".", exist_ok=True)
    out_f = open(args.out_jsonl, "a", buffering=1)
    scores_f = open(args.scores_jsonl, "a", buffering=1) if args.scores_jsonl else None

    buffer_rows, field_map = [], None
    try:
        for row in zeek_stream_rows(args.conn_log):
            if field_map is None:
                field_map = build_colmap(list(row.keys()))
            feat = features_from_row(row, field_map)
            buffer_rows.append((row, feat))
            if len(buffer_rows) >= args.batch:
                _process_batch(buffer_rows, field_map, model, out_f, scores_f, args)
                buffer_rows.clear()
    except KeyboardInterrupt:
        pass
    finally:
        if buffer_rows:
            _process_batch(buffer_rows, field_map, model, out_f, scores_f, args)
        out_f.close()
        if scores_f: scores_f.close()

if __name__ == "__main__":
    main()
