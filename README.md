# KLTN_project_AI_code — Hệ thống phát hiện xâm nhập từ log Zeek (CICIDS)

## 1. Mục tiêu dự án

Xây dựng một hệ thống phát hiện xâm nhập mạng dựa trên log **Zeek** và bộ dữ liệu **CICIDS**. Hệ thống:

* Phân loại **benign / attack** với mô hình **Residual MLP** (wide & deep).
* Huấn luyện offline trên CSV (CICIDS), sau đó **suy luận real-time** trên `conn.log` của Zeek.
* Dễ tái lập, có hướng dẫn triển khai và đánh giá.

---

## 2. Kiến trúc tổng thể (sơ đồ khối)

```
[CICIDS CSV / Zeek conn.log]
            │
            ▼
  Chuẩn hoá tên cột + Ánh xạ alias
            │
            ▼
  Trích xuất đặc trưng (20 số + 2 phân loại)
            │
            ├─(Train)─> Normalization + Embedding
                                  │
                                  ▼
                             Residual MLP
                                  │
                                  ▼
                         Xác suất attack ∈ [0..1]
                                  │
                                  ▼
                    Chọn ngưỡng (threshold) tối ưu
                                  │
                                  ▼
              (Realtime) Nạp model + threshold
                                  │
                                  ▼
                       Dự đoán → So sánh ngưỡng
                                  │
                                  ▼
                       Gán nhãn + Ghi kết quả
```

---

## 3. Dữ liệu & Chuẩn hoá cột (alias)

### 3.1. Chuẩn hoá

* Chuẩn hoá tên cột: bỏ khoảng trắng/ký tự lạ, về *snake_case*.
* Hợp nhất các biến thể tên (alias) từ CICIDS/Zeek về một **tên chuẩn** dùng nội bộ.

### 3.2. Bảng ánh xạ CICIDS → Zeek

| CICIDS                                | Tên chuẩn       | Zeek `conn.log` |
| ------------------------------------- | --------------- | --------------- |
| SourceIP / Src IP                     | SourceIP        | id.orig_h       |
| DestinationIP / Dst IP                | DestinationIP   | id.resp_h       |
| SourcePort / Src Port                 | SourcePort      | id.orig_p       |
| DestinationPort / Dst Port / dport    | DestinationPort | id.resp_p       |
| FlowDuration                          | Duration        | duration        |
| TotalFwdPackets                       | orig_pkts       | orig_pkts       |
| TotalBackwardPackets                  | resp_pkts       | resp_pkts       |
| TotalLengthFwdPackets / Tot Fwd Bytes | orig_bytes      | orig_bytes      |
| TotalLengthBwdPackets / Tot Bwd Bytes | resp_bytes      | resp_bytes      |
| Protocol                              | Protocol        | proto           |

> Ghi chú: `Duration` nếu là nano-second thì quy đổi về **giây**.

---

## 4. Trích xuất đặc trưng (feature engineering)

Sinh **20 đặc trưng số** + **2 đặc trưng phân loại**.

**Ký hiệu:**
`ob = orig_bytes`, `rb = resp_bytes`, `op = orig_pkts`, `rp = resp_pkts`, `T = duration (s)`, `ε` rất nhỏ tránh chia 0.

**Biến gốc (số):** `duration`, `ob`, `rb`, `op`, `rp`.

**Tổng:**

* `total_bytes = ob + rb`
* `total_pkts = op + rp`

**Tỷ lệ:**

* `bytes_ratio = ob / (rb + ε)`
* `pkts_ratio = op / (rp + ε)`

**Tốc độ:**

* `bytes_per_sec = total_bytes / (T + ε)`
* `pkts_per_sec = total_pkts / (T + ε)`

**Mật độ:**

* `bytes_per_pkt = total_bytes / (total_pkts + ε)`
* `pkts_per_byte = total_pkts / (total_bytes + ε)`

**Phi tuyến (ổn định thang đo):**

* `log1p` của: `ob, rb, op, rp, total_bytes, total_pkts, bytes_per_sec, pkts_per_sec, bytes_per_pkt, pkts_per_byte`.

**Phân loại (chuỗi):**

* `resp_port_bucket`: bucket hoá `id.resp_p` → `well_known`(0–1023), `registered`(1024–49151), `dynamic`(49152–65535).
* `proto`: chuẩn hoá về `tcp / udp / icmp / other`.

---

## 5. Kiến trúc Neural Network (Residual MLP)

* **Đầu vào:**

  * Nhánh **số** → `Normalization` (mean/var từ **train**).
  * Nhánh **chuỗi** → `StringLookup` (vocabulary từ **train**) → `Embedding` (ví dụ: `proto` dim=6, `resp_port_bucket` dim=4).
* **Ghép nhánh** → **n khối Residual MLP** (mặc định 5):
  `Dense → BatchNorm → ReLU → Dropout → Dense(giảm chiều)` + **skip connection**.
* **Đầu ra:** `Dense(96) → Dense(1, sigmoid)` → xác suất `p ∈ [0..1]`.
* **Huấn luyện:** Adam, `BinaryCrossentropy`, metric `BinaryAccuracy` + `AUC`; callbacks `EarlyStopping`, `ReduceLROnPlateau`, `ModelCheckpoint`.

---

## 6. Quy trình huấn luyện (offline)

1. Chuẩn hoá tên cột, **ánh xạ alias**.
2. Tạo **20 số + 2 phân loại** từ CSV CICIDS.
3. Chia **train/val** (80/20, stratify).
4. Tính thống kê chuẩn hoá & vocab embedding trên **train**.
5. Tạo `tf.data.Dataset` theo `--batch`.
6. Train mô hình (≈40 epoch, tuỳ chỉnh) + callbacks.
7. Quét **ngưỡng** (threshold) và chọn theo chiến lược **maximin**:
   `τ* = argmax_τ min(acc_train(τ), acc_val(τ))`.
8. Lưu `best.keras`, `metrics.json`, `metrics_threshold.json`, biểu đồ loss/AUC.

**Lệnh ví dụ:**

```bash
python train_cicids_zeek.py \
  --train_csv data/train.csv \
  --test_csv data/test.csv \
  --outdir out_dir \
  --epochs 60 \
  --batch 2048
```

---

## 7. Thuật toán suy luận (realtime)

> **Quan trọng:** Logic đặc trưng/định dạng đầu vào được định nghĩa ở **train** và được **tái sử dụng** y nguyên khi suy luận.

**Vai trò file:**

* `train_cicids_zeek.py`: định nghĩa đặc trưng, kiến trúc, huấn luyện, lựa chọn ngưỡng.
* `new.py`: **đọc `conn.log` realtime**, ánh xạ cột, tạo **cùng đặc trưng**, nạp mô hình & ngưỡng, **dự đoán**.

**Quy trình:**

1. Đọc `conn.log` theo stream (NDJSON hoặc TSV).
2. Ánh xạ cột thực tế ↔ tên chuẩn (alias).
3. Tạo 20 số + 2 phân loại, xử lý thiếu/ngoại lệ (mặc định an toàn).
4. **Vector hoá**:

   * **Multi-input**: dict `{input_name: tensor(batch,1)}` cho số/chuỗi.
   * **Single-input**: ma trận 2D `(batch, n_features)` theo **thứ tự cố định**.
5. `model.predict(inputs)` → xác suất `p`.
6. So sánh `p` với `τ*` → `pred ∈ {0,1}`.
7. Ghi JSONL + (tuỳ chọn) in alert.

**Lệnh ví dụ:**

```bash
python new.py \
  --conn_log /path/to/zeek/conn.log \
  --model_path out_dir/best.keras \
  --threshold_json out_dir/metrics_threshold.json \
  --out_jsonl output/alerts.jsonl \
  --print_alerts
```

Tuỳ chọn:

* `--override_threshold` (ghi đè ngưỡng)
* `--stream_all` (ghi cả benign vào file điểm số)

---

## 8. Cho điểm & Ngưỡng (scoring & thresholding)

* **Xác suất**: đầu ra sigmoid `p = σ(z)`.
* **Gán nhãn**: `pred = 1` nếu `p ≥ τ*`, ngược lại `0`.
* **Chọn ngưỡng** (khi train): quét dải ngưỡng, chọn **maximin** để cân bằng train/val.
* **Báo cáo**:

  * Classification report (precision/recall/F1).
  * Confusion matrix.
  * ROC-AUC, PR-AUC.
  * Biểu đồ loss/AUC theo epoch.

---

## 9. Xử lý **đầu vào** chi tiết

* **Parse NDJSON/TSV** an toàn, log lỗi dòng hỏng.
* **Đơn vị thời gian**: bảo đảm `duration` theo **giây**.
* **Thiếu cột**: dùng giá trị mặc định (0 cho số, `other` cho chuỗi), log cảnh báo.
* **Trật tự/kiểu dữ liệu**: giữ **đúng thứ tự** và dtype như lúc train.

---

## 10. Xử lý **đầu ra** chi tiết

**JSONL** mỗi dòng:

```json
{
  "ts": "2025-10-17T09:21:30Z",
  "score": 0.8432,
  "pred": 1,
  "uid": "Cbrg0a3kP8N",
  "id.orig_h": "10.0.0.5",
  "id.resp_h": "8.8.8.8",
  "id.resp_p": 53,
  "duration": 0.012,
  "proto": "udp"
}
```

Tuỳ chọn ghi:

* `--print_alerts`: chỉ in các dòng `pred=1`.
* `--stream_all`: ghi toàn bộ điểm số (benign + attack).
* Tích hợp SIEM: đẩy JSONL sang log pipeline (tuỳ môi trường).

---

## 11. Tham số CLI chính

**Huấn luyện (`train_cicids_zeek.py`):**

* `--train_csv`, `--test_csv`, `--outdir`
* `--epochs`, `--batch`
* (khác tuỳ code: seed, depth, width…)

**Suy luận (`new.py`):**

* `--conn_log`, `--model_path`, `--threshold_json`
* `--out_jsonl`, `--print_alerts`, `--stream_all`, `--override_threshold`

---

## 12. Cấu trúc thư mục gợi ý

```
.
├─ train_cicids_zeek.py     # Train + đặc trưng + threshold
├─ new.py                   # Đọc conn.log realtime + áp dụng model
├─ data/                    # CSV CICIDS (chuẩn hoá cột)
├─ output/                  # alerts.jsonl (tuỳ chọn)
├─ out_dir/                 # model, metrics, threshold, biểu đồ
└─ README.md
```

---

## 13. Sự cố thường gặp

* Sai thứ tự feature → kết quả lệch.
* Duration sai đơn vị → tốc độ “vọt” bất thường.
* Thiếu cột hoặc tên lạ → bật log cảnh báo, cập nhật alias.
* Ngưỡng không khớp → kiểm tra `metrics_threshold.json` hoặc dùng `--override_threshold`.


