# Hướng dẫn chi tiết dự án KLTN_project_AI_code

## 1. Mục tiêu dự án

Dự án **KLTN_project_AI_code** xây dựng một hệ thống phát hiện xâm nhập mạng dựa trên log **Zeek** và bộ dữ liệu **CICIDS**. Mục tiêu: phân loại kết nối **benign / attack** với độ chính xác cao và có thể áp dụng trên log thời gian thực.

## 2. Kiến trúc tổng thể

1. **Chuẩn bị & tiền xử lý**: đọc CSV (CICIDS), chuẩn hóa tên cột, ánh xạ alias, trích xuất đặc trưng.
2. **Huấn luyện**: mô hình Residual MLP (wide & deep) với 20 đặc trưng số + 2 đặc trưng phân loại; chia train/val/test; chọn ngưỡng tối ưu.
3. **Suy luận thời gian thực**: đọc `conn.log` của Zeek, tái tạo đặc trưng như lúc train, nạp mô hình, chấm điểm, phát cảnh báo.

## 3. Bảng ánh xạ CICIDS → Zeek (các cột chính)

| Trường CICIDS (ví dụ)                    | Tên chuẩn dùng khi train | Trường Zeek trong `conn.log` | Ghi chú                 |
| ---------------------------------------- | ------------------------ | ---------------------------- | ----------------------- |
| `SourceIP`, `Src IP`                     | `SourceIP`               | `id.orig_h`                  | IP nguồn                |
| `DestinationIP`, `Dst IP`                | `DestinationIP`          | `id.resp_h`                  | IP đích                 |
| `SourcePort`, `Src Port`                 | `SourcePort`             | `id.orig_p`                  | Cổng nguồn              |
| `DestinationPort`, `Dst Port`, `dport`   | `DestinationPort`        | `id.resp_p`                  | Cổng đích (dùng bucket) |
| `FlowDuration`                           | `Duration`               | `duration`                   | ns → giây               |
| `TotalFwdPackets`                        | `orig_pkts`              | `orig_pkts`                  | Số gói chiều đi         |
| `TotalBackwardPackets`                   | `resp_pkts`              | `resp_pkts`                  | Số gói chiều về         |
| `TotalLengthFwdPackets`, `Tot Fwd Bytes` | `orig_bytes`             | `orig_bytes`                 | Tổng bytes chiều đi     |
| `TotalLengthBwdPackets`, `Tot Bwd Bytes` | `resp_bytes`             | `resp_bytes`                 | Tổng bytes chiều về     |
| `Protocol`                               | `Protocol`               | `proto`                      | tcp/udp/icmp/other      |

> Lưu ý: tên cột CICIDS có thể khác nhau tùy file; code có bảng **alias** để dò các biến thể phổ biến, sau đó đổi về tên chuẩn trước khi trích xuất đặc trưng.

## 4. Kỹ thuật đặc trưng (Feature engineering)

Sinh **20 đặc trưng số** + **2 đặc trưng phân loại** từ các trường chuẩn:

* **Số**: `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `total_bytes`, `total_pkts`, `bytes_ratio`, `pkts_ratio`, `bytes_per_sec`, `pkts_per_sec`, `bytes_per_pkt`, `pkts_per_byte`, và các biến **log1p** tương ứng (giảm lệch).
* **Phân loại**:

  * `resp_port_bucket`: bucket hóa cổng đích (well-known 0–1023, registered 1024–49151, dynamic 49152–65535).
  * `proto`: chuẩn hóa về `tcp / udp / icmp / other`.

## 5. Kiến trúc Neural Network (Residual MLP)

* **Đầu vào**:

  * Nhánh **số** → `Normalization` (mean/var từ train).
  * Nhánh **chuỗi** → `StringLookup` (từ vocab train) → `Embedding` (ví dụ `proto` dim=6, `resp_port_bucket` dim=4).
* **Ghép nhánh** → chuỗi **khối Residual MLP** (mặc định 5 khối): Dense → BN → ReLU → Dropout → Dense (giảm chiều) + **skip connection** (nếu cần).
* **Đầu ra**: Dense(96) → Dense(1, sigmoid).
* **Huấn luyện**: Optimizer Adam, `BinaryCrossentropy`, metric `BinaryAccuracy`, `AUC`; có `EarlyStopping`, `ReduceLROnPlateau`, `ModelCheckpoint`.

## 6. Quy trình huấn luyện

1. Chuẩn hóa tên cột, ánh xạ alias → lấy đúng cột chuẩn.
2. Tính đặc trưng số và phân loại; tách **train/val** (80/20, stratify).
3. Tính thống kê chuẩn hóa và vocab embedding từ **train**.
4. Tạo `tf.data.Dataset` theo `--batch`.
5. Train mô hình (mặc định ~40 epoch) + callbacks.
6. **Tối ưu ngưỡng (threshold)**: dùng tiêu chí *maximin* (tối đa hóa min(train_acc, val_acc)) để chọn ngưỡng quyết định.
7. Lưu mô hình tốt nhất (`.keras`), `metrics.json`, `metrics_threshold.json`, biểu đồ loss/AUC.

## 7. Thuật toán suy luận (Inference)

> **Quan trọng:** **logic suy luận/đặc trưng** nằm trong **file huấn luyện** `train_cicids_zeek.py`.
> **`new.py`** là **trình đọc `conn.log` real-time** và **áp dụng** mô hình đã train.

Luồng chạy thực tế:

1. **Đọc log**: `new.py` đọc `conn.log` (NDJSON hoặc TSV) theo stream.
2. **Ánh xạ cột**: dùng alias để khớp cột thực tế ↔ tên chuẩn.
3. **Trích xuất đặc trưng**: tạo đúng 20 số + 2 phân loại như lúc train.
4. **Vector hóa**:

   * **Multi-input**: tạo dict `{input_name: tensor(batch,1)}` cho số/chuỗi.
   * **Single-input**: tạo ma trận 2D theo thứ tự feature cố định.
5. **Dự đoán**: `model.predict(...)` → xác suất `[0..1]`.
6. **Gán nhãn**: so sánh với **threshold** đã lưu → 0/1.
7. **Ghi kết quả**: JSONL gồm timestamp, score, pred, UID, IP, cổng, duration, proto. Tuỳ chọn `--print_alerts` để in alert; `--stream_all` để ghi cả benign.

## 8. Đánh giá & ngưỡng (Scoring)

* **Báo cáo**: classification report (precision/recall/F1), **confusion matrix**.
* **Đường cong**: **ROC-AUC**, **PR-AUC**, biểu đồ **loss/AUC** theo epoch.
* **Ngưỡng tối ưu**: `metrics_threshold.json` lưu giá trị threshold, dùng thống nhất cho inference.

## 9. Cách chạy nhanh

### 9.1 Huấn luyện (ví dụ)

```bash
python train_cicids_zeek.py \
  --train_csv data/train.csv \
  --test_csv data/test.csv \
  --outdir out_dir \
  --epochs 60 \
  --batch 2048
```

Kết quả: `out_dir/best.keras`, `out_dir/metrics.json`, `out_dir/metrics_threshold.json`, biểu đồ loss/AUC, báo cáo test.

### 9.2 Suy luận thời gian thực (đọc Zeek)

```bash
python new.py \
  --conn_log /path/to/zeek/conn.log \
  --model_path out_dir/best.keras \
  --threshold_json out_dir/metrics_threshold.json \
  --out_jsonl output/alerts.jsonl \
  --print_alerts
```

Tùy chọn:

* `--override_threshold` thay thế ngưỡng từ file JSON.
* `--stream_all` ghi cả benign (lưu log điểm số đầy đủ).

## 10. Cấu trúc thư mục (gợi ý)

```
.
├─ train_cicids_zeek.py     # Train + tính đặc trưng + chọn threshold
├─ new.py                   # Đọc conn.log realtime + áp dụng model
├─ data/                    # CSV CICIDS (đã chuẩn hóa tên cột)
├─ out_dir/                 # model, metrics, threshold, biểu đồ
└─ README.md
```

## 11. Mở rộng & lưu ý

* **Bổ sung đặc trưng**: thêm IP/ASN/flags nếu log cho phép.
* **Mất cân bằng**: cân nhắc resample hoặc `class_weight`.
* **Sản xuất**: giám sát drift; retrain định kỳ; tối ưu batch/latency.
* **Bảo mật**: ẩn/giải danh IP khi xuất kết quả theo quy định.

---
