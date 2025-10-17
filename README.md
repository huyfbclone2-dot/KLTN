# Hướng dẫn chi tiết dự án KLTN\_project\_AI\_code

## 1. Mục tiêu dự án

Dự án **KLTN\_project\_AI\_code** được xây dựng nhằm nghiên cứu và triển khai một hệ thống phát hiện xâm nhập mạng dựa trên log kết nối của **Zeek** và bộ dữ liệu **CICIDS**. Mục tiêu là tận dụng học sâu để phân loại các kết nối mạng thành **benign** (bình thường) hoặc **attack** (tấn công) với độ chính xác cao, đồng thời triển khai mô hình đó trong môi trường thực để xử lý log theo thời gian thực.

## 2. Kiến trúc tổng thể

Dự án gồm hai phần chính: huấn luyện mô hình và triển khai chấm điểm trực tuyến. Sơ đồ pipeline tổng quát như sau:


### 2.1 Sơ đồ luồng xử lý dữ liệu

Biểu đồ dưới đây mô tả luồng xử lý dữ liệu từ log Zeek đến mô hình, bao gồm các bước tiền xử lý, tạo đặc trưng, mô hình và ngưỡng cảnh báo.

![Sơ đồ xử lý dữ liệu](data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCAOEAlgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD7JoooqSgooooAKSlooAKKKKACiiigAoopKAFpKWigAooooAKKSloAKSlooASiiloASiilFACUUUUAFFFFABRRRQAUUUUAFFFFABRRS0AJRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFLSUtACUtFFABSUtFABRRRQAUUUUAFFFFABRRRQAUUlLQAUUUUAFAoooAKKKKACiiigAopKWgAooooAKKKKACiij8KACiiigAooooAKKKKACiiigAooooAKKSigBaSiigAooooAKKKWgBKKKKACiiigBaSiigAooooAWikooAWikooAKKKKACiiigBTSUUUAFFFFABRRRQAUtJS0AJRRRQAUtJRQAtFFJQAtFFFABRRRQAUUUUAFFFFABRRRQAd6KKKACiiigAooooAKKKKACiiigApKWigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACkpaSgBaKKKAEooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAWiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKSigBaKSloAKKKSgBRRSUtAAaSlooAKKSigBaKSigBaKSloAKSiigBaSlpKACiiigAoopsjpGu6R1RfVjgUAOoqH7Xa/8APzD/AN/B/jR9rtf+fmH/AL+D/GgVyaioftdr/wA/MP8A38X/ABo+12v/AD8w/wDfxf8AGgCaioPtdr/z8w/9/F/xpftdr/z8wf8Afxf8aBk1FQ/a7X/n5g/7+L/jR9rtf+fmH/v4v+NAE1FQ/a7X/n5h/wC/g/xpPtdr/wA/MH/fxf8AGgRPRUH2u1/5+YP+/i/40v2u1/5+YP8Av4v+NA7k1FQ/a7X/AJ+YP+/g/wAaPtdr/wA/MP8A38X/ABosFyaioftdr/z8wf8Afwf40fa7X/n5h/7+D/GgCaioPtdr/wA/MH/fxf8AGl+12v8Az8wf9/B/jQFyaioftdr/AM/MP/fwf40fa7X/AJ+Yf+/i/wCNAE1FQ/a7X/n5g/7+D/Gj7Xa/8/MH/fxf8aAJqKg+12v/AD8wf9/F/wAaX7Xa/wDPzD/38H+NAE1FQ/a7X/n5g/7+D/Gj7Xa/8/MH/fwf40BcmoqH7Xa/8/MP/fwf41JG6SLuR1ceqnNADqKKKACiiigBaKSloAKSlooAKKKKAEpaKKACiiigAooooAKKKKACiiigAooooASilooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAoNFFABRSUUAFFLSUAc58QfEUvh3RY3srdbrU72ZbWwgY8PK3c/wCyACT9PeuITwdZXzfa/FM83iDUH5kkuZG8pT6RxggKvpWx8SCW+IHg2M8qBeyAf7QiGD+pq9Xo4OlGUeZnl42rJS5Uznf+EF8G/wDQtad/3w3+NJ/wgvg3/oWtN/74b/Gujors9lDscPtJdznP+EE8G/8AQtab/wB8N/jR/wAI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[... truncated to not exceed tokens ...])

1. **Thu thập log**: Sử dụng Zeek để thu thập file `conn.log` (định dạng JSON hoặc TSV) từ môi trường mạng.
2. **Tiền xử lý & xây dựng đặc trưng**: Chuẩn hóa tên cột, ánh xạ alias và tạo các đặc trưng số/chuỗi an toàn từ log như tổng byte, tỉ lệ byte, log1p, phân nhóm cổng…【436517485083403†L0-L18】【436517485083403†L55-L71】.
3. **Huấn luyện mô hình**: Xây dựng kiến trúc **Residual MLP** với hai nhánh: 
   - Nhánh số: chuẩn hóa bằng `Normalization` với mean/variance học được【969484378569973†L350-L372】.
   - Nhánh chuỗi: tra cứu từ điển (`StringLookup`) và nhúng (`Embedding`) cho các thuộc tính như `proto` và `resp_port_bucket`【969484378569973†L350-L372】.
   Mô hình sử dụng Dropout và các khối residual để chống quá khớp; được tối ưu bằng hàm mất mát `BinaryCrossentropy` và theo dõi `BinaryAccuracy` & `AUC`【969484378569973†L350-L376】.
4. **Tinh chỉnh ngưỡng**: Sau khi huấn luyện, hệ thống tính toán ngưỡng tối ưu bằng thuật toán **maximin** dựa trên kết quả train/validation để cân bằng độ chính xác giữ hai tập【436517485083403†L8-L10】.
5. **Triển khai inference**: Script real-time đọc log `conn.log`, xây dựng đặc trưng theo đúng thứ tự, nạp mô hình, tính xác suất và so sánh với ngưỡng để phát hiện bất thường【412330984030775†L320-L367】.
6. **Lưu trữ & báo cáo**: Kết quả huấn luyện sinh ra nhiều artefact gồm báo cáo phân loại, ma trận nhầm lẫn, biểu đồ ROC/PR, file `metrics.json` và mô hình (`model.keras` và `saved_model/`)【436517485083403†L12-L17】.

## 3. Chuẩn bị dữ liệu

### 3.1 Bộ dữ liệu

Dữ liệu huấn luyện sử dụng các bản ghi từ bộ **CICIDS** hoặc log Zeek thực tế. Mỗi bản ghi cần chứa các cột cơ bản như:

* `DestinationPort`, `FlowDuration`, `TotalLengthofFwdPackets`, `TotalLengthofBwdPackets`, `TotalFwdPackets`, `TotalBackwardPackets` và nhãn `Label`【436517485083403†L55-L71】.

Ngoài ra, các cột khác như `SourcePort`, `Protocol`… sẽ được xử lý thông qua alias để phù hợp với tên chuẩn【436517485083403†L47-L71】.

### 3.2 Chuẩn hóa cột

Hàm `normalize_columns` trong tệp huấn luyện sẽ loại bỏ khoảng trắng và ký tự đặc biệt khỏi tên cột để chuẩn hóa【436517485083403†L34-L44】. Sau đó, các alias được ánh xạ để tìm đúng cột dù tên có thể khác nhau trong dataset (ví dụ: `id.resp_p`, `dst_port`, `Destination Port` đều trỏ về cùng một thuộc tính)【436517485083403†L47-L71】.

### 3.3 Xây dựng đặc trưng

Tập hợp **20 đặc trưng** số và 2 đặc trưng phân loại được trích xuất từ log để đưa vào mô hình. Các đặc trưng chính bao gồm【436517485083403†L112-L126】:

| Loại | Tên đặc trưng | Diễn giải |
|---|---|---|
| **Số (ZEEK\_MIN\_NUM)** | `id.resp_p`, `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `total_bytes`, `total_pkts`, `byte_ratio`, `pkt_ratio`, `bytes_per_pkt`, `pkts_per_sec`, `bytes_per_sec`, `log_total_bytes`, `log_total_pkts`, `log_bytes_per_pkt`, `log_pkts_per_sec`, `log_bytes_per_sec` | Các số liệu gốc và các biến dẫn xuất (tỉ lệ, log1p) từ chiều dài, số gói và thời lượng kết nối【436517485083403†L112-L126】. |
| **Chuỗi (ZEEK\_MIN\_CAT)** | `proto`, `resp_port_bucket` | Giá trị protocol (tcp/udp/icmp/other) và nhóm cổng đích theo khoảng (well\_known, registered, dynamic)【436517485083403†L112-L126】. |

Các hàm `map_proto_number_to_str` và `port_bucket` chịu trách nhiệm chuyển đổi giá trị protocol và phân nhóm cổng【436517485083403†L83-L92】【436517485083403†L128-L135】.

## 4. Kiến trúc mô hình

Mô hình được xây dựng bằng Keras và sử dụng kiến trúc **wide & deep residual MLP**:

1. **Nhánh số**: Các đặc trưng số được ghép thành vector và chuẩn hóa bằng lớp `Normalization` với mean và variance tính từ tập train【969484378569973†L350-L372】.
2. **Nhánh chuỗi**: Mỗi đặc trưng chuỗi (`proto`, `resp_port_bucket`) được ánh xạ qua `StringLookup` để chuyển thành id, sau đó đưa vào `Embedding` với kích thước nhúng nhỏ (4–6)【969484378569973†L350-L365】.
3. **Ghép nối & MLP**: Các phần đầu ra được nối (`Concatenate`) và truyền qua nhiều khối residual gồm Dense–BatchNorm–ReLU–Dropout–Dense【969484378569973†L350-L370】. Mỗi khối giảm dần số chiều và thêm kết nối tắt (skip connection) để cải thiện gradient.
4. **Đầu ra**: Lớp Dense cuối cùng sử dụng activation **sigmoid** để dự đoán xác suất tấn công【969484378569973†L371-L372】. Mô hình được biên dịch với optimizer Adam và loss `BinaryCrossentropy`, đồng thời theo dõi các metric `BinaryAccuracy` và `AUC`【969484378569973†L371-L376】.

## 5. Huấn luyện mô hình

Tệp `train_cicids_zeek.py` triển khai pipeline huấn luyện đầy đủ:

1. **Đọc dữ liệu**: Sử dụng tham số dòng lệnh `--train_csv` và `--test_csv` để đọc tập train và test bằng Pandas. Các cột được chuẩn hóa và ánh xạ alias【969484378569973†L408-L417】.
2. **Tạo tập train/validation**: Hàm `train_test_split` chia dữ liệu thành train và validation theo tỉ lệ 80/20, bảo toàn phân bố lớp【969484378569973†L414-L416】.
3. **Tính toán số liệu thống kê & vocabulary**: Tính mean/variance cho tủng đặc trưng số và thu thập các giá trị duy nhất (vocabulary) của đặc trưng chuỗi để dùng cho `StringLookup`【969484378569973†L418-L423】.
4. **Chuyển dữ liệu sang TensorFlow Dataset**: Tạo dataset cho quá trình huấn luyện (`shuffle=True`) và đánh giá (`shuffle=False`) để đảm bảo thứ tự ổn định khi dự đoán【969484378569973†L423-L426】.
5. **Khởi tạo mô hình**: Gọi `make_model` với các tham số chiều rộng (`width`), số lớp (`depth`), dropout…【969484378569973†L428-L430】.
6. **Huấn luyện**: Mô hình huấn luyện với số epoch tùy chọn (`--epochs`, mặc định 40) và batch size lớn (`--batch`, mặc định 4096)【969484378569973†L408-L411】. Callback `EarlyStopping` theo dõi `val_binary_accuracy` với patience 5; `ReduceLROnPlateau` giảm learning rate khi metric không cải thiện; `ModelCheckpoint` lưu mô hình tốt nhất【969484378569973†L430-L437】.
7. **Đánh giá & chọn ngưỡng**: Sau huấn luyện, script tính điểm dự đoán trên train và validation, sau đó tìm ngưỡng tối ưu bằng maximin để cân bằng độ chính xác của hai tập【436517485083403†L8-L10】. Các báo cáo (classification report, confusion matrix), biểu đồ ROC/PR và file metrics được ghi ra `outdir`【969484378569973†L449-L476】.

## 6. Tinh chỉnh ngưỡng dự đoán

Ngưỡng xác định ranh giới giữa **benign** và **attack**. Script sử dụng hàm `maximin_threshold` để duyệt lưới quantile và chọn ngưỡng tối đa hóa giá trị tối thiểu của accuracy trên train và validation【436517485083403†L8-L10】. Ngưỡng này được lưu vào `metrics_threshold.json` để dùng cho inference.

## 7. Chấm điểm log Zeek thời gian thực

Script `new.py` cho phép bạn triển khai mô hình trong môi trường thực:

1. **Đọc log**: Hàm `zeek_stream_rows` theo dõi file `conn.log` giống như lệnh `tail -F`, tự động nhận biết định dạng JSON hoặc TSV và trả về từng dòng dưới dạng dict【959694457367750†L72-L110】.
2. **Xây dựng đặc trưng**: Hàm `features_from_row` chuyển từng dòng log thành dict 20 đặc trưng số và chuềi đúng thứ tự【959694457367750†L112-L150】.
3. **Nạp mô hình & ngưỡng**: Lớp `InferenceModel` nạp mô hình Keras (single hoặc multi input), lấy ngưỡng từ file JSON, và chuẩn hóa dữ liệu đầu vào đúng dtype【412330984030775†L320-L367】.
4. **Tính điểm & gán nhãn**: Với mỗi batch (mặc định 256 bản ghi), script gọi `model.predict` để tính xác suất, sau đó so sánh với ngưỡng và gán nhãn【412330984030775†L370-L377】.
5. **Xuất kết quả**: Nếu một bản ghi được gán nhãn **attack**, script ghi ra file JSON lines (mặc định `alerts.jsonl`) hoặc in ra console nếu bật `--print_alerts`【412330984030775†L370-L377】. Có thể ghi toàn bộ bản ghi kèm đàn chỉ bặng tham số `--stream_all`【412330984030775†L385-L389】.

### 7.1 Tham số dòng lệnh của `new.py`

| Tham số | Mô tả |
|---|---|
| `--conn_log` | Đường dẫn tới file log Zeek cần theo dõi (bắt buộc)【412330984030775†L381-L389】. |
| `--model_path` | Đường dẫn tới mô hình (`model.keras` hoặc thư mục `saved_model`)【412330984030775†L381-L389】. |
| `--threshold_json` | Tập tin chứa ngưỡng dự đoán được sinh ra sau huấn luyện【412330984030775†L381-L389】. |
| `--override_threshold` | Ghi đè ngưỡng mặc định bằng giá trị mới (tuỳ chọn)【412330984030775†L381-L389】. |
| `--out_jsonl` | File JSONL để ghi cảnh báo, mặc định `./alerts.jsonl`. |
| `--batch` | Kích thước batch inference, mặc định 256【412330984030775†L385-L389】. |
| `--print_alerts` | In cảnh báo ra console. |
| `--stream_all` | Ghi toàn bộ bản ghi (kể cả benign) vào file `--scores_jsonl` nếu được chỉ định【412330984030775†L385-L389】. |

## 8. Kết quả & báo cáo

Sau khi chạy script huấn luyện, thư mục `outdir` sẽ chứa:

* **Mô hình**: `model.keras` (&#272;inh dạng Keras) và thư mục `saved_model/` (định dạng TensorFlow SavedModel).
* **Báo cáo**: Các tệp `classification_report(_val)(_tuned).txt` mô tả precision, recall, f1-score; `confusion_matrix(_val)(_tuned).csv` thể hiện ma trận nhầm lẫn; `metrics.json` lưu trữ ROC-AUC, AP của tập validation/test【436517485083403†L12-L17】.
* **Biểu đồ**: `train_val_loss.png` và `train_val_auc.png` so sánh loss/AUC giữa train và validation; `roc_curve.png` và `pr_curve.png` hiển thị các đường cong ROC và PR cho validation/test【969484378569973†L376-L396】.
* **Ngưỡng**: `metrics_threshold.json` lưu ngưỡng tối ưu để sử dụng khi inference【436517485083403†L12-L17】.

## 9. Hướng dẫn triển khai

### 9.1 Huấn luyện mô hình

```
bash
python3 train_cicids_zeek.py \
  --train_csv path/to/train.csv \
  --test_csv path/to/test.csv \
  --outdir ./output_dir \
  --epochs 40 \
  --batch 4096
```

* `--train_csv` và `--outdir` là bắt buộc. `--test_csv` giúp đánh giá thêm mô hình trên tập test (tùy chọn). 
* Thời gian huấn luyện phụ thuộc vào kích thước dữ liệu và cấu hình máy. Khi chạy trên CPU, nên điều chỉnh `batch` cho phù hợp.

### 9.2 Chấm điểm log thời gian thực

```
bash
python3 new.py \
  --conn_log /var/log/zeek/current/conn.log \
  --model_path ./output_dir/model.keras \
  --threshold_json ./output_dir/metrics_threshold.json \
  --out_jsonl /tmp/alerts.jsonl \
  --print_alerts
```

* Script sẻ chạy vô hạn cho tới khi dừng thủ công (Ctrl+C). 
* Khi bật `--print_alerts`, mỗi dòng cảnh báo sẻ được in dưới dạng JSON, chứa thời gian (`ts`), điểm xác suất (`score`), nhãn (`pred`) và thông tin kết nối như `uid`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `duration` và `proto`【412330984030775†L370-L377】.

## 10. Lưu ý và mở rộng

* **Tuỳ chỉnh đặc trưng**: Bạn có thể bổ sung hoặc thay đổi các đặc trưng đầu vào bằng cách sửa hàm `build_features_zeekmin` và cập nhật danh sách `ZEEK_MIN_NUM`/`ZEEK_MIN_CAT`. Điều này đòi hòi huấn luyện lại mô hình.
* **Cân bằng dữ liệu**: Script hiện tại không sử dụng `class_weight` trong quá trình huấn luyện để tối ưu độ chính xác; bạn có thể thêm tham số `class_weight` trong `model.fit` để xử lý mất cân bằng dữ liệu【969484378569973†L428-L430】.
* **Triển khai production**: Khi triển khai thực tế, nên chạy script inference như một dịch vụ (ví dụ systemd hoặc container) và tích hợp với hệ thống cảnh báo (Webhook, SIEM…).
* **Cập nhật mô hình**: Bộ dữ liệu mạng có thể thay đổi theo thời gian; hãy định kỳ thu thập dữ liệu mới và retrain để cái thiện hiệu suất.
