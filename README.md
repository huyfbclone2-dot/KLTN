Hướng dẫn chi tiết dự án KLTN_project_AI_code
1. Mục tiêu dự án
Dự án KLTN_project_AI_code xây dựng một hệ thống phát hiện xâm nhập mạng dựa trên log Zeek và bộ dữ liệu CICIDS. Mục tiêu là sử dụng học sâu để phân loại các kết nối thành benign hoặc attack với độ chính xác cao, đồng thời triển khai mô hình đó trong môi trường thực để xử lý log theo thời gian thực.
2. Kiến trúc tổng thể
Hệ thống gồm ba module chính:
1.	Thu thập và tiền xử lý log: thu thập log kết nối của Zeek (conn.log), chuẩn hóa tên cột, ánh xạ alias và trích xuất đặc trưng.
2.	Huấn luyện mô hình: sử dụng bộ dữ liệu CICIDS (đã map cột sang tên chuẩn) để huấn luyện mô hình Residual MLP với 20 đặc trưng số và 2 đặc trưng phân loại, thực hiện chia train/validation/test, tính toán thống kê, huấn luyện với callback và chọn ngưỡng tối ưu.
3.	Suy luận & cảnh báo thời gian thực: áp dụng mô hình vào log Zeek thực, trích xuất đặc trưng từ từng dòng, dự đoán xác suất tấn công và sinh cảnh báo khi điểm số vượt ngưỡng.
2.1 Sơ đồ luồng xử lý dữ liệu
Biểu đồ dưới đây minh hoạ luồng xử lý từ log Zeek đến cảnh báo. Các hình ảnh sơ đồ đã được nhúng trực tiếp dưới dạng base64 trong README gốc, vì vậy bạn có thể tham khảo ở đó hoặc sử dụng file ảnh riêng nếu muốn.
3. Chuẩn bị dữ liệu
3.1 Bản đồ ánh xạ cột CICIDS → Zeek
Dữ liệu CICIDS có nhiều tên cột khác nhau tuỳ tập. Bảng dưới đây tổng hợp các alias thường gặp, tên chuẩn mà script huấn luyện sử dụng và trường tương ứng trong log Zeek. Bảng này nhằm giúp bạn hiểu cách một cột trong bộ CICIDS được chuyển thành trường của conn.log và cuối cùng trở thành đặc trưng của mô hình.
Trường CICIDS (ví dụ)	Tên chuẩn (train script)	Trường Zeek	Ghi chú
SourceIP, Src IP, Source Address	SourceIP	id.orig_h	Địa chỉ IP nguồn (client). Không dùng trong đặc trưng mặc định nhưng có thể xuất hiện trong bản ghi kết quả
DestinationIP, Dst IP, Destination Address	DestinationIP	id.resp_h	Địa chỉ IP đích (server). Không dùng trong đặc trưng mặc định nhưng có thể ghi kèm khi xuất kết quả
SourcePort, Src Port, Sport	SourcePort	id.orig_p	Cổng nguồn
DestinationPort, Dst Port, Destination Port, dport	DestinationPort	id.resp_p	Cổng đích trong log Zeek, dùng để phân loại port bucket
FlowDuration	Duration	duration	Thời lượng luồng (nanoseconds) chuyển sang giây
TotalFwdPackets, Tot Fwd Pkts, Fwd Packet Total	orig_pkts	orig_pkts	Số gói chiều đi (client → server)
TotalBackwardPackets, Tot Bwd Pkts, Bwd Packet Total	resp_pkts	resp_pkts	Số gói chiều về (server → client)
TotalLengthFwdPackets, Tot Fwd Bytes, Fwd Bytes	orig_bytes	orig_bytes	Tổng bytes chiều đi
TotalLengthBwdPackets, Tot Bwd Bytes, Bwd Bytes	resp_bytes	resp_bytes	Tổng bytes chiều về
Protocol	Protocol	proto	Giao thức (TCP/UDP/ICMP/other)
3.2 Chuẩn hóa cột
Script huấn luyện sử dụng hàm normalize_columns() để loại bỏ khoảng trắng, ký tự đặc biệt trong tên cột và chuyển về chữ thường. Sau đó, các alias trong bảng trên được ánh xạ sang tên chuẩn. Nếu thiếu cột cần thiết, script sẽ bỏ qua hàng hoặc cảnh báo.
4. Kỹ thuật đặc trưng (Feature engineering)
Hàm build_features_zeekmin() trong file train_cicids_zeek.py tạo ra 20 đặc trưng số và 2 đặc trưng phân loại từ các trường gốc. Các bước chính:
•	Chuyển duration từ nanosecond sang giây.
•	Tính tổng bytes và tổng gói: total_bytes = orig_bytes + resp_bytes, total_pkts = orig_pkts + resp_pkts.
•	Tính tỷ lệ: bytes_ratio = orig_bytes / max(resp_bytes,1) và pkts_ratio = orig_pkts / max(resp_pkts,1).
•	Tính tốc độ: bytes/gói mỗi giây (bytes_per_sec, pkts_per_sec), bytes/gói mỗi packet (bytes_per_pkt, pkts_per_byte).
•	Tính log1p (logarit cơ sở e của 1 + giá trị) cho các biến chính để giảm độ lệch.
•	Phân loại cổng đích vào ba bucket (well‑known: 0–1023, registered: 1024–49151, dynamic: 49152–65535) → resp_port_bucket.
•	Chuẩn hóa proto thành một trong các nhãn: tcp, udp, icmp, other.
Danh sách 21 đặc trưng số:
•	duration
•	orig_bytes
•	resp_bytes
•	orig_pkts
•	resp_pkts
•	bytes_ratio
•	pkts_ratio
•	bytes_per_sec
•	pkts_per_sec
•	bytes_per_pkt
•	pkts_per_byte
•	total_bytes
•	total_pkts
•	orig_bytes_log
•	resp_bytes_log
•	orig_pkts_log
•	resp_pkts_log
•	total_bytes_log
•	total_pkts_log
•	bytes_ratio_log
•	pkts_ratio_log
Danh sách đặc trưng phân loại:
•	resp_port_bucket
•	proto
5. Kiến trúc mô hình Residual MLP
Mô hình được thiết kế cho dữ liệu dạng bảng với hai nhánh đầu vào:
•	Nhánh số: ghép 20 đặc trưng số thành vector, sau đó chuẩn hóa bằng Normalization (sử dụng mean và variance tính từ tập train).
•	Nhánh phân loại: mỗi đặc trưng phân loại (proto, resp_port_bucket) được ánh xạ thành chỉ số qua StringLookup (từ điển học từ train) rồi nhúng thành vector nhiều chiều qua Embedding.
Các nhánh được ghép lại (Concatenate) và đi qua nhiều khối residual MLP: Dense → BatchNormalization → ReLU → Dropout → Dense. Skip connection cộng đầu vào với đầu ra giúp mô hình học quan hệ phi tuyến mà không mất gradient. Chiều rộng giảm dần qua các khối. Kết thúc bằng một lớp Dense 96 neuron và một lớp sigmoid để xuất xác suất tấn công.
6. Quy trình huấn luyện
1.	Đọc dữ liệu: nạp file CSV train và test (nếu có), chuẩn hóa tên cột và ánh xạ alias.
2.	Chia tập train/validation/test: sử dụng phân phối stratified (80/20) để giữ tỷ lệ attack/benign.
3.	Tính thống kê & từ điển: tính mean/variance cho đặc trưng số và vocab cho đặc trưng phân loại từ tập train.
4.	Xây dựng dataset: chuyển dữ liệu thành tf.data.Dataset, shuffle và batch.
5.	Khởi tạo và huấn luyện mô hình: tạo mô hình Residual MLP, compile với BinaryCrossentropy và optimizer Adam; huấn luyện với callback EarlyStopping, ReduceLROnPlateau, ModelCheckpoint.
6.	Tinh chỉnh ngưỡng: sau huấn luyện, tính ngưỡng tối ưu dựa trên hàm maximin để cân bằng accuracy trên train và validation. Lưu ngưỡng vào metrics_threshold.json.
7.	Lưu kết quả: lưu mô hình (.keras và saved_model), báo cáo classification, ma trận nhầm lẫn, đường ROC/PR, và đồ thị loss/AUC theo epoch.
7. Thuật toán suy luận & triển khai thời gian thực
Thuật toán suy luận (inference) được triển khai trong file train_cicids_zeek.py – đây là nơi định nghĩa các hàm trích xuất đặc trưng và logic áp dụng mô hình đã huấn luyện để đưa ra dự đoán. Script new.py chỉ đảm nhiệm vai trò đọc file conn.log của Zeek theo thời gian thực và sử dụng lại các hàm từ train_cicids_zeek.py. Cụ thể:
1.	Trích xuất đặc trưng: khi huấn luyện, hàm build_features_zeekmin() và các hàm liên quan trong train_cicids_zeek.py tạo vector đặc trưng từ dữ liệu. new.py tái sử dụng những hàm này (hoặc logic tương đương) để trích xuất cùng một tập đặc trưng từ mỗi dòng log.
2.	Nạp mô hình & ngưỡng: new.py nạp mô hình Keras đã huấn luyện cùng với lớp Normalization, embedding và đọc ngưỡng tối ưu từ metrics_threshold.json. Nếu truyền --override_threshold, script sẽ sử dụng ngưỡng do người dùng chỉ định.
3.	Vector hóa & dự đoán: script phát hiện mô hình dạng multi-input hay single-input để tạo tensor đầu vào, gọi model.predict() lấy xác suất tấn công.
4.	Gán nhãn & xuất kết quả: so sánh xác suất với ngưỡng để gán nhãn attack (1) hoặc benign (0). Script ghi mỗi bản ghi ra file JSONL với timestamp, UID, IP nguồn/đích, cổng, thời lượng, protocol, score và label. Nếu bật --print_alerts, nó in ra console khi phát hiện attack.
Điểm quan trọng: logic suy luận chính nằm trong file huấn luyện để đảm bảo nhất quán giữa huấn luyện và triển khai. new.py chỉ là một interface nhẹ để đọc log Zeek theo thời gian thực và áp dụng mô hình, không chứa thuật toán trích xuất hay huấn luyện riêng biệt.
8. Đánh giá & chọn ngưỡng
Sau huấn luyện, script sinh ra:
•	Classification report: precision, recall, f1-score cho từng lớp và overall.
•	Confusion matrix: phân phối dự đoán đúng/sai trên tập test.
•	ROC-AUC & PR-AUC: đồ thị và giá trị đường cong ROC/PR.
•	Đồ thị loss & AUC theo epoch để đánh giá quá trình học.
•	Ngưỡng tối ưu: hàm maximin chọn ngưỡng sao cho accuracy trên train và validation càng cân bằng càng tốt. Ngưỡng được lưu trong metrics_threshold.json và dùng cho suy luận.
9. Hướng dẫn sử dụng
9.1 Huấn luyện
Chạy lệnh sau để huấn luyện mô hình:
python train_cicids_zeek.py \
  --train_csv path/to/train.csv \
  --test_csv path/to/test.csv \
  --outdir path/to/output_dir \
  --epochs 60 \
  --batch 2048
Kết quả sẽ được lưu vào thư mục outdir, gồm mô hình .keras, saved_model, file metrics.json, metrics_threshold.json, báo cáo và đồ thị.
9.2 Suy luận thời gian thực
Chạy lệnh sau để chấm điểm log Zeek thực tế:
python new.py \
  --conn_log /path/to/zeek/conn.log \
  --model_path path/to/output_dir/best.keras \
  --threshold_json path/to/output_dir/metrics_threshold.json \
  --out_jsonl output/alerts.jsonl \
  --print_alerts
Tham số --override_threshold cho phép thay thế ngưỡng, --stream_all ghi cả bản ghi benign.
10. Mở rộng & lưu ý
•	Bổ sung đặc trưng: có thể thêm các trường khác từ log Zeek như địa chỉ IP, cờ TCP, v.v. để cải thiện độ chính xác hoặc hỗ trợ phân tích chi tiết hơn.
•	Xử lý mất cân bằng: CICIDS là bộ dữ liệu mất cân bằng; xem xét resample hoặc đặt class_weight khi huấn luyện.
•	Triển khai sản xuất: theo dõi độ trễ suy luận và tối ưu pipeline nếu log có lưu lượng cao; cập nhật mô hình định kỳ khi dữ liệu mới.
•	Bảo mật: đảm bảo log không chứa thông tin nhạy cảm và cân nhắc mã hoá/ẩn danh khi triển khai thực tế.
Phụ lục: Sơ đồ mapping
Sơ đồ dưới đây minh hoạ trực quan cách dữ liệu CICIDS được chuyển thành trường Zeek và đặc trưng của mô hình. Sơ đồ chỉ mang tính minh hoạ để hiểu luồng chuyển đổi, không bắt buộc phải nhúng vào README nếu file quá lớn.
 

________________________________________
