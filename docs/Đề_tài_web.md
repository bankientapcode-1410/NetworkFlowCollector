# VDT Backend Projects

## Network Flow Collector & Query Service

### Mô Tả
Xây dựng hệ thống backend thu thập và truy vấn network flow log (dữ liệu phiên kết nối mạng) từ nhiều nguồn khác nhau. Hệ thống đóng vai trò là tầng ingestion — nhận dữ liệu flow từ các agent/probe gửi lên, chuẩn hóa về schema thống nhất, và lưu vào kho tập trung để phục vụ phân tích.

Sinh viên sẽ tìm hiểu các định dạng flow phổ biến (NetFlow v5/v9, sFlow, JSON log từ Zeek/Suricata), xây dựng các parser/collector tương ứng, và thiết kế pipeline ingestion theo mô hình producer-consumer.

#### Các Collector Cần Xây Dựng

| Collector                | Cơ Chế                                         | Ghi Chú  |
|--------------------------|------------------------------------------------|----------|
| NetFlow v5/v9            | UDP listener, parse binary packet theo RFC     | Bắt buộc |
| Zeek/Suricata JSON log   | Đọc file log hoặc nhận qua TCP/Unix socket     | Bắt buộc |
| Syslog (CEF/LEEF format) | UDP/TCP listener, parse header + extension     | Tùy chọn |
| REST ingest API          | POST JSON trực tiếp, dùng cho test/integration | Bắt buộc |

### Yêu Cầu Kết Quả Đầu Ra

| # | Hạng Mục | Mô Tả |
|---|----------|-------|
| 1 | Tài liệu thiết kế | Kiến trúc hệ thống, lý do chọn cơ chế parse cho từng format, schema chuẩn hóa (normalized flow record) |
| 2 | Flow Normalization Service | Chuẩn hóa data từ các nguồn về schema thống nhất |
| 3 | Storage layer | Lưu vào DB phù hợp với partition theo thời gian, index tối ưu cho query src/dst IP |
| 4 | REST API truy vấn | Filter theo các trường đã có; aggregation (top talkers, top ports); phân trang |
| 5 | Unit test + tài liệu API | Coverage ≥ 80%, Swagger/OpenAPI |
| 6 | Demo | Docker Compose toàn bộ hệ thống, script sinh NetFlow packet và Zeek log giả để demo |

### Yêu Cầu Phi Chức Năng

#### 1. Hiệu Năng (Performance)
- Xử lý tối thiểu 5.000 flow records/giây
- API phản hồi < 2 giây với 10 triệu bản ghi

#### 2. Độ Tin Cậy (Reliability)
- At-least-once delivery
- Auto-retry với exponential backoff
- Collector lưu offset/position để restart không mất dữ liệu

#### 3. Khả Năng Mở Rộng (Scalability)
- Kiến trúc plugin-based cho collector — thêm format mới không ảnh hưởng collector đang chạy
- Hỗ trợ chạy nhiều collector instance song song

#### 4. Bảo Mật (Security)
- Credential không hardcode
- Sensitive field (payload content) có thể mask trước khi lưu

#### 5. Khả Năng Vận Hành (Operability)
- `/health` endpoint
- Metrics: records processed, ingest rate, parse error count
- Application log dạng JSON structured

#### 6. Khả Năng Bảo Trì (Maintainability)
- Linter tự động
- Unit test không phụ thuộc network thật (dùng mock packet/file)
- Contribution guide mô tả cách thêm collector mới
