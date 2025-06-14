# Đồ Án Nhập Môn Công Nghệ Phần Mềm
## Giới Thiệu
> - Tên đề tài: Hệ thống phát hiện tấn công DDoS dựa trên AI
> - Tập dữ liệu: CIC-DDoS2019
> - Mục tiêu: Xây dựng được một hệ thống phát hiện DDoS và có khả năng tự động chặn ip tấn công
> - Hệ thống được triển khai trên hệ điều hành linux

## Yêu Cầu
> - Một máy ảo PfSense
> - Một máy ảo Ubuntu

## Xây dựng PfSense
Bạn có thể tham khảo thông qua link này: [Hướng dẫn cài đặt PfSense](https://thegioifirewall.com/pfsense-huong-dan-cai-dat-firewall-pfsense-len-vmware/)      

![image](https://github.com/user-attachments/assets/0975afb2-3b52-4a5f-a5b9-656b0360e012)

PfSense cần ít nhất 2 network adapter:
  - Một adapter để giao tiếp với mạng ngoài
  - Một adapter để quản lý mạng nội bộ, cấp phát IP, thực hiện NAT, tường lửa… cho các máy nằm phía sau pfSense    
    
Bạn có thể tùy chỉnh để phù hợp với cấu hình của máy nhưng phải đáp ứng được ít nhất 2 network adapter cho PfSense

Sau khi cài đặt xong PfSense ta cần phải cấu hình phù hợp để quản lý:
  - Đây là ip của PfSense để ra Internet (192.168.88.166)
    
  ![image](https://github.com/user-attachments/assets/5bc6f541-5361-4788-9f66-1138afc34148)

  - Đây là ip của PfSense trong mạng nội bộ, thường là 192.168.1.1
    
  ![image](https://github.com/user-attachments/assets/56f85cc3-9390-4a3c-a162-7fb9d213d2da)

  - Thiết lập rule để hệ thống có thể giao tiếp với máy bên ngoài tường lửa (Thiết lập trên máy Ubuntu)
    
  ![image](https://github.com/user-attachments/assets/6ab8aa07-e18b-4e67-a92e-2ae7ae87d615)

  - Ở đây chỉ cho phép hệ thống (192.168.1.100) giao tiếp với các máy bên ngoài thông qua cổng 5001 và giao thức TCP/UDP
    
  ![image](https://github.com/user-attachments/assets/953e5b2e-61e3-4961-b532-4fbfc5b5a85d)

**Lưu ý:** Sau khi tải mã nguồn về, bạn cần thay đổi `pfsense_host`, `username`, `password` trong `backend/block.py` để phù hợp với hệ thống của bạn

## Xây dựng máy Ubuntu
- Chỉ yêu cầu sử dụng đúng network adapter với pfSense (ở đây hệ thống của tôi sử dụng là `Custom (/dev/vmnet1)`

## Tải và sử dụng hệ thống

- Hệ thống sẽ chạy trên ip local thông qua port 5000
- Bắt buộc phải chạy hệ thống với người dùng root
- Nên sử dụng venv 
- Bạn có thể thử mô phỏng tấn công UDP để kiểm thử hệ thống (sử dụng hping3 hoặc cách khác)

```
$ git clone https://github.com/ch1lL9uy/DO-AN-NMCNPM.git
$ cd DO-AN-NMCNPM/CodeAIDDoS_CNPM
$ python3 -m venv myvenv
$ sudo su
$ source myvenv/bin/active
$ pip install -r requirements.txt
$ python3 app/app.py
```

## Mô phỏng tấn công
Ở đây tôi sử dụng hping3 để mô phỏng tấn công từ một máy bên ngoài
sudo hping3 -2 -d 100000 --flood `<ip PfSense>` -p `<port>` 
```
sudo hping3 -2 -d 100000 --flood 192.168.88.166 -p 5001
```
Sau khi phát hiện tấn công, hệ thống sẽ gửi cảnh báo và chặn ip đó

![image](https://github.com/user-attachments/assets/cdfd564f-b9dc-4dd1-88be-e3da2240c54a)

![image](https://github.com/user-attachments/assets/4f8d0e85-e08e-4cde-b7f3-ad512d12110e)

![image](https://github.com/user-attachments/assets/1c76eed3-2b6a-43ff-a5cf-9d0ce6013637)

## Xây dựng Docker
### **Lưu ý**: Việc build docker sẽ chỉ có thể sử dụng để phát hiện DDoS, không thể chặn ip bằng pfSense được
Nếu bạn muốn thì chúng tôi cũng đã có sẵn một `Dockerfile` để bạn có thể build
hoặc bạn có thể tải container đã được build sẵn [tại đây](https://hub.docker.com/repository/docker/ch1ll9uy/ddos_detector)
```
$ sudo docker build -t <name> .
```

Vì câu lệnh có chút dài do cần quyền để có thể bắt gói tin nên sẽ tạo một script
```
$ nano run.sh
```
```
#!/bin/bash
sudo docker run -p 5000:5000 --net=host --cap-add=NET_ADMIN <name>
```
```
$ chmod +x run.sh
$ ./run.sh
```
