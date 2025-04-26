import time
from scapy.all import sniff, IP, ICMP

# Cấu hình
delay_bit_1 = 1.5      # Độ trễ cho bit 1
delay_bit_0 = 0.1      # Độ trễ cho bit 0
threshold = (delay_bit_0 + delay_bit_1) / 2  # Ngưỡng xác định bit
source_ip = "192.168.186.129"  # IP của sender (loopback để thử nghiệm)

def decode_message():
    binary_message = ""
    previous_timestamp = None
    previous_id = None
    decoding_started = False

    def process_packet(packet):
        nonlocal binary_message, previous_timestamp, previous_id, decoding_started

        # Lọc gói ICMP Echo Request (type 8) từ source_ip
        if not (packet.haslayer(IP) and packet.haslayer(ICMP) and
                packet[ICMP].type == 8 and packet[IP].src == source_ip):
            return

        # Kiểm tra marker chính (byte 56 = 0x3F)
        payload = bytes(packet[ICMP].payload)
        if len(payload) < 56 or payload[55] != 0x3F:  # Byte 56 của payload
            return

        # Lấy ID và timestamp
        icmp_id = packet[ICMP].id
        current_timestamp = time.time()

        # Kiểm tra gói mốc (byte 54 = 0x3d)
        if payload[53] == 0x3d and not decoding_started:
            print(f"[MOCK] Nhận gói mốc với id={icmp_id}")
            decoding_started = True
            previous_timestamp = current_timestamp
            previous_id = icmp_id
            return

        # Bỏ qua nếu chưa thấy gói mốc
        if not decoding_started:
            return

        # Kiểm tra gói kết thúc (byte 54 = 0x2b)
        if payload[53] == 0x2b:
            print(f"[END] Nhận gói kết thúc với id={icmp_id}")
            if binary_message:
                decoded_message = ''.join(
                    chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8)
                    if len(binary_message[i:i+8]) == 8
                )
                print(f"\nDecoded binary message: {binary_message}")
                print(f"Decoded message: {decoded_message}")
            else:
                print("Không có thông điệp để giải mã")
            raise SystemExit  # Thoát sniff

        # Bỏ qua gói trùng
        if previous_id is not None and icmp_id == previous_id:
            return

        # Xử lý gói nhiễu (ID lẻ)
        if icmp_id % 2 != 0:
            print(f"[NOISE] Nhận gói nhiễu với id={icmp_id}")
            previous_timestamp = current_timestamp
            previous_id = icmp_id
            return

        # Xử lý gói dữ liệu (ID chẵn)
        if previous_timestamp is not None:
            delay = current_timestamp - previous_timestamp
            print(f"[DATA] Delay id={icmp_id}: {delay:.3f} seconds")
            if delay >= threshold:
                binary_message += '1'
            elif delay <= threshold and delay > 0.05:
                binary_message += '0'
            else:
                print(f"Delay {delay:.3f}s không khớp bit 0 hoặc 1")
            print(f"Current binary: {binary_message}")  # Debug

        previous_timestamp = current_timestamp
        previous_id = icmp_id

    # Bắt gói tin liên tục
    # LƯU Ý: sniff tự động lặp, gọi process_packet cho mỗi gói ICMP khớp bộ lọc
    #        cho đến khi gặp gói kết thúc (SystemExit) hoặc nhấn Ctrl+C
    print(f"Bắt đầu lắng nghe gói ICMP từ {source_ip}...")
    try:
        sniff(filter=f"icmp and src {source_ip}", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\nĐã dừng chương trình")
    except SystemExit:
        pass

# Chạy receiver
decode_message()