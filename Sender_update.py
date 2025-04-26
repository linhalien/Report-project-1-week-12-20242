import time
import random
import struct
from scapy.all import IP, ICMP, send

target_ip = "127.0.0.1"  # Địa chỉ IP đích 
message = "H"
print(f"Message: {message}")

# Mã hóa thông điệp thành nhị phân 8 bit cho mỗi ký tự
binary_message = ''.join(format(ord(c), '08b') for c in message)
print(f"Binary message: {binary_message}")

def send_icmp(identifier, packet_type="data"):
    # Tạo timestamp động (8 bytes) giống gói ICMP Linux
    current_time = int(time.time() * 1000000)  # Microseconds since epoch (00:00:00 UTC, 1/1/1970)
    timestamp = struct.pack('>Q', current_time)  # 8 bytes, big-endian

    # Payload tuần tự: 48 bytes, default trên Linux (0x00, 0x01, ..., 0x2F)
    sequential_data = bytes(range(0x00, 0x30))  # 0x00 đến 0x2F (48 bytes)
    # Marker chính cho covert channel: thay byte cuối 48 (56) thành 0x3f
    sequential_data = sequential_data[:-1] + b'\x3f'

    # Marker phụ để phân biệt loại gói
    if packet_type == "mock":
        # Gói mốc: byte 46 (54) thành 0x3d
        sequential_data = sequential_data[:-3] + b'\x3d' + sequential_data[-2:]
    elif packet_type == "end":
        # Gói kết thúc: byte 46 (54) thành 0x2b
        sequential_data = sequential_data[:-3] + b'\x2b' + sequential_data[-2:]

    # Kết hợp timestamp và sequential data thành payload 56 bytes
    payload = timestamp + sequential_data

    # Tạo gói tin ICMP
    pkt = IP(dst=target_ip)/ICMP(id=identifier)/payload
    send(pkt, verbose=0)

# Gửi gói mốc đầu tiên (thuộc covert channel, marker phụ ở byte 47)
moc_identifier = random.randrange(1, 65535)
send_icmp(moc_identifier, packet_type="mock")
print(f"[MOCK] Gửi gói mốc với id={moc_identifier}")

# Định nghĩa độ trễ cho bit
delay_bit_1 = 1.0  # Độ trễ cho bit 1
delay_bit_0 = 0.1  # Độ trễ cho bit 0

# Gửi từng bit theo kiểu covert timing
num = 0
while num < len(binary_message):
    is_noise = random.choice([True, False])
    
    if is_noise:
        # Gửi nhiễu: delay ngẫu nhiên + identifier lẻ
        delay_noise = random.uniform(0.05, 1.5)
        time.sleep(delay_noise)
        identifier = random.randrange(1, 65535, 2)  # Identifier lẻ
        send_icmp(identifier, packet_type="data")
        print(f"[NOISE] id={identifier} - Gửi nhiễu sau {delay_noise:.2f} giây")
    else:
        # Gửi dữ liệu: identifier chẵn + delay theo bit
        time.sleep(delay_bit_1 if binary_message[num] == '1' else delay_bit_0)
        identifier = random.randrange(0, 65534, 2)  # Identifier chẵn
        send_icmp(identifier, packet_type="data")
        print(f"[DATA] bit={binary_message[num]}, id={identifier} - Gửi thông điệp sau {delay_bit_1 if binary_message[num] == '1' else delay_bit_0} giây")
        num += 1

# Gửi gói kết thúc (thuộc covert channel, marker phụ ở byte 47)
end_identifier = random.randrange(1, 65535)
send_icmp(end_identifier, packet_type="end")
print(f"[END] Gửi gói kết thúc với id={end_identifier}")