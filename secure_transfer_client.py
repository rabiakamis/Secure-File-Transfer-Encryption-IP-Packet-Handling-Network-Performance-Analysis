import socket
import os
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5001
BUFFER_SIZE = 4096
ENCRYPTION_KEY = b'ThisIsASecretKey'  # 16, 24, 32 byte olmalı

def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ct_bytes  # IV başta yollanır

def send_file(filename):
    filesize = os.path.getsize(filename)
    s = socket.socket()
    s.connect((SERVER_HOST, SERVER_PORT))
    print(f"[+] Bağlandı {SERVER_HOST}:{SERVER_PORT}")

    # Dosya adı gönder
    s.send(filename.encode())
    s.recv(BUFFER_SIZE)

    # Dosya boyutu gönder
    s.send(str(filesize).encode())
    s.recv(BUFFER_SIZE)

    # Dosya şifrele
    with open(filename, "rb") as f:
        data = f.read()
        encrypted = encrypt(data, ENCRYPTION_KEY)

    # Dosyayı parça parça gönder ve zaman ölç
    start_time = time.time()
    total_sent = 0
    chunk_size = 4096
    for i in range(0, len(encrypted), chunk_size):
        s.sendall(encrypted[i:i+chunk_size])
        total_sent += min(chunk_size, len(encrypted) - i)
    end_time = time.time()

    duration = end_time - start_time
    if duration == 0:
        duration = 0.000001

    # SHA-256 hash gönder
    sha256_hash = hashlib.sha256(data).hexdigest()
    s.send(sha256_hash.encode())
    print(f"[✓] Dosya ve hash gönderildi.")

    # Bant genişliği hesapla (bit/saniye -> Mbps)
    size_bits = total_sent * 8
    speed_mbps = size_bits / (duration * 1_000_000)
    print(f"[i] Transfer süresi: {duration:.6f} saniye")
    print(f"[i] Ortalama bant genişliği: {speed_mbps:.2f} Mbps")

    s.close()


if __name__ == "__main__":
    send_file("testfile.txt")
