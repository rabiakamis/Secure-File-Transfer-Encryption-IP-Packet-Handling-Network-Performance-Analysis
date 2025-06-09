import socket
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5001
BUFFER_SIZE = 4096
ENCRYPTION_KEY = b'ThisIsASecretKey'  # 16, 24 veya 32 byte olmalı

def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=ciphertext[:16])
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext

def receive_file():
    s = socket.socket()
    s.bind((SERVER_HOST, SERVER_PORT))
    s.listen(1)
    print(f"[+] Dinleniyor: {SERVER_HOST}:{SERVER_PORT}")
    
    client_socket, address = s.accept()
    print(f"[+] {address} bağlandı.")

    # Dosya adı al
    filename = client_socket.recv(BUFFER_SIZE).decode()
    client_socket.send(b'OK')

    encrypted_size = int(client_socket.recv(BUFFER_SIZE).decode())
    client_socket.send(b'OK')

    total_received = 0
    start_time = time.time()
    with open("received_" + filename, "wb") as f:
        while total_received < encrypted_size:
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            f.write(bytes_read)
            total_received += len(bytes_read)
    end_time = time.time()

    duration = end_time - start_time

    print(f"[+] {filename} alındı.")

    # Hash al
    file_hash = client_socket.recv(BUFFER_SIZE).decode()
    print(f"[+] Beklenen SHA-256 hash: {file_hash}")

    # Hash doğrulama
    with open("received_" + filename, "rb") as f:
        data = f.read()
        decrypted = decrypt(data, ENCRYPTION_KEY)
        calculated_hash = hashlib.sha256(decrypted).hexdigest()

    if calculated_hash == file_hash:
        with open("decrypted_" + filename, "wb") as f:
            f.write(decrypted)
        print("[✓] Hash doğrulandı, dosya başarıyla alındı ve çözüldü.")
    else:
        print("[✗] Hash uyuşmuyor, dosya bozulmuş olabilir.")

    # Bant genişliği hesaplama
    size_bits = total_received * 8
    speed_mbps = size_bits / (duration * 1_000_000)
    print(f"[i] Alım süresi: {duration:.2f} saniye")
    print(f"[i] Ortalama bant genişliği: {speed_mbps:.2f} Mbps")

    client_socket.close()
    s.close()

if __name__ == "__main__":
    receive_file()
