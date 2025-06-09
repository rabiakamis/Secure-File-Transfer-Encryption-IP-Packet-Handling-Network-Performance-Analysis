# ip_utils.py

from scapy.all import IP, send, fragment
import random

def send_fragmented_packet(dst_ip, payload):
    ip_packet = IP(dst=dst_ip, ttl=64, id=random.randint(1, 65535)) / payload
    frags = fragment(ip_packet, fragsize=500)
    print(f"[i] {len(frags)} parçaya bölündü. Gönderiliyor...")
    for frag in frags:
        send(frag)
    print("[✓] Parçalar gönderildi.")

def build_custom_packet(dst_ip):
    pkt = IP(dst=dst_ip, ttl=128, flags="DF", id=12345)
    print(f"[✓] Paket: {pkt.summary()}")
    send(pkt)
