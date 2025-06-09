# performance_tools.py

import subprocess

def ping_test(host="8.8.8.8"):
    result = subprocess.run(["ping", "-c", "4", host], capture_output=True, text=True)
    print("[✓] Ping Sonucu:")
    print(result.stdout)

def run_iperf(server_ip="127.0.0.1"):
    print("[✓] iPerf ölçümü başlatılıyor...")
    subprocess.run(["iperf3", "-c", server_ip])

def simulate_packet_loss(interface="lo", loss_percent="10%"):
    print(f"[!] % {loss_percent} paket kaybı uygulanıyor...")
    subprocess.run(["tc", "qdisc", "add", "dev", interface, "root", "netem", "loss", loss_percent])

def clear_tc(interface="lo"):
    subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"])
    print("[✓] tc ayarları temizlendi.")


