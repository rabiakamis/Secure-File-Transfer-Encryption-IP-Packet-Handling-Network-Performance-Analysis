from scapy.all import sniff, Raw, get_if_list

def sniff_packets(interface, filter_rule="tcp port 5001"):
    print(f"[!] Paketler dinleniyor... Arayüz: {interface}")
    sniff(iface=interface, filter=filter_rule, prn=analyze_packet, count=10)

def analyze_packet(packet):
    if packet.haslayer(Raw):
        data = packet[Raw].load
        print(f"[!] Veri bulundu (şifreli olmalı): {data[:50]}...")

def select_interface():
    interfaces = get_if_list()
    print("[i] Kullanılabilir arayüzler:")
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    while True:
        choice = input("Lütfen dinlemek istediğiniz arayüzün numarasını girin: ")
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            return interfaces[int(choice) - 1]
        else:
            print("Geçersiz seçim, tekrar deneyin.")

def simulate_mitm():
    print("[⚠] MITM saldırısı simülasyonu (örnek olarak loglama yapılır).")
    iface = select_interface()
    sniff_packets(iface)

if __name__ == "__main__":
    simulate_mitm()
