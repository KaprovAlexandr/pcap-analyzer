from pathlib import Path
from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP
from collections import Counter, defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP


PCAP_PATH = Path("pcaps/sample.pcapng")


def read_pcap(path: Path):
    """
    Читает PCAP-файл и возвращает список пакетов.
    """

    packets = rdpcap(str(path))

    return packets



def packet_statistics(packets):
    """
    Подсчитывает количество пакетов каждого типа.
    """

    stats = Counter()

    for packet in packets:

        if packet.haslayer(TCP):
            stats["TCP"] += 1

        elif packet.haslayer(UDP):
            stats["UDP"] += 1

        elif packet.haslayer(ICMP):
            stats["ICMP"] += 1

        elif packet.haslayer(ARP):
            stats["ARP"] += 1

        else:
            stats["Other"] += 1

        if packet.haslayer(DNS):
            stats["DNS"] += 1

    print("\n===== Packet Statistics =====\n")

    print(f"Всего пакетов: {len(packets)}\n")

    for protocol, count in stats.items():
        print(f"{protocol:<6}: {count}")

    return stats



def ip_statistics(packets):
    """
    Подсчитывает количество пакетов для каждого IP-адреса.
    """

    src_counter = Counter()
    dst_counter = Counter()

    for packet in packets:

        if packet.haslayer(IP):

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            src_counter[src_ip] += 1
            dst_counter[dst_ip] += 1

    print("\n===== TOP SOURCE IP =====\n")

    for ip, count in src_counter.most_common(10):
        print(f"{ip:<20} -> {count}")

    print("\n===== TOP DESTINATION IP =====\n")

    for ip, count in dst_counter.most_common(10):
        print(f"{ip:<20} -> {count}")

    return {
        "source_ips": dict(src_counter),
        "destination_ips": dict(dst_counter)
    }



def port_statistics(packets):
    """
    Подсчитывает количество пакетов для TCP и UDP портов.
    """

    src_ports = Counter()
    dst_ports = Counter()

    for packet in packets:

        if packet.haslayer(TCP):

            src_ports[packet[TCP].sport] += 1
            dst_ports[packet[TCP].dport] += 1

        elif packet.haslayer(UDP):

            src_ports[packet[UDP].sport] += 1
            dst_ports[packet[UDP].dport] += 1

    print("\n===== TOP SOURCE PORTS =====\n")

    for port, count in src_ports.most_common(10):
        print(f"{port:<8} -> {count}")

    print("\n===== TOP DESTINATION PORTS =====\n")

    for port, count in dst_ports.most_common(10):
        print(f"{port:<8} -> {count}")

    return {
        "source_ports": dict(src_ports),
        "destination_ports": dict(dst_ports)
    }



def dns_statistics(packets):
    """
    Подсчитывает количество DNS-запросов.
    """

    dns_counter = Counter()

    for packet in packets:

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):

            domain = packet[DNSQR].qname.decode(errors="ignore")

            domain = domain.rstrip(".")

            dns_counter[domain] += 1

    print("\n===== DNS REQUESTS =====\n")

    if not dns_counter:
        print("DNS-запросов не найдено.")
    else:

        for domain, count in dns_counter.most_common(10):
            print(f"{domain:<40} -> {count}")

    return dict(dns_counter)



def tcp_flag_statistics(packets):
    """
    Подсчитывает количество TCP-флагов.
    """

    flag_counter = Counter()

    FLAG_NAMES = {
        "S": "SYN",
        "SA": "SYN+ACK",
        "A": "ACK",
        "F": "FIN",
        "FA": "FIN+ACK",
        "R": "RST",
        "RA": "RST+ACK",
        "PA": "PSH+ACK",
        "P": "PSH"
    }

    for packet in packets:

        if packet.haslayer(TCP):

            flags = packet.sprintf("%TCP.flags%")

            flag_name = FLAG_NAMES.get(flags, flags)

            flag_counter[flag_name] += 1

    print("\n===== TCP FLAGS =====\n")

    for flag, count in flag_counter.most_common():
        print(f"{flag:<10} -> {count}")

    return dict(flag_counter)



def suspicious_port_statistics(packets):
    """
    Ищет обращения к потенциально опасным портам.
    """

    SUSPICIOUS_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "MS RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
    }

    port_counter = Counter()

    for packet in packets:

        if packet.haslayer(TCP):

            dst_port = packet[TCP].dport

            if dst_port in SUSPICIOUS_PORTS:
                port_counter[dst_port] += 1

        elif packet.haslayer(UDP):

            dst_port = packet[UDP].dport

            if dst_port in SUSPICIOUS_PORTS:
                port_counter[dst_port] += 1

    print("\n===== SUSPICIOUS PORTS =====\n")

    if not port_counter:
        print("Подозрительные порты не обнаружены.")

    else:

        for port, count in port_counter.most_common():

            service = SUSPICIOUS_PORTS[port]

            print(f"{port:<6} ({service:<10}) -> {count}")

    return {
        SUSPICIOUS_PORTS[port]: count
        for port, count in port_counter.items()
    }



def port_scan_detection(packets):
    """
    Обнаруживает возможное TCP SYN Port Scan.
    Один источник -> один получатель -> множество SYN на разные порты.
    """

    scans = defaultdict(set)

    for packet in packets:

        if (
            packet.haslayer(IP)
            and packet.haslayer(TCP)
        ):

            flags = packet.sprintf("%TCP.flags%")

            # интересуют только SYN без ACK
            if flags == "S":

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport

                scans[(src_ip, dst_ip)].add(dst_port)

    print("\n===== PORT SCAN DETECTION =====\n")

    suspicious = {}

    for (src_ip, dst_ip), ports in scans.items():

        if len(ports) >= 10:

            print(f"Источник: {src_ip}")
            print(f"Назначение: {dst_ip}")
            print(f"SYN на различных портов: {len(ports)}")
            print(f"Порты: {sorted(ports)}")
            print("Возможен TCP SYN Port Scan\n")

            suspicious[f"{src_ip} -> {dst_ip}"] = {
                "unique_ports": len(ports),
                "ports": sorted(ports)
            }

    if not suspicious:
        print("Признаков TCP SYN Port Scan не обнаружено.")

    return suspicious


def dns_flood_detection(packets):
    """
    Обнаруживает возможный DNS Flood.
    Один источник отправляет слишком много DNS-запросов.
    """

    dns_counter = Counter()

    for packet in packets:

        if (
            packet.haslayer(IP)
            and packet.haslayer(DNS)
            and packet.haslayer(DNSQR)
        ):

            src_ip = packet[IP].src
            dns_counter[src_ip] += 1

    print("\n===== DNS FLOOD DETECTION =====\n")

    suspicious = {}

    THRESHOLD = 100

    for ip, count in dns_counter.items():

        if count >= THRESHOLD:

            print(f"Источник: {ip}")
            print(f"DNS-запросов: {count}")
            print("Возможен DNS Flood\n")

            suspicious[ip] = count

    if not suspicious:
        print("Признаков DNS Flood не обнаружено.")

    return suspicious


def main():

    packets = read_pcap(PCAP_PATH)

    print(f"Файл успешно открыт: {PCAP_PATH}")
    print(f"Всего пакетов: {len(packets)}")

    packet_statistics(packets)
    ip_statistics(packets)
    port_statistics(packets)
    dns_statistics(packets)
    tcp_flag_statistics(packets)
    suspicious_port_statistics(packets)
    port_scan_detection(packets)
    dns_flood_detection(packets)


if __name__ == "__main__":
    main()