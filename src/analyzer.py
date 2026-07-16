import json
import argparse
from pathlib import Path
from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP
from collections import Counter, defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import init, Fore, Style


init(autoreset=True)
USE_COLOR = True

def read_pcap(path: Path):
    """
    Читает PCAP-файл и возвращает список пакетов.
    """

    packets = rdpcap(str(path))

    return packets



def parse_arguments():
    """
    Обрабатывает аргументы командной строки.
    """

    parser = argparse.ArgumentParser(
        description="PCAP Analyzer"
    )

    parser.add_argument(
        "-f",
        "--file",
        default="pcaps/sample.pcapng",
        help="Путь к PCAP-файлу"
    )

    parser.add_argument(
        "-j",
        "--json",
        default="results.json",
        help="Имя JSON-файла для сохранения результатов"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Отключить цветной вывод"
    )

    return parser.parse_args()



def export_report(report: dict, output_path: Path):
    """
    Экспортирует полный отчет анализа в JSON.
    """

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    success(f"\nJSON отчет сохранен: {output_path}")


def info(text):
    if USE_COLOR:
        print(Fore.CYAN + text)
    else:
        print(text)


def success(text):
    if USE_COLOR:
        print(Fore.GREEN + text)
    else:
        print(text)


def warning(text):
    if USE_COLOR:
        print(Fore.YELLOW + text)
    else:
        print(text)


def danger(text):
    if USE_COLOR:
        print(Fore.RED + text)
    else:
        print(text)


def header(text):
    if USE_COLOR:
        print(
            Style.BRIGHT +
            Fore.MAGENTA +
            text
        )
    else:
        print(text)


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

    header("\n===== Packet Statistics =====\n")

    info(f"Всего пакетов: {len(packets)}\n")

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

    header("\n===== TOP SOURCE IP =====\n")

    for ip, count in src_counter.most_common(10):
        print(f"{ip:<20} -> {count}")

    header("\n===== TOP DESTINATION IP =====\n")

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

    header("\n===== TOP SOURCE PORTS =====\n")

    for port, count in src_ports.most_common(10):
        print(f"{port:<8} -> {count}")

    header("\n===== TOP DESTINATION PORTS =====\n")

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

    header("\n===== DNS REQUESTS =====\n")

    if not dns_counter:
        success("DNS-запросов не найдено.")
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

    header("\n===== TCP FLAGS =====\n")

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

    header("\n===== SUSPICIOUS PORTS =====\n")

    if not port_counter:
        success("Подозрительные порты не обнаружены.")

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

    header("\n===== PORT SCAN DETECTION =====\n")

    suspicious = {}

    for (src_ip, dst_ip), ports in scans.items():

        if len(ports) >= 10:

            print(f"Источник: {src_ip}")
            print(f"Назначение: {dst_ip}")
            print(f"SYN на различных портов: {len(ports)}")
            print(f"Порты: {sorted(ports)}")
            warning("Возможен TCP SYN Port Scan\n")

            suspicious[f"{src_ip} -> {dst_ip}"] = {
                "unique_ports": len(ports),
                "ports": sorted(ports)
            }

    if not suspicious:
        success("Признаков TCP SYN Port Scan не обнаружено.")

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

    header("\n===== DNS FLOOD DETECTION =====\n")

    suspicious = {}

    THRESHOLD = 100

    for ip, count in dns_counter.items():

        if count >= THRESHOLD:

            print(f"Источник: {ip}")
            print(f"DNS-запросов: {count}")
            warning("Возможен DNS Flood\n")

            suspicious[ip] = count

    if not suspicious:
        success("Признаков DNS Flood не обнаружено.")

    return suspicious


def syn_flood_detection(packets):
    """
    Обнаруживает возможный TCP SYN Flood.
    """

    syn_counter = Counter()
    ack_counter = Counter()

    for packet in packets:

        if (
            packet.haslayer(IP)
            and packet.haslayer(TCP)
        ):

            src_ip = packet[IP].src
            flags = packet.sprintf("%TCP.flags%")

            if flags == "S":
                syn_counter[src_ip] += 1

            elif flags == "A":
                ack_counter[src_ip] += 1

    header("\n===== SYN FLOOD DETECTION =====\n")

    suspicious = {}

    SYN_THRESHOLD = 100
    RATIO = 5

    for ip, syn_count in syn_counter.items():

        ack_count = ack_counter.get(ip, 0)

        if (
            syn_count >= SYN_THRESHOLD
            and syn_count > ack_count * RATIO
        ):

            print(f"Источник: {ip}")
            print(f"SYN: {syn_count}")
            print(f"ACK: {ack_count}")
            danger("Обнаружены признаки TCP SYN Flood\n")

            suspicious[ip] = {
                "syn": syn_count,
                "ack": ack_count
            }

    if not suspicious:
        success("Признаков TCP SYN Flood не обнаружено.")

    return suspicious


def main():

    args = parse_arguments()

    global USE_COLOR
    USE_COLOR = not args.no_color
    
    pcap_path = Path(args.file)
    packets = read_pcap(pcap_path)

    success(f"Файл успешно открыт: {pcap_path}")
    info(f"Всего пакетов: {len(packets)}")

    packet_stats = packet_statistics(packets)
    ip_stats = ip_statistics(packets)
    port_stats = port_statistics(packets)
    dns_stats = dns_statistics(packets)
    tcp_flags = tcp_flag_statistics(packets)
    suspicious_ports = suspicious_port_statistics(packets)
    port_scan = port_scan_detection(packets)
    dns_flood = dns_flood_detection(packets)
    syn_flood = syn_flood_detection(packets)

    report = {
        "pcap_file": str(pcap_path),
        "total_packets": len(packets),

        "packet_statistics": packet_stats,
        "ip_statistics": ip_stats,
        "port_statistics": port_stats,
        "dns_statistics": dns_stats,
        "tcp_flags": tcp_flags,

        "suspicious_ports": suspicious_ports,
        "port_scan_detection": port_scan,
        "dns_flood_detection": dns_flood,
        "syn_flood_detection": syn_flood,
    }

    REPORT_PATH = Path(args.json)
    export_report(report, REPORT_PATH)


if __name__ == "__main__":
    main()