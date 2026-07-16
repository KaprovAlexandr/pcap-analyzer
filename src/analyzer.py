from pathlib import Path
from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from collections import Counter
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



def main():

    packets = read_pcap(PCAP_PATH)

    print(f"Файл успешно открыт: {PCAP_PATH}")
    print(f"Всего пакетов: {len(packets)}")

    packet_statistics(packets)
    ip_statistics(packets)


if __name__ == "__main__":
    main()