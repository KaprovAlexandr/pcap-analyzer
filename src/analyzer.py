from pathlib import Path
from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from collections import Counter


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



def main():

    packets = read_pcap(PCAP_PATH)

    print(f"Файл успешно открыт: {PCAP_PATH}")
    print(f"Всего пакетов: {len(packets)}")

    packet_statistics(packets)


if __name__ == "__main__":
    main()