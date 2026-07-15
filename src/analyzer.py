from pathlib import Path
from scapy.all import rdpcap


PCAP_PATH = Path("pcaps/sample.pcapng")


def read_pcap(path: Path):
    """
    Читает PCAP-файл и возвращает список пакетов.
    """

    packets = rdpcap(str(path))

    return packets


def main():

    packets = read_pcap(PCAP_PATH)

    print(f"Файл успешно открыт: {PCAP_PATH}")
    print(f"Всего пакетов: {len(packets)}")


if __name__ == "__main__":
    main()