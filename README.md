# PCAP Analyzer

## Цель

Автоматизация анализа сетевого трафика PCAP с целью выявления подозрительной активности

## Возможности

- Анализ общего количества пакетов
- Статистика по протоколам (TCP, UDP, ICMP, ARP, DNS)
- Статистика по IP-адресам
- Статистика по TCP/UDP портам
- Анализ DNS-запросов
- Анализ TCP-флагов
- Поиск обращений к потенциально опасным портам
- Обнаружение признаков TCP SYN Port Scan
- Обнаружение признаков DNS Flood
- Обнаружение признаков TCP SYN Flood
- Цветной вывод результатов в консоль
- Экспорт полного отчета в JSON
- Поддержка выбора PCAP-файла через CLI
- Поддержка выбора имени JSON-файла через CLI

## Стек / Инструменты

- Python 3
- Scapy
- Colorama
- JSON
- argparse
- Wireshark

## Как запустить

Установить зависимости:

```bash
pip install -r requirements.txt
```

Без цветного вывода:

```bash
python src/analyzer.py --no-color
```

Базовый запуск:

```bash
python src/analyzer.py
```

Указать PCAP-файл:

```bash
python src/analyzer.py -f pcaps/sample.pcapng
```

Указать имя JSON-файл:

```bash
python src/analyzer.py -j report.json
```

Справочная информация:

```bash
python src/analyzer.py --help
```

## Что я узнал

- Научился захватывать и анализировать сетевой трафик с помощью Wireshark и Scapy.
- Освоил методы обнаружения распространённых сетевых атак по признакам сетевого трафика (TCP SYN Port Scan, DNS Flood, TCP SYN Flood).
- Получил практический опыт обработки PCAP-файлов и работы с сетевыми протоколами (TCP, UDP, DNS, ICMP, ARP).

## Скриншоты / Результаты

### Терминал

![Terminal Output](/assets/terminal-output.png)

### JSON-файл

![JSON Report](/assets/json-report.png)
