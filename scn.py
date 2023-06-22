import networkx as nx
from scapy.all import ARP, Ether, srp
import matplotlib.pyplot as plt
import socket
import threading
from tqdm import tqdm
import time


COMMON_PORTS = [80, 443, 22, 23, 25, 53, 67, 68, 110, 143, 161, 162, 389, 443, 514, 636, 1080, 1194, 1701, 1723, 3306, 3389, 5432, 5900, 8080]

def scan_network(ip_address):
    devices = []
    arp_request = ARP(pdst=ip_address)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp_request
    result = srp(packet, timeout=3, verbose=0)[0]

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    print(f"Сканирование сети {ip_address} завершено. Найдено устройств: {len(devices)}")

    return devices

def create_network_graph(devices):
    G = nx.Graph()
    labels = {}
    for device in devices:
        ip_address = device.get('ip')
        mac_address = device.get('mac')
        if mac_address is not None:
            labels[ip_address] = f"{ip_address}\n{mac_address}"
        else:
            labels[ip_address] = f"{ip_address}"
        G.add_node(ip_address)
    return G, labels
def add_connections_to_graph(G, devices):
    threads = []
    for device in devices:
        ip_address = device['ip']
        thread = threading.Thread(target=scan_open_ports, args=(G, ip_address,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

def scan_open_ports(G, ip_address):
    open_ports = []
    try:
        for port in COMMON_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
    except KeyboardInterrupt:
        print("Сканирование открытых портов было остановлено пользователем.")

    for neighbor in open_ports:
        G.add_edge(ip_address, neighbor)

def create_network_map(ip_address):
    # Сканирование сети и получение списка устройств
    devices = scan_network(ip_address)

    # Создание графа сети
    G, labels = create_network_graph(devices)

    # Добавление соединений между устройствами на граф
    add_connections_to_graph(G, devices)

    # Визуализация графа
    pos = nx.spring_layout(G)
    nx.draw_networkx_nodes(G, pos, node_size=500)
    nx.draw_networkx_edges(G, pos, alpha=0.3)
    nx.draw_networkx_labels(G, pos, labels, font_size=10)
    plt.show()

if __name__ == '__main__':
    start_time = time.time()
    #Реализовать выбор/ввод/получение данных из файла изначального сканирования
    # И производить построение карты по данным полученным из файла сканирования, а не сканировать заново 
    # ip_address = '192.168.0.0/24' and int(input("Enter the ip and mask(example: 192.168.0.0/24): "))
    # ip_address = input("Enter the ip and mask(example: 192.168.0.0/24): ")
    ip_address = '192.168.0.0/24'
    create_network_map(ip_address)
    end_time = time.time()
    print(f"Время выполнения скрипта: {end_time - start_time} секунд")