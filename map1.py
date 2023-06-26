import networkx as nx
from scapy.all import ARP, Ether, srp
import matplotlib.pyplot as plt
import socket
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib
matplotlib.use('TkAgg')


COMMON_PORTS = [80, 443, 22, 23, 25, 53, 67, 68, 110, 143, 161, 162, 389, 443, 514, 636, 1080, 1194, 1701, 1723, 3306, 3389, 5432, 5900, 8080]

def scan_network(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        device = {'ip': received.psrc, 'ports': []}
        try:
            for port in COMMON_PORTS:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((device['ip'], port))
                    if result == 0:
                        device['ports'].append(port)
        except KeyboardInterrupt:
            print("Scanning interrupted by user.")
        devices.append(device)

    return devices

def network_map(ip_address):
    devices = scan_network(ip_address)
    
    G = nx.Graph()

    for device in devices:
        ip_address = device.get('ip')
        name = socket.getfqdn(ip_address)
        ports = device.get('ports', [])
        label = f"Name: {name}\nIP: {ip_address}\nPorts: {', '.join(map(str, ports))}"
        G.add_node(ip_address, label=label)

        for neighbor in ports:
            G.add_edge(ip_address, str(neighbor), weight=1)

    pos = nx.spring_layout(G)
    nx.draw_networkx_nodes(G, pos, node_size=500)
    nx.draw_networkx_edges(G, pos, edgelist=G.edges(), edge_color='gray', width=[d['weight'] for (u, v, d) in G.edges(data=True)])
    nx.draw_networkx_labels(G, pos, nx.get_node_attributes(G,'label'), font_size=10)
    plt.show()

def get_device_info(ip_address):
    devices = scan_network(ip_address)
    open_ports = []
    
    for device in devices:
        if device['ip'] == ip_address:
            open_ports = device['ports']
            break
    
    return open_ports

root = tk.Tk()
root.geometry("600x500")
root.title("Network Scanner")

tab_control = ttk.Notebook(root)
tab1 = ttk.Frame(tab_control)
tab2 = ttk.Frame(tab_control)

tab_control.add(tab1, text='Map')
tab_control.add(tab2, text='Devices and Open Ports')

input_label = tk.Label(tab1, text="Enter IP address or network range to scan:")
input_label.pack()

input_field = tk.Entry(tab1)
input_field.pack()

scan_button = tk.Button(tab1, text="Scan Network", command=lambda: network_map(input_field.get()))
scan_button.pack()

map_frame = tk.Frame(tab1)
map_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

canvas = plt.gcf().canvas
canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

devices_label = tk.Label(tab2, text="Devices:")
devices_label.pack()

box = tk.Frame(tab2)
box.pack(expand=True, fill=tk.BOTH)

device_list_scroller = tk.Scrollbar(box, orient=tk.VERTICAL)
device_list_scroller.pack(side=tk.RIGHT, fill=tk.Y)

device_list = tk.Listbox(box, yscrollcommand=device_list_scroller.set)
device_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
device_list_scroller.config(command=device_list.yview)

ports_label = tk.Label(tab2, text="Open Ports:")
ports_label.pack()

device_list_ports = tk.Listbox(tab2)
device_list_ports.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

get_port_button = tk.Button(tab2, text="Get Port Info", command=lambda: device_list_ports.insert(tk.END, str(get_device_info(device_list.get(device_list.curselection()[0]).split()[0]))))
get_port_button.pack()

root.bind("<Return>", lambda event: network_map(input_field.get()))

tab_control.pack(expand=1, fill='both')

plt.ion()

root.mainloop()