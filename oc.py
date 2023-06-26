import platform
import socket
import tkinter as tk
from tkinter import ttk

class NetworkScanner:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Информация о хостах")

        
        subnet_frame = tk.Frame(self.window)
        subnet_frame.pack(side=tk.TOP, fill=tk.X)

        subnet_label = tk.Label(subnet_frame, text="Введите подсеть:")
        subnet_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.subnet_entry = tk.Entry(subnet_frame)
        self.subnet_entry.pack(side=tk.LEFT, padx=5, pady=5)

      
        self.table_frame = tk.Frame(self.window)
        self.table_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        columns = ("Хост", "Операционная система", "Версия операционной системы", "Процессор")
        self.table_widget = ttk.Treeview(self.table_frame, columns=columns, show='headings')
        self.table_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(self.table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.table_widget.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.table_widget.yview)

        for col in columns:
            self.table_widget.heading(col, text=col)

        button_frame = tk.Frame(self.window)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X)

        scan_button = tk.Button(button_frame, text="Сканировать", command=self.scan_network)
        scan_button.pack(side=tk.RIGHT)


        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.window, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def scan_network(self):

        subnet = self.subnet_entry.get()


        for item in self.table_widget.get_children():
            self.table_widget.delete(item)


        num_hosts = 255
        for i in range(1, num_hosts+1):
            ip_address = f"{subnet}.{i}"
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            except socket.herror:
                hostname = "unknown"


            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            result = s.connect_ex((ip_address, 80))
            s.close()

            if result == 0:
                os_name = platform.system()
                os_version = platform.version()
                processor_name = platform.processor()

                
                self.table_widget.insert("", tk.END, values=(f"{ip_address} ({hostname})", os_name, os_version, processor_name))

      
            progress = (i / num_hosts) * 100
            self.progress_var.set(progress)
            self.window.update_idletasks()

if __name__ == "__main__":
    NetworkScanner().window.mainloop()