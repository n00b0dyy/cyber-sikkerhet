
# soft wrapp
"""
## Basic Network Scanner
**Programming Language:** Python  
**Difficulty (1 to 10):** 4

This program provides a GUI-based network scanning tool using Tkinter. It allows users to scan a range of IP addresses, detect active devices, check open ports, gather device information, and export results to a CSV file. The program supports scanning for both TCP and UDP ports and can detect the operating system of the devices.

### Functions
- **setup_gui()**
    Initializes the graphical user interface, creating input fields for start and end IP addresses, ports, port range, and checkboxes for TCP/UDP. It also sets up buttons for starting the scan and exporting results.

- **scan_network()**
    Gathers user input, validates the IP range, and initiates the network scan by calling `scan_ip_range()`. It displays the results and re-enables the scan button upon completion.

- **validate_ip_range(start_ip, end_ip)**
    Validates the provided start and end IP addresses to ensure they form a valid range. Returns `True` if valid, otherwise shows an error message.

- **scan_ip_range(start_ip, end_ip, open_ports)**
    Scans the specified IP range for active devices. Checks open ports on each device and gathers additional information such as MAC address and operating system. Returns a list of active devices with their details.

- **is_device_active(ip)**
    Sends an ICMP echo request to check if a device is active. Returns `True` if the device responds, otherwise `False`.

- **check_open_ports(ip, ports, protocols)**
    Checks specified ports on a device for TCP/UDP protocols. Returns a list of open ports.

- **collect_device_info(ip, router_ip=None, router_user=None, router_password=None, snmp_community='public')**
    Collects MAC address and other device information using ARP, router SSH login, or SNMP. Returns a dictionary with the device's details.

- **get_mac_via_arp(ip)**
    Retrieves the MAC address of a device using an ARP request. Returns the MAC address or "Unknown" if not found.

- **get_mac_via_router(ip, router_ip, router_user, router_password)**
    Retrieves the MAC address from the router's ARP table via SSH. Returns the MAC address or "Unknown" if not found.

- **get_mac_via_snmp(ip, snmp_community)**
    Retrieves the MAC address using SNMP. Returns the MAC address or "Unknown" if not found.

- **get_response_time(ip)**
    Measures the response time of a device by sending an ICMP echo request. Returns the response time in milliseconds or "Timeout".

- **detect_os(ip)**
    Attempts to detect the operating system of a device using various methods such as HTTP headers, SMB, SSH, and TCP SYN responses. Returns the OS name or "Unknown".

- **get_os_via_smb(ip)**
    Retrieves the OS information via SMB. Returns the OS name or "Unknown".

- **get_os_via_ssh(ip, username, password)**
    Retrieves the OS information via SSH. Returns the OS name or "Unknown".

- **export_to_csv()**
    Exports the scanned results to a CSV file. Prompts the user to choose a file location and saves the data.

- **display_results(devices)**
    Displays the scanned results in the GUI text box.

### Usage
1. Enter the start and end IP addresses for the range to be scanned.
2. Optionally, specify ports or a port range for the scan.
3. Select whether to scan for TCP, UDP, or both.
4. Click the "Scan" button to start the network scan.
5. View the results in the "Results" section.
6. Optionally, click "Export to CSV" to save the results to a file.

### Dependencies
- **tkinter**: Python library for creating graphical user interfaces (GUIs).
- **scapy**: Python module for network packet manipulation and analysis.
sr1: Sends a packet and waits for the first response. It returns only the first packet that answers the sent packet.
srp: Sends and receives packets at the data link layer (Layer 2). It sends a packet and receives all responses, returning both the sent and received packets.
IP: Constructs and manipulates IP packets. It allows setting fields such as source and destination IP addresses, protocol type, and more.
ICMP: Constructs and manipulates ICMP packets. ICMP is used for sending error messages and operational information, commonly used with ping.
ARP: Constructs and manipulates ARP packets. ARP (Address Resolution Protocol) is used to map IP network addresses to the hardware addresses used by data link protocols.
Ether: Constructs and manipulates Ethernet frames. It allows setting fields such as source and destination MAC addresses and Ethernet type.
TCP: Constructs and manipulates TCP packets. It allows setting fields such as source and destination ports, sequence numbers, flags, and more.
UDP: Constructs and manipulates UDP packets. It allows setting fields such as source and destination ports and data payload.
- **socket**: Low-level networking interface for checking open ports.
- **csv**: Module for reading and writing CSV files.
- **datetime**: Module for handling dates and times.
- **platform**: Module for detecting the platform and OS.
- **ipaddress**: Module for validating and handling IP addresses.
- **logging**: Module for generating log files.
- **threading**: Module for concurrent execution using threads.
- **paramiko**: Python module for handling SSH connections.
- **pysnmp**: Python module for SNMP operations.
- **requests**: Module for HTTP requests.
- **impacket.smb**: Module for SMB protocol operations.
"""


import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import sr1, srp, IP, ICMP, ARP, Ether, TCP, UDP 
import socket
import csv
import datetime
import platform
import ipaddress
import logging
import threading
import paramiko
from pysnmp.hlapi import *
import requests
from impacket.smb import SMB 

class NetworkScannerApp:
    def __init__(self, root):
        """
        Initializes the NetworkScannerApp class. This method sets up the root window,
        configures logging, and sets up the graphical user interface (GUI).

        Parameters:
        root (tk.Tk): The root window of the Tkinter application.
        """
        self.root = root
        self.root.title("Basic Network Scanner")
        self.scan_button = None  # Placeholder for the scan button, initialized in setup_gui
        self.logger = logging.getLogger("network_scanner")
        self.logger.setLevel(logging.ERROR)
        
        # Set up logging to a file
        file_handler = logging.FileHandler("network_scanner.log")
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)
        
        # Set up the GUI
        self.setup_gui()

    def setup_gui(self):
        """
        Sets up the graphical user interface (GUI) for the network scanner application.
        It creates and places input fields, buttons, and other widgets in the window.
        """
        input_frame = ttk.LabelFrame(self.root, text="Input")
        input_frame.grid(column=0, row=0, padx=10, pady=10)
        
        # Labels and entry fields for IP range and ports
        ttk.Label(input_frame, text="Start IP:").grid(column=0, row=0, sticky=tk.W)
        self.start_ip_entry = ttk.Entry(input_frame, width=15)
        self.start_ip_entry.grid(column=1, row=0, padx=5, pady=5)
        
        ttk.Label(input_frame, text="End IP:").grid(column=0, row=1, sticky=tk.W)
        self.end_ip_entry = ttk.Entry(input_frame, width=15)
        self.end_ip_entry.grid(column=1, row=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Ports (comma separated):").grid(column=0, row=2, sticky=tk.W)
        self.port_entry = ttk.Entry(input_frame, width=25)
        self.port_entry.grid(column=1, row=2, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Port Range:").grid(column=0, row=3, sticky=tk.W)
        ttk.Label(input_frame, text="from").grid(column=0, row=3, sticky=tk.E)
        self.port_range_start_entry = ttk.Entry(input_frame, width=10)
        self.port_range_start_entry.grid(column=1, row=3, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(input_frame, text="to").grid(column=2, row=3, sticky=tk.E)
        self.port_range_end_entry = ttk.Entry(input_frame, width=10)
        self.port_range_end_entry.grid(column=1, row=3, padx=5, pady=5, sticky=tk.E)
        
        # Checkboxes for selecting TCP and UDP protocols
        self.tcp_var = tk.BooleanVar()
        self.tcp_var.set(True)
        self.tcp_checkbox = ttk.Checkbutton(input_frame, text="TCP", variable=self.tcp_var)
        self.tcp_checkbox.grid(column=1, row=4, sticky=tk.W)
        
        self.udp_var = tk.BooleanVar()
        self.udp_var.set(False)
        self.udp_checkbox = ttk.Checkbutton(input_frame, text="UDP", variable=self.udp_var)
        self.udp_checkbox.grid(column=1, row=4, sticky=tk.E)
        
        # Button to start the scan
        self.scan_button = ttk.Button(input_frame, text="Scan", command=lambda: self.scan_network())
        self.scan_button.grid(column=0, row=5, columnspan=4, pady=10)
        
        # Button to export results to CSV
        export_button = ttk.Button(input_frame, text="Export to CSV", command=self.export_to_csv)
        export_button.grid(column=0, row=6, columnspan=4, pady=10)
        
        # Frame and text box to display scan results
        result_frame = ttk.LabelFrame(self.root, text="Results")
        result_frame.grid(column=0, row=1, padx=10, pady=10)
        self.result_text = tk.Text(result_frame, width=80, height=20)
        self.result_text.grid(column=0, row=0, padx=5, pady=5)

    def scan_network(self):
        """
        Initiates the network scan based on user input. This method validates the input,
        disables the scan button, and calls methods to scan the IP range and display results.
        """
        start_ip = self.start_ip_entry.get()  # Get start IP address from input field
        end_ip = self.end_ip_entry.get()  # Get end IP address from input field
        ports = []
        
        # Determine the ports to scan based on user input
        if self.port_entry.get():
            ports = [int(portx.strip()) for portx in self.port_entry.get().split(',')]
        elif self.port_range_start_entry.get() and self.port_range_end_entry.get():
            ports = list(range(int(self.port_range_start_entry.get()), int(self.port_range_end_entry.get()) + 1))
        
        # Validate the IP range
        if not self.validate_ip_range(start_ip, end_ip):
            messagebox.showerror("Invalid IP Range", "Please enter a valid IP range.")
            return
        
        # Disable the scan button during the scan
        if self.scan_button:
            self.scan_button.config(state=tk.DISABLED)
        
        # Scan the IP range and display results
        active_devices = self.scan_ip_range(start_ip, end_ip, ports)
        self.display_results(active_devices)
        
        # Re-enable the scan button after the scan
        if self.scan_button:
            self.scan_button.config(state=tk.NORMAL)

    def validate_ip_range(self, start_ip, end_ip):
        """
        Validates the provided IP range to ensure it is in the correct format and logical order.

        Parameters:
        start_ip (str): The starting IP address.
        end_ip (str): The ending IP address.

        Returns:
        bool: True if the IP range is valid, False otherwise.
        """
        try:
            if not start_ip or not end_ip:
                messagebox.showerror("Missing IP Address", "Please provide both start and end IP addresses.")
                return False
            
            start_ip_obj = ipaddress.ip_address(start_ip)
            end_ip_obj = ipaddress.ip_address(end_ip)
            
            if start_ip_obj > end_ip_obj:
                messagebox.showerror("Invalid IP Range", "Start IP address cannot be greater than end IP address.")
                return False
            
            return True
        except ValueError:
            messagebox.showerror("Invalid IP Address", "Please provide valid IPv4 addresses.")
            return False

    def scan_ip_range(self, start_ip, end_ip, open_ports):
        """
        Scans the range of IP addresses for active devices and checks for open ports.

        Parameters:
        start_ip (str): The starting IP address.
        end_ip (str): The ending IP address.
        open_ports (list): A list of ports to check on each device.

        Returns:
        list: A list of dictionaries containing information about active devices.
        """
        active_devices = []
        start = list(map(int, start_ip.split('.')))
        end = list(map(int, end_ip.split('.')))
        protocols = []
        
        # Determine which protocols (TCP/UDP) to scan based on user selection
        if self.tcp_var.get():
            protocols.append(TCP)
        if self.udp_var.get():
            protocols.append(UDP)
        
        def scan_ip(ip):
            """
            Scans a single IP address for activity and open ports, then collects device information.

            Parameters:
            ip (str): The IP address to scan.
            """
            try:
                if self.is_device_active(ip):
                    open_ports_info = self.check_open_ports(ip, open_ports, protocols)
                    device_info = self.collect_device_info(ip, 'router_ip', 'router_user', 'router_password')  # Replace with actual credentials
                    response_time = self.get_response_time(ip)
                    
                    if response_time:
                        device_info['Response Time'] = response_time
                    else:
                        device_info['Response Time'] = "Timeout"
                    
                    device_info['OS'] = self.detect_os(ip)
                    device_info['Open Ports'] = open_ports_info
                    active_devices.append(device_info)
            except Exception as e:
                self.logger.error(f"An error occurred while scanning {ip}: {str(e)}")
        
        threads = []
        
        # Create a thread for each IP address in the range and start scanning
        for i in range(start[3], end[3] + 1):
            ip = f"{start[0]}.{start[1]}.{start[2]}.{i}"
            thread = threading.Thread(target=scan_ip, args=(ip,))
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
        
        return active_devices

    def is_device_active(self, ip):
        """
        Checks if a device is active at the given IP address using an ICMP ping.

        Parameters:
        ip (str): The IP address to check.

        Returns:
        bool: True if the device is active, False otherwise.
        """
        try:
            icmp = IP(dst=ip) / ICMP()
            resp = sr1(icmp, timeout=1, verbose=False)  # Send ICMP packet and wait for a response
            if resp:
                return True
            else:
                return False
        except Exception as e:
            raise Exception("Error occurred while checking device: {}".format(str(e)))

    def check_open_ports(self, ip, ports, protocols):
        """
        Checks open ports on a given IP address using specified protocols.

        Parameters:
            ip (str): The IP address to check.
            ports (list): A list of ports to check.
            protocols (list): A list of protocols to use for checking.

        Returns:
            list: A list of tuples containing open ports and their respective protocols.
        """
        open_ports = []
        for port in ports:
            for protocol in protocols:
                try:
                    # Create a socket using the given protocol
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)  # Set a timeout for the socket
                        if sock.connect_ex((ip, port)) == 0:  # Check if the port is open
                            open_ports.append((port, protocol.__name__))  # Append open port and protocol name
                except Exception as e:
                    self.logger.error(f"An error occurred while checking port {port} on {ip}: {str(e)}")
        return open_ports


    def collect_device_info(self, ip, router_ip=None, router_user=None, router_password=None, snmp_community='public'):
        """
        Collects device information including IP address and MAC address.

        Parameters:
            ip (str): The IP address of the device.
            router_ip (str, optional): The IP address of the router.
            router_user (str, optional): The username for the router.
            router_password (str, optional): The password for the router.
            snmp_community (str, optional): The SNMP community string. Default is 'public'.

        Returns:
            dict: A dictionary containing IP address and MAC address.
        """
        mac_address = self.get_mac_via_arp(ip)

        if mac_address == "Unknown" and router_ip and router_user and router_password:
            mac_address = self.get_mac_via_router(ip, router_ip, router_user, router_password)

        if mac_address == "Unknown":
            mac_address = self.get_mac_via_snmp(ip, snmp_community)

        return {"IP Address": ip, "MAC Address": mac_address}


    def get_mac_via_arp(self, ip):
        """
        Retrieves the MAC address of a device using ARP.

        Parameters:
            ip (str): The IP address of the device.

        Returns:
            str: The MAC address of the device, or "Unknown" if not found.
        """
        try:
            # Sending ARP request to get MAC address
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc if answered_list else "Unknown"
        except Exception as e:
            self.logger.error(f"An error occurred while sending ARP request: {str(e)}")
            return "Unknown"


    def get_mac_via_router(self, ip, router_ip, router_user, router_password):
        """
        Retrieves the MAC address of a device via router using SSH.

        Parameters:
            ip (str): The IP address of the device.
            router_ip (str): The IP address of the router.
            router_user (str): The username for the router.
            router_password (str): The password for the router.

        Returns:
            str: The MAC address of the device, or "Unknown" if not found.
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(router_ip, username=router_user, password=router_password)
            stdin, stdout, stderr = ssh.exec_command(f"arp -a {ip}")
            output = stdout.read().decode()
            ssh.close()

            for line in output.split('\n'):
                if ip in line:
                    mac_address = line.split()[1]
                    return mac_address
        except Exception as e:
            self.logger.error(f"An error occurred while retrieving MAC address from router: {str(e)}")

        return "Unknown"


    def get_mac_via_snmp(self, ip, snmp_community):
        """
        Retrieves the MAC address of a device via SNMP.

        Parameters:
            ip (str): The IP address of the device.
            snmp_community (str): The SNMP community string.

        Returns:
            str: The MAC address of the device, or "Unknown" if not found.
        """
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(snmp_community, mpModel=0),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.6'))  # OID for MAC address
            )

            error_indication, error_status, error_index, var_binds = next(iterator)

            if error_indication:
                self.logger.error(f"SNMP error: {error_indication}")
            elif error_status:
                self.logger.error(f'SNMP error: {error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1][0] or "?"}')
            else:
                for var_bind in var_binds:
                    mac_address = ':'.join(['%02x' % b for b in var_bind[1].asOctets()])
                    return mac_address
        except Exception as e:
            self.logger.error(f"An error occurred while retrieving MAC address via SNMP: {str(e)}")

        return "Unknown"


    def get_response_time(self, ip):
        """
        Retrieves the response time of a device using ICMP (ping).

        Parameters:
            ip (str): The IP address of the device.

        Returns:
            str: The response time in milliseconds, or "Timeout" if no response.
        """
        icmp = IP(dst=ip) / ICMP()
        start_time = datetime.datetime.now()  # Record the start time
        resp = sr1(icmp, timeout=1, verbose=False)  # Send the ICMP packet
        end_time = datetime.datetime.now()  # Record the end time
        if resp:
            response_time = (end_time - start_time).total_seconds() * 1000  # Calculate response time in ms
            return f"{response_time:.2f} ms"
        else:
            return "Timeout"


    def detect_os(self, ip):
        """
        Detects the operating system of a device.

        Parameters:
            ip (str): The IP address of the device.

        Returns:
            str: The detected operating system, or "Unknown" if not detected.
        """
        try:
            os_info = self.get_os_via_http(f"http://{ip}")
            if os_info and os_info != "Unknown":
                return os_info

            os_info = self.get_os_via_smb(ip)
            if os_info and os_info != "Unknown":
                return os_info

            os_info = self.get_os_via_ssh(ip, 'user', 'password')
            if os_info and os_info != "Unknown":
                return os_info

            # SYN scan to detect the OS
            syn_request = IP(dst=ip) / TCP(dport=80, flags="S")
            response = sr1(syn_request, timeout=1, verbose=False)
            if response:
                if response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:
                        return "Linux"
                    elif response.getlayer(TCP).flags == 0x14:
                        return "Windows"
                    elif response.getlayer(TCP).flags == 0x10:
                        return "macOS"
                    else:
                        return "Unix-like"
            return "Unknown"
        except Exception as e:
            self.logger.error(f"An error occurred while detecting OS for {ip}: {str(e)}")
            return "Detection Error"


    def get_os_via_smb(self, ip):
        """
        Retrieves the operating system of a device via SMB.

        Parameters:
            ip (str): The IP address of the device.

        Returns:
            str: The operating system, or "Unknown" if not detected.
        """
        try:
            smb = SMB(ip, ip)
            smb.login('', '')
            os_info = smb.get_server_os()
            return os_info
        except Exception as e:
            self.logger.error(f"SMB error: {str(e)}")
            return "Unknown"


    def get_os_via_ssh(self, ip, username, password):
        """
        Retrieves the operating system of a device via SSH.

        Parameters:
            ip (str): The IP address of the device.
            username (str): The username for SSH login.
            password (str): The password for SSH login.

        Returns:
            str: The operating system, or "Unknown" if not detected.
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password)
            stdin, stdout, stderr = ssh.exec_command('uname -a')
            os_info = stdout.read().decode()
            ssh.close()
            return os_info
        except Exception as e:
            self.logger.error(f"SSH error: {str(e)}")
            return "Unknown"


    def export_to_csv(self):
        """
        Exports device information to a CSV file.

        Opens a file dialog to select the save location and writes the device information to a CSV file.

        Returns:
            None
        """
        devices = self.result_text.get("1.0", tk.END).strip().split('\n\n')
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not filename:
            return
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP Address", "MAC Address", "Response Time", "OS", "Open Ports"])
            for device in devices:
                device_info = dict(item.split(': ', 1) for item in device.split('\n'))
                writer.writerow([
                    device_info.get("IP Address"),
                    device_info.get("MAC Address"),
                    device_info.get("Response Time"),
                    device_info.get("OS"),
                    device_info.get("Open Ports")
                ])


    def display_results(self, devices):
        """
        Displays the scanned device results in the result text widget.

        Parameters:
            devices (list): A list of dictionaries containing device information.

        Returns:
            None
        """
        self.result_text.delete(1.0, tk.END)
        for device in devices:
            self.result_text.insert(tk.END, f"IP Address: {device['IP Address']}\nMAC Address: {device['MAC Address']}\nResponse Time: {device['Response Time']}\nOS: {device['OS']}\nOpen Ports: {', '.join(f'{port} ({protocol})' for port, protocol in device['Open Ports'])}\n\n")
        self.result_text.configure(state="disabled")

root = tk.Tk()
app = NetworkScannerApp(root)
root.mainloop()
