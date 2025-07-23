import colorama
from colorama import Fore, Style
import os
import socket
import pyshark
from pyshark.capture.live_capture import get_tshark_interfaces
from scapy.arch.windows import get_windows_if_list
import time
import subprocess
import platform
import re
import json

colorama.init(autoreset=True)
class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL

class Styles:
    BOLD = Style.BRIGHT
    DIM = Style.DIM
    NORMAL = Style.NORMAL

with open('mac_vendors.json') as f:
    mac_vendor_table = json.load(f)

banner = r"""

 /$$                           /$$      /$$                    
| $$                          | $$$    /$$$                    
| $$        /$$$$$$   /$$$$$$$| $$$$  /$$$$  /$$$$$$   /$$$$$$ 
| $$       /$$__  $$ /$$_____/| $$ $$/$$ $$ |____  $$ /$$__  $$
| $$      | $$  \ $$| $$      | $$  $$$| $$  /$$$$$$$| $$  \ $$
| $$      | $$  | $$| $$      | $$\  $ | $$ /$$__  $$| $$  | $$
| $$$$$$$$|  $$$$$$/|  $$$$$$$| $$ \/  | $$|  $$$$$$$| $$$$$$$/
|________/ \______/  \_______/|__/     |__/ \_______/| $$____/ 
                                                     | $$      
                                                     | $$      
                                                     |__/      
                    By: Seekuh and BlackyEz
"""

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except Exception as e:
        return f"Error retrieving local IP: {e}"
    
def get_interface_list():
    try:
        interfaces = get_windows_if_list()
        if not interfaces:
            return []
        return [iface for iface in interfaces]
    except Exception as e:
        print(Colors.RED + f"Error retrieving interfaces: {e}" + Colors.RESET)
        return []

def ping_ip(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    os.system(f"ping {param} 1 {ip} >nul 2>&1" if param == '-n' else f"ping {param} 1 {ip} >/dev/null 2>&1")

def sniff(interface, duration, flags):
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(duration)
    for packet in capture:
        print(packet)


def sniff_continous(interface, flags):
    comm_counts = {}  # For -cm flag

    if not flags:
        print(Colors.RED + "No flags specified. Using default settings." + Colors.RESET)
        print(Colors.YELLOW + "Starting default source to destination continuous sniffing. Press Ctrl+C to stop." + Colors.RESET)
        capture = pyshark.LiveCapture(interface=interface)
        try:
            capture.sniff_continuously(10)
            for packet in capture:
                if 'IP' in packet:
                    src_ip = packet.ip.src if hasattr(packet.ip, 'src') else 'N/A'
                    dst_ip = packet.ip.dst if hasattr(packet.ip, 'dst') else 'N/A'
                    print(f"Source: {src_ip}, Destination: {dst_ip}")
        except KeyboardInterrupt:
            print(Colors.RED + "Sniffing stopped." + Colors.RESET)
        except Exception as e:
            print(Colors.RED + f"Error during sniffing: {e}" + Colors.RESET)

    elif flags.lower() in ["-v", "--verbose"]:
        print(Colors.YELLOW + "Verbose mode enabled. Displaying detailed packet information." + Colors.RESET)
        capture = pyshark.LiveCapture(interface=interface)
        print(Colors.YELLOW + "Starting verbose continuous sniffing. Press Ctrl+C to stop." + Colors.RESET)
        try:
            capture.sniff_continuously(10)
            for packet in capture:
                print(packet)
        except KeyboardInterrupt:
            print(Colors.RED + "Sniffing stopped." + Colors.RESET)
        except Exception as e:
            print(Colors.RED + f"Error during sniffing: {e}" + Colors.RESET)

    elif flags.lower() in ["-cm", "--commap", "-cmap"]:
        print(Colors.YELLOW + "Starting continuous sniffing with communication map. Press Ctrl+C to stop." + Colors.RESET)
        capture = pyshark.LiveCapture(interface=interface)
        try:
            last_update = time.time()
            capture.sniff_continuously(10)
            for packet in capture:
                if 'IP' in packet:
                    src_ip = packet.ip.src if hasattr(packet.ip, 'src') else 'N/A'
                    dst_ip = packet.ip.dst if hasattr(packet.ip, 'dst') else 'N/A'
                    comm_pair = (src_ip, dst_ip)
                    comm_counts[comm_pair] = comm_counts.get(comm_pair, 0) + 1

                # Refresh the map every 0.5 seconds
                if time.time() - last_update > 0.5:
                    os.system('cls' if os.name == 'nt' else 'clear')
                    print(Colors.CYAN + "Current Communication Map:" + Colors.RESET)
                    for (src, dst), count in comm_counts.items():
                        print(f"{src} <-----------------------> {dst}: {count} times")
                    last_update = time.time()

        except KeyboardInterrupt:
            print(Colors.RED + "Sniffing stopped." + Colors.RESET)
        except Exception as e:
            print(Colors.RED + f"Error during sniffing: {e}" + Colors.RESET)

                        

        except KeyboardInterrupt:
            print(Colors.RED + "Sniffing stopped." + Colors.RESET)
        except Exception as e:
            print(Colors.RED + f"Error during sniffing: {e}" + Colors.RESET)

def ensure_arp(ip):
    if os.name == 'nt':
        os.system(f"ping -n 1 {ip} >nul")
    else:
        os.system(f"ping -c 1 {ip} >/dev/null 2>&1")
def get_mac(ip):

    try:
        # Make sure the IP is in the ARP cache
        os.system(f"ping -n 1 {ip} >nul") if os.name == 'nt' else os.system(f"ping -c 1 {ip} >/dev/null 2>&1")

        # Run arp -a and decode output
        output = subprocess.check_output(["arp", "-a"], encoding="utf-8", errors="ignore")

        # Search for the matching line
        for line in output.splitlines():
            if ip in line:
                # Match MAC address in format XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX
                match = re.search(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}", line)
                if match:
                    mac = match.group(0).replace("-", ":").lower()
                    return mac
        return None
    except Exception as e:
        print(f"Error getting MAC: {e}")
        return None

def lookup_mac_vendor(mac):
    oui = ":".join(mac.lower().split(":")[:3])
    return mac_vendor_table.get(oui, "Unknown Vendor")
def Recon(target, flags):
    if not flags:
        print(Colors.RED + "No flags specified. Using default settings." + Colors.RESET)

        # Ping to check reachability
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        null_dev = 'nul' if platform.system().lower() == 'windows' else '/dev/null'
        ping_result = os.system(f"ping {param} 1 {target} >{null_dev} 2>&1")
        if ping_result == 0:
            print(Colors.GREEN + f"{target} is reachable." + Colors.RESET)
        else:
            print(Colors.RED + f"{target} is not reachable." + Colors.RESET)

        # Ping again to populate ARP cache before MAC lookup
        ping_ip(target)

        mac = get_mac(target)
        print(f"DEBUG: mac = {mac!r}")
        if mac:
            vendor = lookup_mac_vendor(mac)
            print(Colors.YELLOW + f"MAC Address: {mac}, Vendor: {vendor}" + Colors.RESET)
        else:
            print("MAC address not found.")
        


if __name__ == "__main__":
    print(Colors.RED + banner + Colors.RESET)
    print(Colors.YELLOW + "Enter a command below (type \"help\" for a list of commands):" + Colors.RESET)
    while True:
        command = input(Colors.MAGENTA + ">>>" + Colors.RESET)
        parts = command.lower().split()
        if command.lower() == "help":
            print(Colors.MAGENTA + "Available commands:" + Colors.RESET)
            print("- help: Show this list of commands.\n- exit: Exit LocMap.\n- clear/cls: Clear the terminal.\n- version: Show the current version of LocMap.\n- localip/locip: Show your local IP adress.\n- sniff <interface> <duration> <flags>: Start sniffing on the specified interface for the given duration with optional flags.\n- continous_sniff/csniff <interface> <packets>: sniff for a given amount of packages.\n- recon <target> <flags>\n- interfaces: list all available interfaces." + Colors.RESET)

        elif command.lower() == "exit":
            print(Colors.RED + "Exiting LocMap. See you soon!" + Colors.RESET)

            break
        elif command.lower() == "clear" or command.lower() == "cls":
            os.system('cls' if
                 os.name == 'nt' else
                   'clear')
            print(Colors.RED + banner + Colors.RESET)
            print(Colors.YELLOW + "Enter a command below (type \"help\" for a list of commands):" + Colors.RESET)

        elif command.lower() == "version":
            print(Colors.CYAN + "LocMap Version 1.0.0" + Colors.RESET)

        elif command.lower() == "localip" or command.lower() == "locip":
            local_ip = get_local_ip()
            print(Colors.MAGENTA + f"Your local IP address is: {local_ip}" + Colors.RESET)

        elif command.lower().startswith("sniff") or command.lower().startswith("intercept"):
            # remove the command part and get arguments
            args = command.split()[1:]
            if not args:
                print(Colors.RED + "No interface specified. Usage: sniff <interface> <duration> <flags>" + Colors.RESET)
                continue
            interface = args[0]
            duration = int(args[1]) if len(args) > 1 and args[1].isdigit() else print(Colors.RED + "Invalid duration specified. Using default 10 seconds." + Colors.RESET) or 10
            flags = " ".join(args[1:]) if len(args) > 1 else ""
            sniff(interface, duration, flags)

        elif command.lower().startswith("continous_sniff") or command.lower().startswith("csniff"):
            args = command.split()[1:]
            if not args:
                print(Colors.RED + "No interface specified. Usage: sniff_continous <interface> <packets>" + Colors.RESET)
                continue
            interface = args[0]
            flags = " ".join(args[1:]) if len(args) > 1 else ""
            sniff_continous(interface, flags)

        elif command.lower().startswith("recon"):
            args = command.split()[1:]
            if not args:
                print(Colors.RED + "No target specified. Usage: recon <target> <flags>" + Colors.RESET)
                continue
            target = args[0]
            flags = " ".join(args[1:]) if len(args) > 1 else ""

            # Ensure ping
            os.system(f"ping -n 1 {target} >nul") if os.name == 'nt' else os.system(f"ping -c 1 {target} >/dev/null 2>&1")

            if os.system(f"ping -n 1 {target} >nul") == 0 if os.name == 'nt' else os.system(f"ping -c 1 {target} >/dev/null 2>&1") == 0:
                print(Colors.GREEN + f"{target} is reachable." + Colors.RESET)
            else:
                print(Colors.RED + f"{target} is not reachable." + Colors.RESET)

            mac = get_mac(target)

            if mac:
                vendor = lookup_mac_vendor(mac)
                print(Colors.YELLOW + f"MAC Address: {mac}, Vendor: {vendor}" + Colors.RESET)
            else:
                print(Colors.RED + "MAC address not found." + Colors.RESET)
        elif command.lower().startswith("interfaces") or command.lower().startswith("ifaces"):
            args = command.split()[1:]
            interfaces = get_interface_list()
            flags = " ".join(args) if args else ""
            if not flags:
                print(Colors.YELLOW + "No flags specified. Using default settings." + Colors.RESET)
                if interfaces:
                    print(Colors.GREEN + "Available interfaces:" + Colors.RESET)
                    for iface in interfaces:
                        print(Colors.GREEN + f"- {iface['index']} | {iface['name']}" + Colors.RESET)
                else:
                    print(Colors.RED + "No interfaces found." + Colors.RESET)
            elif flags.lower() in ["-v", "--verbose"]:
                print(Colors.YELLOW + "Verbose mode enabled. Displaying detailed interface information." + Colors.RESET)
                if interfaces:
                    print(Colors.GREEN + "Available interfaces:" + Colors.RESET)
                    for iface in interfaces:
                        print(Colors.GREEN + f"- {iface['index']} | {iface['name']}" + Colors.YELLOW + f"| {iface.get('description', 'No description')}" + Colors.GREEN + f" | {iface.get('guid')}" + Colors.RESET)
                else:
                    print(Colors.RED + "No interfaces found." + Colors.RESET)
        else: print(Colors.RED + f"Unknown command: \"{command}\"" + Colors.RESET)