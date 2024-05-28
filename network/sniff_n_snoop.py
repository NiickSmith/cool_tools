import scapy.all as scapy
import netifaces
import nmap
import requests
import socket
import argparse
import platform
import subprocess
import random


def get_network_interfaces():
    """
    Retrieve all network interfaces and their details.
    """
    interfaces = netifaces.interfaces()
    interface_details = {}
    for iface in interfaces:
        details = netifaces.ifaddresses(iface)
        interface_details[iface] = details
    return interface_details


def generate_mac():
    """
    Generate a random MAC address.
    """
    mac = [
        0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff)
    ]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def mask_mac(interface):
    """
    Randomize MAC address of a specified network interface.
    """
    new_mac = generate_mac()
    os_type = platform.system()
    
    if os_type == "Linux" or os_type == "Darwin":  # macOS uses Darwin
        command = f"sudo ifconfig {interface} hw ether {new_mac}" if os_type == "Linux" else f"sudo ifconfig {interface} ether {new_mac}"
    elif os_type == "Windows":
        command = f"powershell -Command \"Set-NetAdapter -Name '{interface}' -MacAddress '{new_mac}'\""
    else:
        raise OSError("Unsupported operating system for MAC address masking.")
    
    try:
        subprocess.run(command, shell=True, check=True)
        return new_mac
    except subprocess.CalledProcessError as e:
        print(f"Failed to change MAC address: {e}")
        return None


def scan_network(subnet):
    """
    Scan a network to discover hosts and services.
    """
    nm = nmap.PortScanner()
    nm.scan(subnet, arguments='-O')
    hosts = nm.all_hosts()
    results = {}
    for host in hosts:
        results[host] = nm[host]
    return results


def send_packet(packet):
    """
    Send a custom packet using scapy.
    """
    scapy.send(packet)


def receive_packet(interface, filter_expr):
    """
    Receive packets on a specified interface with an optional filter.
    """
    packets = scapy.sniff(iface=interface, filter=filter_expr, timeout=10)
    return packets


def main():
    """
    Main function to parse arguments and execute the appropriate actions.
    """
    parser = argparse.ArgumentParser(description="Network Snooping Tool")
    parser.add_argument('--interface', type=str, help='Network interface to use')
    parser.add_argument('--subnet', type=str, help='Subnet to scan')
    parser.add_argument('--mask', action='store_true', help='Mask MAC address')
    args = parser.parse_args()

    if args.interface:
        if args.mask:
            new_mac = mask_mac(args.interface)
            if new_mac:
                print(f"MAC address for {args.interface} changed to {new_mac}")
            else:
                print("Failed to change MAC address.")
        interface_details = get_network_interfaces()
        print(interface_details)

    if args.subnet:
        scan_results = scan_network(args.subnet)
        print(scan_results)


if __name__ == "__main__":
    main()
