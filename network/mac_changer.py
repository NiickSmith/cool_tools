#!/usr/bin/env python

import subprocess
from optparse import OptionParser
import re
import random
import logging
import json
import os

LOG_FILE = 'mac_changer.log'
BACKUP_FILE = 'backup_mac.json'


def setup_logger():
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                        format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')


def get_arguments():
    parser = OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--newmac", dest="new_mac", help="New MAC address")
    parser.add_option("-r", "--random", action="store_true", dest="random_mac", help="Generate a random MAC address")
    parser.add_option("-b", "--backup", action="store_true", dest="backup_mac", help="Restore to original MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    if not options.new_mac and not options.random_mac and not options.backup_mac:
        parser.error(
            "[-] Please specify a new MAC address, use --random to generate one, or use --backup to restore the original MAC.")
    return options


def validate_mac(mac):
    if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac):
        return False, "Invalid MAC address format."
    if int(mac[1], 16) & 1:
        return False, "MAC address is a multicast address."
    if mac.lower() in ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00']:
        return False, "MAC address is a broadcast address."
    return True, None


def generate_random_mac(base_mac):
    base_mac_parts = base_mac.split(':')
    new_mac = base_mac_parts[:3] + [f'{random.randint(0x00, 0xff):02x}' for _ in range(3)]
    new_mac = ':'.join(new_mac)
    return new_mac


def change_mac(interface, new_mac):
    logging.info(f"Changing MAC address for {interface} to {new_mac}")
    try:
        subprocess.call(["ifconfig", interface, "down"])
        subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
        subprocess.call(["ifconfig", interface, "up"])
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to change MAC address: {e}")
        logging.error(f"Failed to change MAC address for {interface}: {e}")


def get_current_mac(interface):
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface]).decode('utf-8')
    except subprocess.CalledProcessError:
        print(f"[-] Interface {interface} not found. Please specify a valid interface.")
        return None
    mac_address_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_address_result:
        return mac_address_result.group(0)
    else:
        print(f"[-] Could not read MAC address for {interface}.")
        return None


def backup_mac(interface, current_mac):
    backup_data = {}
    if os.path.exists(BACKUP_FILE):
        with open(BACKUP_FILE, 'r') as file:
            backup_data = json.load(file)
    backup_data[interface] = current_mac
    with open(BACKUP_FILE, 'w') as file:
        json.dump(backup_data, file)


def restore_mac(interface):
    if not os.path.exists(BACKUP_FILE):
        print("[-] No backup file found.")
        return
    with open(BACKUP_FILE, 'r') as file:
        backup_data = json.load(file)
    if interface not in backup_data:
        print(f"[-] No backup MAC address found for {interface}.")
        return
    original_mac = backup_data[interface]
    change_mac(interface, original_mac)
    print(f"[+] MAC address restored to {original_mac}")


def main():
    setup_logger()
    options = get_arguments()

    if options.backup_mac:
        restore_mac(options.interface)
        return

    current_mac = get_current_mac(options.interface)
    if not current_mac:
        return
    print(f"Current MAC = {current_mac}")

    if options.random_mac:
        options.new_mac = generate_random_mac()
        print(f"Generated random MAC = {options.new_mac}")

    is_valid, error_message = validate_mac(options.new_mac)
    if not is_valid:
        print(f"[-] {error_message}")
        return

    backup_mac(options.interface, current_mac)
    change_mac(options.interface, options.new_mac)

    current_mac = get_current_mac(options.interface)
    if current_mac == options.new_mac:
        print(f"[+] MAC address changed to {current_mac}")
    else:
        print("[-] MAC address did not change.")


if __name__ == "__main__":
    main()
