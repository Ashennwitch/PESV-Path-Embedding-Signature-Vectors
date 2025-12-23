import os
import shutil
import logging
# --- Scapy Imports ---
# Import only the most basic and stable layers
from scapy.all import rdpcap, TCP, UDP, IP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.ntp import NTP

# --- Configuration ---

# Directory containing the split pcap files from Step 2 (~309k flows)
INPUT_DIR = '/content/drive/MyDrive/1 Skripsi/Dataset/yang belom'

# Directory where the final cleaned pcap files will be saved (~8.7k flows)
OUTPUT_DIR = "/content/drive/MyDrive/1 Skripsi/Dataset/cleaned_flows_yang belom"

# --- Rule A: Protocol Filtering ---
# DISALLOWED_PROTOCOLS: Check for protocols that Scapy can easily identify as layers.
DISALLOWED_PROTOCOLS = {
    DNS,
    NTP,
    DHCP,
    BOOTP
}
# DISALLOWED_UDP_PORTS: A more robust way to block protocols based on their standard ports.
DISALLOWED_UDP_PORTS = {
    137,   # NBNS (NetBIOS Name Service)
    1900,  # SSDP
    5353,  # MDNS
    5355   # LLMNR
}

# --- Logging Setup ---
logging.basicConfig(
    filename='filtering_log_final.txt',
    level=logging.INFO,
    filemode='w',  # Overwrite the log file on each run
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def is_flow_valid_final(pcap_file_path):
    """
    Analyzes a single flow pcap file and applies ALL filtering rules (A, B, and C)
    to determine if it belongs in the final dataset.
    Returns a tuple: (is_valid, reason_for_invalidation)
    """
    try:
        packets = rdpcap(pcap_file_path)
    except Exception as e:
        return False, f"Scapy could not read file. Error: {e}"

    if not packets:
        return False, "File is empty or corrupt"

    # --- Implement ALL Filtering Rules ---
    first_packet = packets[0]

    # Rule B: TCP 3-Way Handshake Check (applies only to TCP flows)
    if TCP in first_packet:
        if len(packets) > 4 and 'S' not in first_packet[TCP].flags:
            return False, "Rule B Failed: Invalid TCP handshake start"

    # Loop through all packets to check Rules A and C
    for pkt in packets:
        # Rule A (Part 1): Check for disallowed application-layer protocols by Scapy layer
        for protocol_layer in DISALLOWED_PROTOCOLS:
            if protocol_layer in pkt:
                return False, f"Rule A Failed: Disallowed protocol ({protocol_layer.name})"

        if UDP in pkt:
            # Rule A (Part 2): Check for disallowed UDP protocols by their well-known port numbers
            if pkt[UDP].sport in DISALLOWED_UDP_PORTS or pkt[UDP].dport in DISALLOWED_UDP_PORTS:
                return False, f"Rule A Failed: Disallowed UDP port used"

            # Rule C: UDP Beacon Check
            # Check for broadcast UDP packets containing "Beacon~" in the payload
            if IP in pkt and pkt[IP].dst == '255.255.255.255':
                try:
                    payload = bytes(pkt[UDP].payload)
                    if b'Beacon~' in payload:
                        return False, "Rule C Failed: UDP Beacon flow detected"
                except Exception:
                    # Payload might be empty or malformed, safe to ignore and continue
                    pass

    # If the flow has passed all the checks, it's valid
    return True, "Valid"


def main():
    """
    Main function to iterate through all flow files and filter them to the final dataset.
    """
    print("--- Starting Combined Filtering (to get ~8,763 flows) ---")

    if not os.path.isdir(INPUT_DIR):
        print(f"[FATAL ERROR] Input directory '{INPUT_DIR}' not found.")
        print("Please make sure you have run Step 2 successfully.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Final cleaned flows will be saved in: '{OUTPUT_DIR}'")
    print(f"A detailed log will be saved to: 'filtering_log_final.txt'")
    print("\nThis process will take a very long time. Please be patient.\n")

    total_flows = 0
    kept_flows = 0
    discarded_flows = 0

    # Walk through the nested directory structure of split_flows
    for root, _, files in os.walk(INPUT_DIR):
        for filename in files:
            if filename.endswith('.pcap'):
                total_flows += 1
                pcap_path = os.path.join(root, filename)

                is_valid, reason = is_flow_valid_final(pcap_path)

                if is_valid:
                    kept_flows += 1
                    try:
                        shutil.copy(pcap_path, OUTPUT_DIR)
                    except Exception as e:
                        log_msg = f"ERROR COPYING: {pcap_path} | Error: {e}"
                        print(log_msg)
                        logging.error(log_msg)
                else:
                    discarded_flows += 1
                    logging.info(f"DISCARDED: {pcap_path} | Reason: {reason}")

                # Print a progress update every 1000 files processed
                if total_flows % 1000 == 0:
                    print(f"Processed: {total_flows} | Kept: {kept_flows} | Discarded: {discarded_flows}")

    print("\n--- Final Filtering Complete ---")
    print(f"Total flows processed: {total_flows}")
    print(f"Total flows kept: {kept_flows}")
    print(f"Total flows discarded: {discarded_flows}")
    print(f"\nYour final, cleaned dataset is now available in the '{OUTPUT_DIR}' directory.")
    print(f"The final count should be near the target of 8,763.")

if __name__ == '__main__':
    main()
