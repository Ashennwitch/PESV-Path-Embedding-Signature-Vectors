# --- Gamma-Prime (γ') Component Extraction Script ---
# This script reads the 10,284 filtered .pcap files and generates
# the "Gamma-Prime" component: a detailed statistical profile of
# the flow's burst behavior.
# This component replaces the original Gamma (γ) component.

print("--- Initializing Gamma-Prime (γ') v2 Component Script ---")

# --- Step 0: Ensure scapy is installed ---
try:
    import scapy.all as scapy
except ImportError:
    print("Please run '!pip install scapy' in a Colab cell and restart the runtime.")
    # In a notebook, run: !pip install scapy

import os
import collections
import time
import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from scapy.all import rdpcap, IP

print("All libraries imported successfully.")

# --- PART 1: Configuration & Labeling Map ---

# --- File & Path Configuration ---
FLOW_DIR = "/content/drive/MyDrive/1 Skripsi/Notebook/VPNOnlyDataset"
OUTPUT_CSV = "/content/drive/MyDrive/1 Skripsi/VPNOnly-gamma_prime_component_v2.csv"

# --- Burst Definition ---
# From your original documentation:
# A burst is a group of packets where the idle time between them is < 1.0s
BURST_IDLE_THRESHOLD = 1.0

# --- Labeling Map (Copied from your script) ---
KEYWORD_MAP = collections.OrderedDict([
    ('facebook_chat', ('Facebook', 'Chat')),
    ('facebookchat', ('Facebook', 'Chat')),
    ('hangouts_chat', ('Hangout', 'Chat')),
    ('hangout_chat', ('Hangout', 'Chat')),
    ('gmailchat', ('Gmail', 'Chat')),
    ('icq_chat', ('ICQ', 'Chat')),
    ('icqchat', ('ICQ', 'Chat')),
    ('skype_chat', ('Skype', 'Chat')),
    ('aim_chat', ('AIM Chat', 'Chat')),
    ('aimchat', ('AIM Chat', 'Chat')),

    ('facebook_audio', ('Facebook', 'VoIP')),
    ('hangouts_audio', ('Hangout', 'VoIP')),
    ('skype_audio', ('Skype', 'VoIP')),
    ('voipbuster', ('VOIPBuster', 'VoIP')),
    ('facebook_video', ('Facebook', 'VoIP')),
    ('hangouts_video', ('Hangout', 'VoIP')),
    ('skype_video', ('Skype', 'VoIP')),

    ('skype_file', ('Skype', 'File Transfer')),
    ('ftps', ('FTP', 'File Transfer')),
    ('sftp', ('SFTP', 'File Transfer')),
    ('scp', ('SCP', 'File Transfer')),
    ('ftp', ('FTP', 'File Transfer')),

    ('email', ('Email', 'Email')),
    ('gmail', ('Gmail', 'Email')),

    ('netflix', ('Netflix', 'Streaming')),
    ('spotify', ('Spotify', 'Streaming')),
    ('vimeo', ('Vimeo', 'Streaming')),
    ('youtube', ('YouTube', 'Streaming')),

    ('bittorrent', ('BitTorrent', 'P2P')),
])

# --- List of the 6 applications we are using ---
TARGET_APPS = {
    'Skype', 'Email', 'SCP', 'VOIPBuster', 'YouTube', 'BitTorrent'
}


def get_flow_labels(filename):
    """
    Parses a filename to get its labels (application, category, binary_type).
    """
    lower_filename = filename.lower()
    binary_type = 'VPN' if lower_filename.startswith('vpn_') else 'NonVPN'

    for keyword, (application, category) in KEYWORD_MAP.items():
        if keyword in lower_filename:
            if application not in TARGET_APPS:
                 # Allow 'SCP' to not be in the keyword map
                if application == 'SCP':
                   return 'SCP', 'File Transfer', binary_type
                print(f"Warning: Found app '{application}' not in TARGET_APPS.")
            return application, category, binary_type

    # Fallback logic for our 6 target apps
    if 'scp' in lower_filename:
        return 'SCP', 'File Transfer', binary_type
    if 'email' in lower_filename:
        return 'Email', 'Email', binary_type
    if 'youtube' in lower_filename:
        return 'YouTube', 'Streaming', binary_type
    if 'bittorrent' in lower_filename:
        return 'BitTorrent', 'P2P', binary_type
    if 'skype' in lower_filename:
         # This is a fallback, 'skype_chat' etc. should catch first
        return 'Skype', 'Unknown', binary_type
    if 'voipbuster' in lower_filename:
        return 'VOIPBuster', 'VoIP', binary_type

    return None, None, None

def calculate_stats(data_list, prefix):
    """
    Calculates a full statistical profile for a list of numbers.
    Returns a dictionary of features.
    """
    stats = {}

    stat_names = ['count', 'sum', 'mean', 'std', 'min', 'max', 'median', 'p25', 'p75']
    for name in stat_names:
        # We use prefix (e.g., 'burst_vol') to create feature names
        stats[f"{prefix}_{name}"] = 0.0

    if not data_list:
        return stats

    arr = np.array(data_list)

    stats[f"{prefix}_count"] = float(arr.size)
    stats[f"{prefix}_sum"] = float(np.sum(arr))
    stats[f"{prefix}_mean"] = float(np.mean(arr))
    stats[f"{prefix}_min"] = float(np.min(arr))
    stats[f"{prefix}_max"] = float(np.max(arr))
    stats[f"{prefix}_median"] = float(np.median(arr))
    stats[f"{prefix}_p25"] = float(np.percentile(arr, 25))
    stats[f"{prefix}_p75"] = float(np.percentile(arr, 75))

    if arr.size > 1:
        stats[f"{prefix}_std"] = float(np.std(arr))

    return stats


def process_pcap_file(filename, base_dir):
    """
    Reads a single .pcap file and extracts its full burst statistics.
    Designed to be run in parallel.
    """
    filepath = os.path.join(base_dir, filename)

    # 1. Get labels
    application, category, binary_type = get_flow_labels(filename)
    if application is None:
        return None

    all_packets = [] # List to hold (time, size) tuples

    try:
        packets = rdpcap(filepath)

        client_ip = None
        for pkt in packets:
            if IP in pkt:
                client_ip = pkt[IP].src
                break

        if client_ip is None:
            return None # Skip non-IP flows

        # 3. Extract *all* IP packets from the flow (bidirectional)
        for pkt in packets:
            if IP in pkt:
                # Only include packets that are part of this flow
                if pkt[IP].src == client_ip or pkt[IP].dst == client_ip:
                    packet_size = float(pkt[IP].len)
                    packet_time = float(pkt.time)
                    all_packets.append((packet_time, packet_size))

    except Exception as e:
        # Catches corrupted or unreadable files
        # print(f"Skipping file (error reading pcap): {filename}, Error: {e}")
        return None

    if not all_packets:
        return None

    # 4. Sort packets by time
    all_packets.sort(key=lambda x: x[0])

    # 5. Calculate bursts
    burst_packet_counts = []
    burst_volumes = []
    burst_durations = []
    burst_idle_times = [] # Idle time *between* bursts

    if not all_packets:
        # Handle empty (but valid) flow
        pass

    # State for the first burst
    current_burst_packets = 1
    current_burst_volume = all_packets[0][1] # Size of first packet
    current_burst_start_time = all_packets[0][0] # Time of first packet
    last_packet_time = all_packets[0][0]

    # Iterate from the *second* packet onwards
    for (pkt_time, pkt_size) in all_packets[1:]:
        idle_time = pkt_time - last_packet_time

        if idle_time < BURST_IDLE_THRESHOLD:
            # --- This packet is PART of the current burst ---
            current_burst_packets += 1
            current_burst_volume += pkt_size
        else:
            # --- This packet is the START of a new burst ---
            # 1. Save the previous burst
            burst_duration = last_packet_time - current_burst_start_time
            burst_packet_counts.append(current_burst_packets)
            burst_volumes.append(current_burst_volume)
            burst_durations.append(burst_duration)

            # 2. Save the idle time that just ended
            burst_idle_times.append(idle_time)

            # 3. Reset for the new burst
            current_burst_packets = 1
            current_burst_volume = pkt_size
            current_burst_start_time = pkt_time

        # Update the time of the last packet seen
        last_packet_time = pkt_time

    # 6. Save the *final* burst after the loop
    # (This handles 1-packet flows as well)
    burst_duration = last_packet_time - current_burst_start_time
    burst_packet_counts.append(current_burst_packets)
    burst_volumes.append(current_burst_volume)
    burst_durations.append(burst_duration)

    # 7. Calculate all statistical features
    features = {}
    features['total_burst_count'] = float(len(burst_packet_counts))

    features.update(calculate_stats(burst_packet_counts, "burst_pkt_count"))
    features.update(calculate_stats(burst_volumes, "burst_vol"))
    features.update(calculate_stats(burst_durations, "burst_dur"))
    features.update(calculate_stats(burst_idle_times, "burst_idle"))

    # 8. Add labels
    labels = {
        'filename': filename,
        'application': application,
        'category': category,
        'binary_type': binary_type
    }

    # Combine labels and features
    labels.update(features)
    return labels

# --- PART 2: Main Execution ---
def main():
    print(f"\n--- PART 1: Extracting Gamma-Prime (γ') Features ---")
    print(f"Reading from: {FLOW_DIR}")
    print(f"Using Burst Idle Threshold: {BURST_IDLE_THRESHOLD}s")

    if not os.path.isdir(FLOW_DIR):
        print(f"FATAL: Source directory not found. Please check the path.")
        return

    filenames = os.listdir(FLOW_DIR)
    pcap_files = [f for f in filenames if f.endswith('.pcap') or f.endswith('.pcapng')]
    print(f"Found {len(pcap_files)} .pcap files in the directory.")

    start_time = time.time()

    print("Processing files in parallel... (This may take several minutes)")
    results = Parallel(n_jobs=-1, verbose=5)(
        delayed(process_pcap_file)(f, FLOW_DIR) for f in pcap_files
    )

    end_time = time.time()
    print(f"File processing finished in {end_time - start_time:.2f} seconds.")

    valid_results = [r for r in results if r is not None]

    if not valid_results:
        print("FATAL: No valid data was extracted. Stopping script.")
        return

    print(f"Successfully processed {len(valid_results)} files.")
    print(f"Skipped {len(pcap_files) - len(valid_results)} empty/corrupted/unlabeled files.")

    df_final = pd.DataFrame(valid_results)

    # --- PART 2: Saving Final Dataset ---
    print("\n--- PART 2: Saving Final Dataset ---")

    try:
        df_final.to_csv(OUTPUT_CSV, index=False)
        print(f"Successfully saved final gamma-prime component (v2) to:")
        print(OUTPUT_CSV)
    except Exception as e:
        print(f"Error saving final CSV: {e}")

if __name__ == "__main__":
    if not os.path.exists("/content/drive/MyDrive"):
        print("Please mount your Google Drive first!")
        print("from google.colab import drive; drive.mount('/content/drive')")
    else:
        main()

print("\n--- Gamma-Prime (γ') v2 Script Finished ---")
