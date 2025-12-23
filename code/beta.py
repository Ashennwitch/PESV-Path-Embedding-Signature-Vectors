# --- Delta (δ) Component Extraction Script ---
# This script reads the 10,284 filtered .pcap files and generates
# the "Delta" component: a detailed statistical profile of the
# entire flow, calculated bidirectionally.
# This component replaces the original Beta (β) component.

print("--- Initializing Delta (δ) v2 Component Script ---")

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
OUTPUT_CSV = "/content/drive/MyDrive/1 Skripsi/VPNOnly-delta_component_v2.csv"

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

    # Ensure all keys exist, even if they are 0
    stat_names = ['count', 'sum', 'mean', 'std', 'min', 'max', 'median', 'p25', 'p75']
    for name in stat_names:
        stats[f"{prefix}_{name}"] = 0.0

    if not data_list:
        # No data, return all zeros
        return stats

    arr = np.array(data_list)

    stats[f"{prefix}_count"] = float(arr.size)
    stats[f"{prefix}_sum"] = float(np.sum(arr))
    stats[f"{prefix}_mean"] = float(np.mean(arr))
    stats[f"{prefix}_min"] = float(np.min(arr))
    stats[f"{prefix}_max"] = float(np.max(arr))
    stats[f"{prefix}_median"] = float(np.median(arr))

    # Percentiles
    stats[f"{prefix}_p25"] = float(np.percentile(arr, 25))
    stats[f"{prefix}_p75"] = float(np.percentile(arr, 75))

    # Std deviation requires at least 2 samples
    if arr.size > 1:
        stats[f"{prefix}_std"] = float(np.std(arr))

    return stats


def process_pcap_file(filename, base_dir):
    """
    Reads a single .pcap file and extracts its full flow statistics.
    Designed to be run in parallel.
    """
    filepath = os.path.join(base_dir, filename)

    # 1. Get labels
    application, category, binary_type = get_flow_labels(filename)
    if application is None:
        return None

    # Lists to hold packet data
    c2s_sizes = []  # Client-to-Server packet sizes
    c2s_times = []  # Client-to-Server packet arrival times
    s2c_sizes = []  # Server-to-Client packet sizes
    s2c_times = []  # Server-to-Client packet arrival times

    try:
        packets = rdpcap(filepath)

        client_ip = None
        for pkt in packets:
            if IP in pkt:
                client_ip = pkt[IP].src
                break

        if client_ip is None:
            return None # Skip non-IP flows

        # 3. Extract packet sizes and times, separated by direction
        for pkt in packets:
            if IP in pkt:
                packet_size = float(pkt[IP].len)
                packet_time = float(pkt.time)

                if pkt[IP].src == client_ip:
                    c2s_sizes.append(packet_size)
                    c2s_times.append(packet_time)
                elif pkt[IP].dst == client_ip:
                    s2c_sizes.append(packet_size)
                    s2c_times.append(packet_time)

    except Exception as e:
        # Catches corrupted or unreadable files
        # print(f"Skipping file (error reading pcap): {filename}, Error: {e}")
        return None

    if not c2s_times and not s2c_times:
        # No IP packets were found at all
        return None

    # 4. Calculate flow duration
    all_times = sorted(c2s_times + s2c_times)
    flow_duration = all_times[-1] - all_times[0] if all_times else 0.0

    # 5. Calculate Inter-Arrival Times (IATs)
    # np.diff computes the difference between consecutive elements
    c2s_iats = np.diff(c2s_times).tolist()
    s2c_iats = np.diff(s2c_times).tolist()

    # 6. Calculate all statistical features
    features = {}
    features.update(calculate_stats(c2s_sizes, "c2s_size"))
    features.update(calculate_stats(s2c_sizes, "s2c_size"))
    features.update(calculate_stats(c2s_iats, "c2s_iat"))
    features.update(calculate_stats(s2c_iats, "s2c_iat"))

    # 7. Add total flow-level features
    features["flow_duration"] = flow_duration
    features["flow_total_packets"] = len(c2s_sizes) + len(s2c_sizes)
    features["flow_total_volume"] = sum(c2s_sizes) + sum(s2c_sizes)

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
    print(f"\n--- PART 1: Extracting Delta (δ) Features ---")
    print(f"Reading from: {FLOW_DIR}")

    if not os.path.isdir(FLOW_DIR):
        print(f"FATAL: Source directory not found. Please check the path.")
        return

    filenames = os.listdir(FLOW_DIR)
    pcap_files = [f for f in filenames if f.endswith('.pcap') or f.endswith('.pcapng')]
    print(f"Found {len(pcap_files)} .pcap files in the directory.")

    start_time = time.time()

    # Use joblib to process files in parallel
    print("Processing files in parallel... (This may take several minutes)")
    results = Parallel(n_jobs=-1, verbose=5)(
        delayed(process_pcap_file)(f, FLOW_DIR) for f in pcap_files
    )

    end_time = time.time()
    print(f"File processing finished in {end_time - start_time:.2f} seconds.")

    # Filter out 'None' results from skipped/empty files
    valid_results = [r for r in results if r is not None]

    if not valid_results:
        print("FATAL: No valid data was extracted. Stopping script.")
        return

    print(f"Successfully processed {len(valid_results)} files.")
    print(f"Skipped {len(pcap_files) - len(valid_results)} empty/corrupted/unlabeled files.")

    # Create a DataFrame from the results
    df_final = pd.DataFrame(valid_results)

    # --- PART 2: Saving Final Dataset ---
    print("\n--- PART 2: Saving Final Dataset ---")

    try:
        df_final.to_csv(OUTPUT_CSV, index=False)
        print(f"Successfully saved final delta component (v2) to:")
        print(OUTPUT_CSV)
    except Exception as e:
        print(f"Error saving final CSV: {e}")

if __name__ == "__main__":
    if not os.path.exists("/content/drive/MyDrive"):
        print("Please mount your Google Drive first!")
        print("from google.colab import drive; drive.mount('/content/drive')")
    else:
        main()

print("\n--- Delta (δ) v2 Script Finished ---")
