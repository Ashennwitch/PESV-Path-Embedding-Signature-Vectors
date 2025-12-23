# --- 1D-CNN Data Extraction Script (Step 1) ---
#
# This script reads all .pcap files from the v2 dataset
# and extracts the raw packet payloads, preparing them
# for input into a 1D-CNN.
#
# This replaces the original 'alpha' (LSTM/packet size)
# and 'alpha-prime' (Bag-of-Bytes) feature extractors.
#
# It saves two files:
# 1. cnn_payload_data.npy: A 3D NumPy array (samples, N_PACKETS, PAYLOAD_LEN)
# 2. cnn_payload_labels.csv: The corresponding labels for each sample.

print("--- Initializing 1D-CNN Data Extraction Script ---")

import os
import numpy as np
import pandas as pd
from scapy.all import rdpcap, TCP, UDP
from joblib import Parallel, delayed
import collections

print("All libraries imported successfully.")

# --- PART 1: Configuration ---

# --- Dataset Paths ---
BASE_PATH = "/content/drive/MyDrive/1 Skripsi/"
SOURCE_DIR = os.path.join(BASE_PATH, "Notebook/VPNOnlyDataset")

# --- Output Files ---
OUTPUT_DATA_FILE = os.path.join(BASE_PATH, "VPNOnly-cnn_payload_data.npy")
OUTPUT_LABELS_FILE = os.path.join(BASE_PATH, "VPNOnly-cnn_payload_labels.csv")

# --- CNN Parameters (from research papers) ---
N_PACKETS = 10     # Use the first 10 packets
PAYLOAD_LEN = 784  # Use the first 784 bytes of the payload
                   # (a common size from papers like Wang et al. [37])

# --- KEYWORD_MAP (Copied from your previous script) ---
# This ensures our labels are 100% consistent
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

# --- PART 2: Helper Functions ---

def get_labels_from_filename(filename):
    """
    Finds the application, category, and binary_type from a filename.
    """
    lower_filename = filename.lower()
    binary_type = 'VPN' if lower_filename.startswith('vpn_') else 'NonVPN'

    for keyword, (application, category) in KEYWORD_MAP.items():
        if keyword in lower_filename:
            return filename, application, category, binary_type

    return filename, "Unknown", "Unknown", binary_type

def process_pcap_for_cnn(pcap_filepath):
    """
    Extracts the first N_PACKETS * PAYLOAD_LEN bytes of payload
    from a single pcap file and normalizes them.
    """
    try:
        # Get labels
        filename = os.path.basename(pcap_filepath)
        labels = get_labels_from_filename(filename)

        # This will be our (10, 784) array for this one flow
        flow_data = np.zeros((N_PACKETS, PAYLOAD_LEN), dtype=np.float32)

        packets = rdpcap(pcap_filepath)
        packet_count = 0

        for pkt in packets:
            if packet_count >= N_PACKETS:
                break

            # Find the payload (bytes *after* TCP/UDP header)
            payload = None
            if TCP in pkt:
                payload = bytes(pkt[TCP].payload)
            elif UDP in pkt:
                payload = bytes(pkt[UDP].payload)

            # Skip if no payload (e.g., pure TCP SYN) or not TCP/UDP
            if not payload:
                continue

            payload_len = len(payload)

            # This is our (784,) vector for this one packet
            normalized_payload = np.zeros(PAYLOAD_LEN, dtype=np.float32)

            # Determine how many bytes to copy
            copy_len = min(payload_len, PAYLOAD_LEN)

            # Copy the data from the byte buffer and normalize (0-255 -> 0.0-1.0)
            # This is a very fast, C-speed operation
            byte_data = np.frombuffer(payload[:copy_len], dtype=np.uint8)
            normalized_payload[:copy_len] = byte_data.astype(np.float32) / 255.0

            # Add the packet vector to our flow matrix
            flow_data[packet_count] = normalized_payload
            packet_count += 1

        # If we didn't find *any* packets with payload, skip this file
        if packet_count == 0:
            # This was changed to a print statement to avoid cluttering the log
            # print(f"Skipping {filename}: No TCP/UDP payload found.")
            return None

        # Return the (10, 784) data block and the labels
        return flow_data, labels

    except Exception as e:
        # print(f"Error processing {pcap_filepath}: {e}")
        return None

# --- PART 3: Main Execution ---
def main():
    print(f"Reading from: {SOURCE_DIR}")
    if not os.path.exists(SOURCE_DIR):
        print(f"FATAL ERROR: Source directory not found.")
        return

    filenames = [os.path.join(SOURCE_DIR, f) for f in os.listdir(SOURCE_DIR)
                 if f.endswith('.pcap')]
    print(f"Found {len(filenames)} .pcap files to process.")

    # Process all files in parallel
    print("Processing files in parallel... (This may take several minutes)")
    start_time = time.time()
    results = Parallel(n_jobs=-1, verbose=5)(
        delayed(process_pcap_for_cnn)(f) for f in filenames
    )
    end_time = time.time()
    print(f"File processing finished in {end_time - start_time:.2f} seconds.")

    # Filter out empty/corrupted files
    valid_results = [r for r in results if r is not None]

    print(f"Successfully processed {len(valid_results)} files.")
    print(f"Skipped {len(filenames) - len(valid_results)} empty/corrupted/unlabeled files.")

    # Unzip the results into data (X) and labels (y)
    # X_data will be a list of (10, 784) arrays
    # labels_list will be a list of ('filename', 'app', 'cat', 'bin') tuples
    X_data_list = [r[0] for r in valid_results]
    labels_list = [r[1] for r in valid_results] # <-- Defined with one underscore

    # --- Save the data ---
    try:
        # Stack all (10, 784) arrays into one big (N, 10, 784) array
        X_final = np.stack(X_data_list, axis=0)

        # Save the data
        print(f"Saving payload data with shape {X_final.shape} to {OUTPUT_DATA_FILE}")
        np.save(OUTPUT_DATA_FILE, X_final)

        # Save the labels
        # <-- FIX: Corrected variable name from 'labels__list' to 'labels_list'
        y_df = pd.DataFrame(labels_list, columns=['filename', 'application', 'category', 'binary_type'])
        print(f"Saving labels with shape {y_df.shape} to {OUTPUT_LABELS_FILE}")
        y_df.to_csv(OUTPUT_LABELS_FILE, index=False)

        print("\n--- 1D-CNN Data Extraction Finished ---")

    except Exception as e:
        print(f"\nFATAL ERROR during saving: {e}")
        print("This may be a memory error. Check your Colab runtime RAM.")

if __name__ == "__main__":
    if not os.path.exists("/content/drive/MyDrive"):
        print("Please mount your Google Drive first!")
    else:
        main()