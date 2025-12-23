import os
import shutil
import collections
import time

# --- KONFIGURASI ---

# Ini adalah KEYWORD_MAP lengkap Anda, penting untuk identifikasi yang akurat
# Diurutkan dari yang paling spesifik ke yang paling umum
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

# 9 Aplikasi yang kita pilih untuk eksperimen "VPN-Only yang Bermakna"
# Ini mencakup semua 6 kategori
TARGET_APPS = {
    'Skype',
    'Hangout',
    'Facebook',
    'BitTorrent',
    'FTP',
    'Email',
    'YouTube',
    'Spotify',
    'Netflix'
}

# Lokasi folder Anda
SOURCE_DIR = "/content/drive/MyDrive/1 Skripsi/Dataset/ISCX-VPN-NonVPN-2016/cleaned_flows_final"
DEST_DIR = "/content/drive/MyDrive/1 Skripsi/Notebook/VPNOnlyDataset"

def filter_and_copy_files():
    """
    Mengiterasi folder sumber dan menyalin file yang sesuai dengan
    kriteria (VPN-Only DAN 9 aplikasi target) ke folder tujuan.
    """
    print(f"--- Memulai Proses Filter Dataset ---")
    print(f"Folder Sumber: {SOURCE_DIR}")
    print(f"Folder Tujuan: {DEST_DIR}")
    print(f"Target Aplikasi: {len(TARGET_APPS)} aplikasi")
    print("Filter: HANYA file VPN ('vpn_*.pcap')\n")

    start_time = time.time()

    # Membuat folder tujuan jika belum ada
    try:
        os.makedirs(DEST_DIR, exist_ok=True)
    except Exception as e:
        print(f"FATAL ERROR: Tidak dapat membuat folder tujuan: {e}")
        return

    # Mendapatkan daftar semua file
    try:
        all_files = os.listdir(SOURCE_DIR)
        print(f"Menemukan total {len(all_files)} file di folder sumber.")
    except Exception as e:
        print(f"FATAL ERROR: Tidak dapat membaca folder sumber: {e}")
        return

    # Inisialisasi penghitung
    total_processed = 0
    vpn_files_found = 0
    apps_matched = 0
    files_copied = 0
    files_skipped = 0

    for i, filename in enumerate(all_files):
        if not filename.endswith('.pcap'):
            files_skipped += 1
            continue

        total_processed += 1

        # Cetak kemajuan
        if (i + 1) % 1000 == 0:
            print(f"Memproses file {i + 1}/{len(all_files)}...")

        file_lower = filename.lower()

        # --- KRITERIA 1: HARUS VPN ---
        if not file_lower.startswith('vpn_'):
            continue  # Lewati jika bukan file VPN

        vpn_files_found += 1

        # --- KRITERIA 2: HARUS TERMASUK 9 APLIKASI TARGET ---
        found_app = None
        for keyword, (application, category) in KEYWORD_MAP.items():
            if keyword in file_lower:
                found_app = application
                break  # Temukan kecocokan pertama (paling spesifik)

        if found_app in TARGET_APPS:
            apps_matched += 1

            # Jika lolos kedua filter, salin file
            source_path = os.path.join(SOURCE_DIR, filename)
            dest_path = os.path.join(DEST_DIR, filename)

            try:
                shutil.copy2(source_path, dest_path)
                files_copied += 1
            except Exception as e:
                print(f"ERROR: Gagal menyalin {filename}: {e}")

    end_time = time.time()

    print("\n--- Proses Filter Selesai ---")
    print(f"Total waktu: {end_time - start_time:.2f} detik")
    print(f"Total file .pcap diproses: {total_processed}")
    print(f"Total file VPN ditemukan: {vpn_files_found}")
    print(f"Total file cocok dengan 9 aplikasi: {apps_matched}")
    print(f"Total file disalin ke tujuan: {files_copied}")
    print(f"Total file dilewati (bukan .pcap): {files_skipped}")

# --- Main execution ---
if __name__ == "__main__":
    if not os.path.exists("/content/drive/MyDrive"):
        print("Pastikan Google Drive Anda sudah ter-mount!")
        print("Jalankan sel berikut di Colab:")
        print("from google.colab import drive")
        print("drive.mount('/content/drive')")
    else:
        filter_and_copy_files()