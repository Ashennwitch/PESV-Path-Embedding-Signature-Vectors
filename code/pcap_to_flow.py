import os
import subprocess

# --- Configuration ---

# The name of the executable for SplitCap
SPLITCAP_EXECUTABLE = './SplitCap.exe'

# List of your dataset directories
DATASET_DIRS = [
    'NonVPN-PCAPs-01',
    'NonVPN-PCAPs-02',
    'NonVPN-PCAPs-03',
    'VPN-PCAPS-01',
    'VPN-PCAPS-02'
]

# The main output directory where all split flows will be stored
MAIN_OUTPUT_DIR = 'split_flows'

# --- Script Logic ---

def run_splitcap(pcap_file_path, output_dir):
    """
    Constructs and runs the SplitCap command for a single pcap file.
    Splits the file into bidirectional flows (sessions).
    
    *** UPDATED: Includes the -p argument to limit parallel file handles. ***
    """
    # From the documentation, the argument for bidirectional flows is 'session'
    split_argument = 'session'
    
    # Set a limit for parallel sessions to prevent "Too many open files" error
    parallel_sessions_limit = '500'

    # The command to execute in WSL
    command = [
        'mono',
        SPLITCAP_EXECUTABLE,
        '-r', pcap_file_path,
        '-o', output_dir,
        '-s', split_argument,
        '-p', parallel_sessions_limit  # <-- THIS IS THE NEW ARGUMENT
    ]

    print(f"-> Processing: {pcap_file_path}")
    print(f"   Command: {' '.join(command)}")

    try:
        # Execute the command
        result = subprocess.run(
            command,
            check=True,        # This will raise an exception if the command fails
            capture_output=True,
            text=True
        )
        print(f"   Success! Output saved to: {output_dir}")
        # Uncomment the line below if you want to see the full output from SplitCap
        # print(result.stdout)
    except FileNotFoundError:
        print("\n[ERROR] 'mono' command not found.")
        print("Please ensure Mono is installed and accessible in your WSL environment.")
        print("Installation command: sudo apt install mono-runtime")
        return False
    except subprocess.CalledProcessError as e:
        # This error is triggered if SplitCap returns a non-zero exit code (an error)
        print(f"\n[ERROR] SplitCap failed for file: {pcap_file_path}")
        print(f"   Return Code: {e.returncode}")
        print(f"   Error Output:\n{e.stderr}")
        return False
    return True

def main():
    """
    Main function to find all pcap files and process them.
    """
    print("--- Starting PCAP to Bidirectional Flow Splitting Process ---")

    # Check if SplitCap.exe exists
    if not os.path.exists(SPLITCAP_EXECUTABLE):
        print(f"[FATAL ERROR] '{SPLITCAP_EXECUTABLE}' not found in the current directory.")
        return

    # Create the main output directory if it doesn't exist
    os.makedirs(MAIN_OUTPUT_DIR, exist_ok=True)
    print(f"Main output directory is '{MAIN_OUTPUT_DIR}'\n")

    total_files = 0
    success_count = 0

    # Iterate through each dataset directory
    for dir_name in DATASET_DIRS:
        if not os.path.isdir(dir_name):
            print(f"[WARNING] Directory '{dir_name}' not found. Skipping.")
            continue

        print(f"--- Scanning directory: {dir_name} ---")
        # Find all files ending with .pcap in the directory
        for filename in os.listdir(dir_name):
            if filename.endswith('.pcap'):
                total_files += 1
                pcap_path = os.path.join(dir_name, filename)

                # Create a specific output directory for this pcap file's flows
                # Example: 'split_flows/aim_chat_3a'
                output_sub_dir_name = os.path.splitext(filename)[0]
                output_path = os.path.join(MAIN_OUTPUT_DIR, output_sub_dir_name)

                # Create the directory for the split files
                os.makedirs(output_path, exist_ok=True)

                # Run SplitCap on the file
                if run_splitcap(pcap_path, output_path):
                    success_count += 1
                print("-" * 20) # Separator

    print("\n--- Processing Complete ---")
    print(f"Successfully processed {success_count} out of {total_files} .pcap files.")

if __name__ == '__main__':
    main()
