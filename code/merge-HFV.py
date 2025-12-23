# --- Final PESV (v3) Assembly Script ---
#
# This script assembles the "ultimate" feature vector:
# Sigma_v3 = (alpha'' + delta + gamma')
#
# 1. Base (Labels): cnn_payload_labels.csv (9,720 samples)
# 2. Alpha'' (α''): alpha_double_prime_component_v3.csv (128 features)
# 3. Delta (δ):     delta_component_v2.csv (~39 features)
# 4. Gamma' (γ'):   gamma_prime_component_v2.csv (37 features)
#
# It performs an 'inner merge' on 'filename' to ensure
# only flows valid across all three pipelines are included.

print("--- Initializing PESV v3 Assembly Script ---")

import pandas as pd
import os

print("All libraries imported successfully.")

# --- PART 1: Configuration ---
BASE_PATH = "/content/drive/MyDrive/1 Skripsi/"

# --- Input Files ---
# 1. This is our "base" file. It has the 9,720 valid filenames and labels.
BASE_LABELS_FILE = os.path.join(BASE_PATH, "VPNOnly-cnn_payload_labels.csv")

# 2. The new 1D-CNN features
ALPHA_V3_FILE = os.path.join(BASE_PATH, "VPNOnly-alpha_double_prime_component_v3.csv")

# 3. The statistical features (from our v2 run)
DELTA_V2_FILE = os.path.join(BASE_PATH, "VPNOnly-delta_component_v2.csv")
GAMMA_V2_FILE = os.path.join(BASE_PATH, "VPNOnly-gamma_prime_component_v2.csv")

# --- Output File ---
OUTPUT_FILE = os.path.join(BASE_PATH, "VPNOnly-final_PESV_dataset_v3.csv")

# --- PART 2: Main Assembly ---
def main():
    print("Loading component files...")

    try:
        # Load the base labels (9,720 rows)
        df_base_labels = pd.read_csv(BASE_LABELS_FILE)

        # Load the new alpha'' features (9,720 rows)
        df_alpha_pp = pd.read_csv(ALPHA_V3_FILE)

        # Load the delta features (~10k rows)
        df_delta = pd.read_csv(DELTA_V2_FILE)

        # Load the gamma' features (~10k rows)
        df_gamma = pd.read_csv(GAMMA_V2_FILE)

    except FileNotFoundError as e:
        print(f"FATAL ERROR: Could not find a file. {e}")
        print("Please ensure all component files exist:")
        print(f" - {BASE_LABELS_FILE}")
        print(f" - {ALPHA_V3_FILE}")
        print(f" - {DELTA_V2_FILE}")
        print(f" - {GAMMA_V2_FILE}")
        return

    print("--- Initial Shapes ---")
    print(f"Base Labels (from CNN): {df_base_labels.shape}")
    print(f"Alpha'' (CNN features): {df_alpha_pp.shape}")
    print(f"Delta (Flow Stats):     {df_delta.shape}")
    print(f"Gamma' (Burst Stats):   {df_gamma.shape}")

    # --- Prepare feature dataframes for merging ---
    # The delta and gamma files contain redundant label columns.
    # We must drop them before merging to avoid conflicts.
    label_cols_to_drop = ['application', 'category', 'binary_type']

    # Select only filename + delta features
    delta_feature_cols = [col for col in df_delta.columns if col not in label_cols_to_drop]
    df_delta_features_only = df_delta[delta_feature_cols]

    # Select only filename + gamma' features
    gamma_feature_cols = [col for col in df_gamma.columns if col not in label_cols_to_drop]
    df_gamma_features_only = df_gamma[gamma_feature_cols]

    # --- Perform Sequential Inner Merge ---
    # This robustly finds the common set of 'filename' keys

    print("\nMerging... (using 'filename' as the key)")

    # 1. Merge Base Labels + Alpha'' features
    # (This should be a perfect 1-to-1 merge, 9,720 rows)
    df_merged = pd.merge(df_base_labels, df_alpha_pp, on='filename', how='inner')
    print(f"Shape after merging Alpha'': {df_merged.shape}")

    # 2. Merge with Delta features
    df_merged = pd.merge(df_merged, df_delta_features_only, on='filename', how='inner')
    print(f"Shape after merging Delta:  {df_merged.shape}")

    # 3. Merge with Gamma' features
    df_final = pd.merge(df_merged, df_gamma_features_only, on='filename', how='inner')
    print(f"Shape after merging Gamma': {df_final.shape}")

    # --- Save Final Dataset ---
    print(f"\nAssembly complete. Saving final dataset...")
    df_final.to_csv(OUTPUT_FILE, index=False)

    print(f"\n--- Successfully Created {OUTPUT_FILE} ---")
    print(f"Final Dataset Shape: {df_final.shape}")

    # Display info
    print("\nFinal Dataset Info:")
    df_final.info()

if __name__ == "__main__":
    if not os.path.exists("/content/drive/MyDrive"):
        print("Please mount your Google Drive first!")
    else:
        main()