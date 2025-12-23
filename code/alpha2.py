# --- 1D-CNN Feature Extractor Script (Step 2) ---
#
# This script loads the raw payload data created by Step 1,
# trains a 1D-CNN to classify applications (as suggested by
# the research papers), and then saves the trained "encoder"
# part of the model.
#
# It then uses this encoder to generate our new 128-dimension
# alpha'' (alpha-double-prime) feature vector.
#
# This script requires TensorFlow/Keras.
# In Colab, run: !pip install tensorflow

print("--- Initializing 1D-CNN Feature Extractor (Step 2) ---")

import os
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Conv1D, MaxPooling1D, Flatten, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.utils import to_categorical

print(f"TensorFlow Version: {tf.__version__}")

# --- PART 1: Configuration ---

# --- File Paths ---
BASE_PATH = "/content/drive/MyDrive/1 Skripsi/"
DATA_FILE = os.path.join(BASE_PATH, "VPNOnly-cnn_payload_data.npy")
LABELS_FILE = os.path.join(BASE_PATH, "VPNOnly-cnn_payload_labels.csv")

# --- Output Files ---
# The new feature set
OUTPUT_ALPHA_V3_FILE = os.path.join(BASE_PATH, "VPNOnly-alpha_double_prime_component_v3.csv")
# The saved encoder model for future use
OUTPUT_ENCODER_MODEL_FILE = os.path.join(BASE_PATH, "VPNOnly-cnn_encoder_v3.keras")

# --- Model Parameters ---
# From Step 1, we know these are (10, 784)
N_PACKETS = 10
PAYLOAD_LEN = 784
# We will reshape to (10 * 784, 1)
INPUT_SHAPE = (N_PACKETS * PAYLOAD_LEN, 1) # (7840, 1)

FEATURE_VECTOR_SIZE = 128 # The width of our new alpha'' feature
RANDOM_STATE = 42

# --- PART 2: Load & Prepare Data ---
def load_and_prepare_data():
    print(f"Loading data from {DATA_FILE}...")
    X = np.load(DATA_FILE)
    df_y = pd.read_csv(LABELS_FILE)

    print(f"Loaded data shape: {X.shape}")
    print(f"Loaded labels shape: {df_y.shape}")

    # --- 1. Reshape X ---
    # Reshape (samples, 10, 784) -> (samples, 7840, 1)
    # This treats the 10 packets as one long 1D sequence
    X_reshaped = X.reshape(X.shape[0], N_PACKETS * PAYLOAD_LEN, 1)
    print(f"Reshaped X to: {X_reshaped.shape}")

    # --- 2. Encode y ---
    # We will train the CNN to predict the 'application'
    y_labels = df_y['application']
    num_classes = len(y_labels.unique())
    print(f"Target label: 'application' with {num_classes} classes.")

    # a. String labels to integer
    le = LabelEncoder()
    y_int = le.fit_transform(y_labels)

    # b. Integer labels to one-hot vectors (for categorical_crossentropy)
    y_categorical = to_categorical(y_int)

    print(f"y shape after one-hot encoding: {y_categorical.shape}")

    return X_reshaped, y_categorical, df_y, num_classes

# --- PART 3: Build 1D-CNN Model ---
def build_model(num_classes):
    print("Building 1D-CNN model...")

    input_layer = Input(shape=INPUT_SHAPE)

    # Convolutional Block 1
    x = Conv1D(filters=32, kernel_size=7, activation='relu', padding='same')(input_layer)
    x = MaxPooling1D(pool_size=4)(x)

    # Convolutional Block 2
    x = Conv1D(filters=64, kernel_size=5, activation='relu', padding='same')(x)
    x = MaxPooling1D(pool_size=4)(x)

    # Convolutional Block 3
    x = Conv1D(filters=128, kernel_size=3, activation='relu', padding='same')(x)
    x = MaxPooling1D(pool_size=4)(x)

    x = Flatten()(x)

    # --- This is our Feature Vector ---
    # We give it a name so we can easily extract it later
    x = Dense(FEATURE_VECTOR_SIZE, activation='relu', name="encoder_output")(x)
    x = Dropout(0.5)(x)
    # ----------------------------------

    # Output classifier layer
    output_layer = Dense(num_classes, activation='softmax', name="classifier_output")(x)

    # Create the full model
    model = Model(inputs=input_layer, outputs=output_layer)

    model.compile(
        optimizer='adam',
        loss='categorical_crossentropy',
        metrics=['accuracy']
    )

    print(model.summary())
    return model

# --- PART 4: Main Execution ---
def main():
    if not all([os.path.exists(DATA_FILE), os.path.exists(LABELS_FILE)]):
        print(f"FATAL ERROR: Missing {DATA_FILE} or {LABELS_FILE}")
        print("Please run Step 1 (extract_cnn_payloads.py) first.")
        return

    # --- 1. Load Data ---
    X_full, y_full, df_labels, num_classes = load_and_prepare_data()

    # --- 2. Split Data for Training ---
    X_train, X_val, y_train, y_val = train_test_split(
        X_full, y_full,
        test_size=0.2, # 20% for validation
        random_state=RANDOM_STATE,
        stratify=y_full
    )

    print(f"Training data: {X_train.shape}, Validation data: {X_val.shape}")

    # --- 3. Build & Train Model ---
    model = build_model(num_classes)

    early_stopping = EarlyStopping(
        monitor='val_loss',
        patience=10, # Stop if val_loss doesn't improve for 10 epochs
        restore_best_weights=True # Restore the best model
    )

    print("\n--- Starting 1D-CNN Training ---")
    history = model.fit(
        X_train, y_train,
        epochs=100, # Max epochs
        batch_size=64,
        validation_data=(X_val, y_val),
        callbacks=[early_stopping]
    )
    print("--- Training Complete ---")

    # --- 4. Create and Save the Encoder ---
    print("Extracting and saving the encoder model...")

    # Create a new model that ends at our named "encoder_output" layer
    encoder_model = Model(
        inputs=model.input,
        outputs=model.get_layer("encoder_output").output
    )

    encoder_model.save(OUTPUT_ENCODER_MODEL_FILE)
    print(f"Encoder model saved to: {OUTPUT_ENCODER_MODEL_FILE}")

    # --- 5. Generate and Save alpha'' Features ---
    print(f"Generating {FEATURE_VECTOR_SIZE}-dimension alpha'' features for all {X_full.shape[0]} samples...")

    # Use the encoder to predict (extract features) on the *entire* dataset
    alpha_prime_prime_features = encoder_model.predict(X_full, batch_size=128)

    print(f"Generated features with shape: {alpha_prime_prime_features.shape}")

    # Create a DataFrame for the new features
    alpha_cols = [f'alpha_pp_{i}' for i in range(FEATURE_VECTOR_SIZE)]
    df_alpha_pp = pd.DataFrame(alpha_prime_prime_features, columns=alpha_cols)

    # Combine with the original labels (for merging later)
    # We take the 'filename' from df_labels
    df_final_alpha = pd.concat([df_labels['filename'], df_alpha_pp], axis=1)

    # Save to CSV
    df_final_alpha.to_csv(OUTPUT_ALPHA_V3_FILE, index=False)
    print(f"New alpha'' (v3) component saved to: {OUTPUT_ALPHA_V3_FILE}")
    print("\n--- 1D-CNN Feature Extractor Finished ---")

if __name__ == "__main__":
    if not os.path.exists("/content/drive/MyDrive"):
        print("Please mount your Google Drive first!")
    else:
        main()