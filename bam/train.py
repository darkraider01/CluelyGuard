import os
import json
import numpy as np
from sklearn.ensemble import IsolationForest
from joblib import dump

DATASET_DIR = "bam/bam/dataset"
MODEL_PATH = "bam/bam_model.joblib"

def load_data(mode):
    latencies = []
    if not os.path.isdir(DATASET_DIR):
        # The directory doesn't exist, which is a valid state if no data
        # has been collected yet. Return an empty list.
        return latencies

    for filename in os.listdir(DATASET_DIR):
        if filename.startswith(mode) and filename.endswith(".json"):
            with open(os.path.join(DATASET_DIR, filename)) as f:
                try:
                    data = json.load(f)
                    if isinstance(data["latencies"], list):
                        latencies.extend(data["latencies"])
                except Exception as e:
                    print(f"❌ Failed to read {filename}: {e}")
    return latencies

def train_model(data):
    # Reshape data for sklearn: each latency is a feature.
    X = np.array(data).reshape(-1, 1)
    # The contamination is the expected proportion of outliers (AI data) in the dataset.
    # We'll use this during prediction, but for training, we only show the model what's "normal".
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(X)
    return model

def main():
    print("🧠 Loading dataset...")
    human_latencies = load_data("human")
    ai_latencies = load_data("ai")

    # We need human data to train the model on what is "normal".
    # AI data is good for validation/testing, but not required for training this model.
    if not human_latencies:
        print("❌ Not enough human data to train the model. Please collect human samples first.")
        return

    print(f"✅ Loaded {len(human_latencies)} human and {len(ai_latencies)} AI samples")

    # Train the model *only* on human data to learn "normal" behavior.
    # The model will then identify AI typing as an anomaly.
    model = train_model(human_latencies)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    dump(model, MODEL_PATH)
    print(f"✅ Model trained and saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()
