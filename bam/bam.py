import time
import json
import os
import sys
from datetime import datetime
try:
    import joblib
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️  Warning: joblib/numpy not available, ML detection disabled")

def collect_typing_latencies():
    print("⌨️  Start typing one word per line (press Enter to end):")
    latencies = []

    try:
        while True:
            start = time.time()
            line = input()
            if line.strip() == "":
                break
            end = time.time()
            latency = round(end - start, 3)
            latencies.append(latency)
            print(f"🕒 Latency: {latency:.3f} sec")
    except KeyboardInterrupt:
        pass

    return latencies

def dummy_typing_data():
    return [1.0, 0.8, 1.2, 0.9, 1.1, 0.75, 1.05, 0.85, 1.3, 0.95]

def load_model():
    """Load the trained IsolationForest model"""
    model_path = "bam_model.joblib"
    if not os.path.exists(model_path):
        print(f"⚠️  Model file {model_path} not found. Please train the model first.")
        return None
    
    try:
        model = joblib.load(model_path)
        print(f"✅ Loaded model from {model_path}")
        return model
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return None

def detect_ai_typing(latencies, model):
    """Use IsolationForest to detect if typing behavior is AI-like"""
    if not ML_AVAILABLE or model is None or not latencies:
        return {
            "ai_detected": False,
            "confidence": 0.0,
            "anomaly_score": 0.0,
            "status": "detection_unavailable"
        }
    
    try:
        # Prepare data for model (reshape for single sample)
        X = np.array(latencies).reshape(1, -1)
        
        # Predict: -1 = anomaly (AI-like), 1 = normal (human-like)
        prediction = model.predict(X)[0]
        
        # Get anomaly score (lower = more anomalous)
        anomaly_score = model.decision_function(X)[0]
        
        # Convert to more intuitive format
        ai_detected = prediction == -1
        confidence = abs(anomaly_score)  # Higher absolute value = higher confidence
        
        return {
            "ai_detected": ai_detected,
            "confidence": round(confidence, 3),
            "anomaly_score": round(anomaly_score, 3),
            "status": "detection_complete"
        }
        
    except Exception as e:
        print(f"❌ Error in AI detection: {e}")
        return {
            "ai_detected": False,
            "confidence": 0.0,
            "anomaly_score": 0.0,
            "status": "detection_error"
        }

def save_log(latencies, detection_result=None):
    if not os.path.exists("logs"):
        os.makedirs("logs")

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = f"logs/bam_{now}.json"

    summary = {
        "timestamp": now,
        "latencies": latencies,
        "mean_latency": round(sum(latencies)/len(latencies), 3) if latencies else 0.0,
        "count": len(latencies),
        "detection": detection_result or {
            "ai_detected": False,
            "confidence": 0.0,
            "anomaly_score": 0.0,
            "status": "no_detection"
        }
    }

    with open(log_path, "w") as f:
        json.dump(summary, f, indent=2)

    # Print results for user and Rust parsing
    if detection_result:
        status = "🤖 AI DETECTED" if detection_result["ai_detected"] else "👤 Human-like"
        print(f"🔍 Detection: {status} (confidence: {detection_result['confidence']:.3f})")
    
    print(f"✅ BAM log written to {log_path}")
    print(log_path)  # For Rust to parse

    return log_path

if __name__ == "__main__":
    # Load the ML model
    model = load_model() if ML_AVAILABLE else None
    
    if sys.stdin.isatty():
        # Interactive mode
        print("🔍 BAM - Behavioral Analysis Module")
        data = collect_typing_latencies()
    else:
        # Non-interactive mode (called from Rust)
        data = dummy_typing_data()
    
    if data:
        # Perform AI detection
        detection_result = detect_ai_typing(data, model)
        save_log(data, detection_result)
    else:
        print("⚠️  No typing data collected")
        save_log([], None)
