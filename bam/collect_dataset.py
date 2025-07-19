import time
import json
import os
import random
import sys
from datetime import datetime

def collect(mode="human"):
    latencies = []

    print(f"⌨️ Collecting typing latency for mode: {mode}")

    if mode == "ai":
        print("🤖 AI mode: Paste your text below. Press Ctrl-D (Unix) or Ctrl-Z+Enter (Windows) when done.")
        ai_text = sys.stdin.read()
        words = ai_text.split()

        if not words:
            print("No input received. No data collected for AI mode.")
            return latencies

        repetitions = 30
        try:
            # Ask user for repetitions to generate more data easily
            rep_input = input("🔁 How many times to repeat this text for data generation? (e.g., 30): ")
            if rep_input.strip():
                repetitions = int(rep_input)
            
            if repetitions < 1:
                repetitions = 1
        except (ValueError, TypeError):
            print("⚠️ Invalid number, defaulting to 1 repetition.")
            repetitions = 1

        words = words * repetitions
        print(f"🤖 Simulating AI typing for {len(words)} words...")
        for word in words:
            start = time.time()
            # Simulate a more "realistic" AI typing latency based on word length
            delay = random.uniform(0.05, 0.15) + (len(word) * random.uniform(0.01, 0.03))
            time.sleep(delay)
            end = time.time()
            latency = round(end - start, 3)
            latencies.append(latency)
            print(f"🤖 Typed '{word}': {latency:.3f} sec")
    else:
        print("Start typing one word per line. Press Enter on an empty line to stop.")
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

def save(latencies, mode):
    if not latencies:
        print("⚠️ No latencies were recorded. Nothing to save.")
        return

    os.makedirs("bam/dataset", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"bam/dataset/{mode}_{timestamp}.json"

    summary = {
        "mode": mode,
        "timestamp": timestamp,
        "count": len(latencies),
        "mean_latency": round(sum(latencies) / len(latencies), 3),
        "latencies": latencies,
    }

    with open(filename, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"✅ Saved {len(latencies)} latencies to {filename}")

if __name__ == "__main__":
    print("=== Behavioral Dataset Collector ===")
    mode = input("Choose mode (human / ai): ").strip().lower()
    if mode not in {"human", "ai"}:
        print("❌ Invalid mode. Use 'human' or 'ai'.")
    else:
        data = collect(mode)
        if data:
            save(data, mode)
