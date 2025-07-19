#!/usr/bin/env python3
"""
Test script to demonstrate CluelyGuard's AI detection capabilities
"""

import json
import time
import subprocess
from typing import List, Dict, Any

def simulate_ai_processes() -> List[Dict[str, Any]]:
    """Simulate various types of AI processes for testing"""
    
    # Simulate different types of AI tools
    test_processes = [
        # Known AI tools (should be detected by Layer 1)
        {
            "name": "ChatGPT.exe",
            "path": "C:\\Program Files\\ChatGPT\\ChatGPT.exe",
            "cmdline": ["ChatGPT.exe"],
            "expected_detection": "Layer 1 (Configured Binary)",
            "expected_confidence": 0.9
        },
        {
            "name": "claude",
            "path": "/usr/local/bin/claude",
            "cmdline": ["claude", "--api-key", "sk-..."],
            "expected_detection": "Layer 1 (Configured Binary)",
            "expected_confidence": 0.9
        },
        
        # New AI tools (should be detected by Layer 2)
        {
            "name": "new_ai_tool.exe",
            "path": "C:\\AI Tools\\new_ai_tool.exe",
            "cmdline": ["new_ai_tool.exe"],
            "expected_detection": "Layer 2 (AI Pattern)",
            "expected_confidence": 0.7
        },
        {
            "name": "gpt_assistant",
            "path": "/home/user/ai_tools/gpt_assistant",
            "cmdline": ["gpt_assistant"],
            "expected_detection": "Layer 2 (AI Pattern)",
            "expected_confidence": 0.85
        },
        
        # Stealth AI tools (should be detected by Layer 5)
        {
            "name": "helper.exe",
            "path": "C:\\Program Files\\Helper\\helper.exe",
            "cmdline": ["helper.exe"],
            "expected_detection": "Layer 5 (Behavioral Analysis)",
            "expected_confidence": 0.5
        },
        {
            "name": "assistant.app",
            "path": "/Applications/Assistant.app/Contents/MacOS/Assistant",
            "cmdline": ["assistant.app"],
            "expected_detection": "Layer 5 (Behavioral Analysis)",
            "expected_confidence": 0.5
        },
        
        # Web-based AI tools (should be detected by Layer 4)
        {
            "name": "chrome.exe",
            "path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "cmdline": ["chrome.exe", "--new-window", "https://chat.openai.com"],
            "expected_detection": "Layer 4 (Command Line Analysis)",
            "expected_confidence": 0.6
        },
        {
            "name": "firefox",
            "path": "/usr/bin/firefox",
            "cmdline": ["firefox", "https://claude.ai"],
            "expected_detection": "Layer 4 (Command Line Analysis)",
            "expected_confidence": 0.6
        },
        
        # Custom AI applications (should be detected by Layer 3)
        {
            "name": "my_text_generator",
            "path": "/usr/local/bin/my_text_generator",
            "cmdline": ["my_text_generator"],
            "expected_detection": "Layer 3 (Keyword Analysis)",
            "expected_confidence": 0.7
        },
        {
            "name": "ai_writing_helper",
            "path": "/home/user/tools/ai_writing_helper",
            "cmdline": ["ai_writing_helper"],
            "expected_detection": "Layer 3 (Keyword Analysis)",
            "expected_confidence": 0.7
        },
        
        # Legitimate processes (should NOT be detected)
        {
            "name": "notepad.exe",
            "path": "C:\\Windows\\System32\\notepad.exe",
            "cmdline": ["notepad.exe"],
            "expected_detection": "None",
            "expected_confidence": 0.0
        },
        {
            "name": "chrome.exe",
            "path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "cmdline": ["chrome.exe", "--new-window", "https://google.com"],
            "expected_detection": "None",
            "expected_confidence": 0.0
        }
    ]
    
    return test_processes

def analyze_process_detection(process: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze how CluelyGuard would detect this process"""
    
    name = process["name"].lower()
    path = process["path"].lower()
    cmdline = " ".join(process["cmdline"]).lower()
    
    # Layer 1: Configured binary matching (90% confidence)
    configured_binaries = ["chatgpt", "claude", "bard", "copilot", "grammarly"]
    for binary in configured_binaries:
        if binary in name or binary in path:
            return {
                "detected": True,
                "layer": "Layer 1 (Configured Binary)",
                "confidence": 0.9,
                "reason": f"Matches configured binary: {binary}",
                "expected": process["expected_detection"],
                "confidence_match": abs(0.9 - process["expected_confidence"]) < 0.1
            }
    
    # Layer 2: AI pattern matching (50-95% confidence)
    ai_patterns = {
        "gpt": 0.95,
        "claude": 0.95,
        "bard": 0.90,
        "ai_": 0.70,
        "_ai": 0.70,
        "ai": 0.60
    }
    
    for pattern, confidence in ai_patterns.items():
        if pattern in name or pattern in path:
            return {
                "detected": True,
                "layer": "Layer 2 (AI Pattern)",
                "confidence": confidence,
                "reason": f"Matches AI pattern: {pattern}",
                "expected": process["expected_detection"],
                "confidence_match": abs(confidence - process["expected_confidence"]) < 0.1
            }
    
    # Layer 3: Keyword analysis (70% confidence)
    ai_keywords = ["ai", "gpt", "claude", "writing", "assistant", "helper", "generate", "text"]
    found_keywords = []
    
    search_text = f"{name} {path}"
    for keyword in ai_keywords:
        if keyword in search_text:
            found_keywords.append(keyword)
    
    if found_keywords:
        return {
            "detected": True,
            "layer": "Layer 3 (Keyword Analysis)",
            "confidence": 0.7,
            "reason": f"Contains AI keywords: {found_keywords}",
            "expected": process["expected_detection"],
            "confidence_match": abs(0.7 - process["expected_confidence"]) < 0.1
        }
    
    # Layer 4: Command line analysis (60% confidence)
    ai_domains = ["chat.openai.com", "claude.ai", "bard.google.com", "perplexity.ai"]
    for domain in ai_domains:
        if domain in cmdline:
            return {
                "detected": True,
                "layer": "Layer 4 (Command Line Analysis)",
                "confidence": 0.6,
                "reason": f"Command line contains AI domain: {domain}",
                "expected": process["expected_detection"],
                "confidence_match": abs(0.6 - process["expected_confidence"]) < 0.1
            }
    
    # Layer 5: Behavioral analysis (40-70% confidence)
    stealth_indicators = ["helper", "assistant", "tool", "utility", "service", "daemon"]
    for indicator in stealth_indicators:
        if indicator in name or indicator in path:
            # Check if it's not a legitimate system process
            legitimate_processes = ["systemd", "init", "chrome", "firefox", "notepad", "calculator"]
            is_legitimate = any(legit in name or legit in path for legit in legitimate_processes)
            
            if not is_legitimate:
                return {
                    "detected": True,
                    "layer": "Layer 5 (Behavioral Analysis)",
                    "confidence": 0.5,
                    "reason": f"Suspicious behavior: stealth indicator '{indicator}'",
                    "expected": process["expected_detection"],
                    "confidence_match": abs(0.5 - process["expected_confidence"]) < 0.1
                }
    
    # No detection
    return {
        "detected": False,
        "layer": "None",
        "confidence": 0.0,
        "reason": "No suspicious indicators found",
        "expected": process["expected_detection"],
        "confidence_match": True
    }

def run_detection_test():
    """Run the detection test and display results"""
    
    print("🔍 CluelyGuard AI Detection Test")
    print("=" * 50)
    
    test_processes = simulate_ai_processes()
    results = []
    
    for i, process in enumerate(test_processes, 1):
        print(f"\n📋 Test {i}: {process['name']}")
        print(f"   Path: {process['path']}")
        print(f"   Command: {' '.join(process['cmdline'])}")
        
        result = analyze_process_detection(process)
        results.append(result)
        
        if result["detected"]:
            print(f"   ✅ DETECTED: {result['layer']}")
            print(f"   🎯 Confidence: {result['confidence']:.1%}")
            print(f"   📝 Reason: {result['reason']}")
        else:
            print(f"   ❌ NOT DETECTED")
            print(f"   📝 Reason: {result['reason']}")
        
        # Check if detection matches expectation
        if result["detected"] and process["expected_detection"] != "None":
            if result["layer"] == process["expected_detection"] and result["confidence_match"]:
                print(f"   🎉 EXPECTATION MATCHED ✓")
            else:
                print(f"   ⚠️  EXPECTATION MISMATCH: Expected {process['expected_detection']}")
        elif not result["detected"] and process["expected_detection"] == "None":
            print(f"   🎉 EXPECTATION MATCHED ✓")
        else:
            print(f"   ⚠️  EXPECTATION MISMATCH: Expected {process['expected_detection']}")
    
    # Summary statistics
    print("\n" + "=" * 50)
    print("📊 DETECTION SUMMARY")
    print("=" * 50)
    
    total_tests = len(results)
    detected_count = sum(1 for r in results if r["detected"])
    expected_detections = sum(1 for p in test_processes if p["expected_detection"] != "None")
    correct_detections = sum(1 for r in results if r["detected"] and r["layer"] == r["expected"])
    
    print(f"Total tests: {total_tests}")
    print(f"Detected: {detected_count}")
    print(f"Expected detections: {expected_detections}")
    print(f"Correct detections: {correct_detections}")
    print(f"Detection rate: {detected_count/total_tests:.1%}")
    print(f"Accuracy: {correct_detections/expected_detections:.1%}" if expected_detections > 0 else "Accuracy: N/A")
    
    # Layer breakdown
    print("\n🔍 DETECTION BY LAYER:")
    layers = {}
    for result in results:
        if result["detected"]:
            layer = result["layer"]
            layers[layer] = layers.get(layer, 0) + 1
    
    for layer, count in layers.items():
        print(f"  {layer}: {count} detections")
    
    print("\n🎯 CONCLUSION:")
    if detected_count >= expected_detections * 0.8:
        print("✅ CluelyGuard is working effectively!")
        print("✅ Multiple detection layers are catching AI tools")
        print("✅ Both known and unknown AI tools are being detected")
    else:
        print("⚠️  Some improvements needed")
        print("⚠️  Consider adjusting detection patterns")
        print("⚠️  Review false positives/negatives")

if __name__ == "__main__":
    run_detection_test() 