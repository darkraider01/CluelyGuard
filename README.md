# CluelyGuard - Universal Linux Anti-LLM Proctoring System 🕵️

> **"Because sometimes students get a little too creative with their AI friends during exams"**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-blue.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-3.8+-green.svg)](https://www.python.org/)
[![Linux](https://img.shields.io/badge/Linux-All%20Distros-orange.svg)](https://www.linux.org/)

## 🎯 What is CluelyGuard?

CluelyGuard is an **industrial-grade Linux anti-cheat system** designed to detect and prevent AI-assisted cheating during proctored exams and interviews. It specifically targets AI tools like Cluely, ChatGPT, Claude, and other LLM-based assistants by monitoring user behavior, system processes, overlays, audio, and network activity while respecting Linux's privacy and performance expectations.

### 🚨 The Problem
AI tools like Cluely offer stealthy overlays and real-time answers during live assessments. Existing anti-cheat systems, especially on Linux, lack the capability to detect such tools due to user-space privacy constraints and distribution fragmentation.

### ✅ The Solution
A **modular, privacy-respecting Linux system** that detects LLM-based cheating through:
- **Process and overlay analysis**
- **Audio and network monitoring** 
- **Behavioral anomaly detection**
- **Multi-display protocol support** (X11, Wayland, Mir)

## 🏗️ Architecture Overview

```
┌─────────────────┐
│  Teacher's PC   │
│ (Log Receiver)  │
└────────▲────────┘
         │ [Real-time Logs]
         │
┌────────┼────────┐
│ CLI: CluelyGuard │
└────────┬────────┘
         │
┌────────┼────────┐
│        │        │
│Process │Audio/Mic│
│Monitor │Monitor  │
│        │        │
└────────┼────────┘
         │
┌────────▼────────┐
│   BAM (ML)      │
└────────┬────────┘
         │
┌────────▼────────┐
│ Network Monitor  │
└─────────────────┘
```

## 🚀 Quick Start (Universal Installation)

### One-Command Installation (Works on ANY Linux Distribution!)

```bash
# Clone the repository
git clone https://github.com/yourusername/cluelyguard.git
cd cluelyguard

# Universal installation (works on all Linux distros!)
# WARNING: This script will install and configure CluelyGuard to run as a system service.
# It requires root privileges for system-level monitoring.
sudo ./install.sh

# Start the service
sudo systemctl start cluelyguard

# Test it works
cluelyguard status
```

## 🐧 Universal Linux Support

CluelyGuard works on **ALL Linux distributions** through intelligent package manager detection:

### ✅ **Fully Supported Distributions**

| Distribution Family | Examples | Package Manager |
|-------------------|----------|----------------|
| **Arch-based** | Arch, Manjaro, Garuda, EndeavourOS | `pacman` |
| **Debian-based** | Ubuntu, Debian, Linux Mint, Pop!_OS | `apt` |
| **RHEL/Fedora** | Fedora, CentOS, RHEL, Rocky Linux | `dnf`/`yum` |
| **openSUSE** | Tumbleweed, Leap, SLE | `zypper` |
| **Gentoo** | Gentoo, Funtoo | `emerge` |
| **Independent** | Void, Alpine, NixOS, Slackware | Various |

### 🔧 **Automatic Detection Features**
- **Package Manager Detection**: Automatically finds the right package manager
- **Distribution-Agnostic Packages**: Maps generic names to distro-specific packages
- **Fallback Installation**: Source compilation if packages aren't available
- **System Requirements Check**: Validates kernel, memory, and disk space

## 🧠 How Detection Works

### 1. 👁️ **Process Monitoring**
```rust
// Detects AI tools by process name, path, and behavior
- ChatGPT, Claude, Bard, Perplexity
- Custom AI tools (configurable)
- Suspicious command-line arguments
- Memory pattern analysis (LLM libraries, data structures)
- File access pattern analysis (LLM model files)
```

### 2. 🎤 **Audio Monitoring**
```rust
// Monitors microphone usage for AI assistance
- PulseAudio/PipeWire integration
- Detects unauthorized mic activity
- Flags voice-to-text usage during exams
- Whitelists legitimate apps (Zoom, Meet)
```

### 3. 🌐 **Network Monitoring (DPI)**
```rust
// Detects AI service connections and data exfiltration
- DNS monitoring for AI domains
- Placeholder for Deep Packet Inspection (DPI) for obfuscated traffic
- Placeholder for network traffic pattern analysis
```

### 4. 🖥️ **Screensharing Detection**
```rust
// Detects active screensharing sessions or applications
- Placeholder for checking known screensharing processes (Zoom, TeamViewer, OBS)
- Placeholder for display server activity monitoring (X11/Wayland)
```

### 5. 💾 **File System Monitoring**
```rust
// Monitors file system events for suspicious activity
- Placeholder for inotify/fanotify integration
- Placeholder for detecting creation/modification of LLM-related files
```

### 6. ⚙️ **System Call (Syscall) Monitoring**
```rust
// Observes low-level process interactions with the kernel
- Placeholder for auditd/eBPF integration
- Placeholder for detecting unusual syscall patterns indicative of AI
```

### 7. 👤 **User Activity Monitoring**
```rust
// Tracks user interactions and commands
- Placeholder for monitoring shell commands and history
- Placeholder for clipboard content analysis
```

### 8. 🧠 **Behavioral Analysis (BAM)**
```python
# Machine learning-based typing pattern analysis
- IsolationForest anomaly detection
- Typing latency analysis
- Human vs AI pattern recognition
- Real-time confidence scoring
```

### 9. 📝 **Output Analysis**
```rust
// Analyzes generated content for statistical markers of LLM usage
- Placeholder for NLP techniques (perplexity, burstiness)
- Placeholder for machine learning models to classify text
```

## 🎯 Usage Examples

### For Teachers/Administrators

```bash
# Start monitoring a student's exam (logs sent to teacher's PC)
sudo cluelyguard daemon --student-code "unique-exam-code-123"

# On Teacher's PC, you would run a log collection server (not part of this repo)
# Example: nc -l -p 8081 > student_logs.json
```

### For Students (What They Experience)

1. **Before Exam**: Teacher provides a unique code, student starts CluelyGuard daemon with `sudo` and the code.
2. **During Exam**: System runs in background, monitoring for AI usage and sending logs to teacher's PC.
3. **If Cheating Detected**: Real-time alerts sent to teacher's PC.
4. **After Exam**: Teacher reviews collected logs.

## 📊 Detection Capabilities

### 🚨 **High-Risk Activities Detected**
- **AI Chat Tools**: ChatGPT, Claude, Bard, Perplexity, Poe
- **AI Writing Tools**: Jasper, Copy.ai, Writesonic, Grammarly
- **AI Coding Tools**: GitHub Copilot, Replit, CodeSandbox
- **Stealth Overlays**: Cluely, transparent windows, click-through overlays
- **Voice Dictation**: Unauthorized microphone usage
- **Suspicious Browsing**: AI service websites and extensions

### 📈 **Report Features**
- **Session Timeline**: When each suspicious activity occurred
- **Confidence Scores**: How likely AI was used (0-100%)
- **Process Details**: Which specific tools were detected
- **Network Activity**: AI service connections and patterns
- **Behavioral Analysis**: Typing pattern anomalies
- **Audio Logs**: Microphone usage patterns

## ⚙️ Configuration

### Basic Configuration (`config/local.yaml`)

```yaml
# Monitoring intervals
monitoring:
  bam:
    check_interval_seconds: 5
    anomaly_threshold: 0.8
  
  process:
    scan_interval_seconds: 30
    suspicious_binaries:
      - "chatgpt"
      - "claude"
      - "bard"
      - "cluely"
      - "your-custom-ai-tool"
  
  audio:
    enabled: true
    whitelisted_apps:
      - "zoom"
      - "teams"
      - "meet"
  
  browser:
    enabled: true
    overlay_detection: true
    ai_domains:
      - "chat.openai.com"
      - "claude.ai"
      - "bard.google.com"

# Alert configuration
alerts:
  enabled: true
  webhook_url: "https://your-slack-webhook.com"
  email:
    recipients: ["teacher@school.edu"]
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
  
  thresholds:
    bam_anomaly_score: 0.8
    process_confidence: 0.7
    overlay_confidence: 0.9


```

