# CluelyGuard - Advanced Anti-LLM Detection System (Rust Implementation)

A comprehensive GUI application built in Rust for detecting AI usage and preventing unauthorized assistance during exams, assessments, and secure environments.

## 🚀 Features

### Core Detection Capabilities
- **🌐 Browser Extension Detection**: Scans Chrome, Firefox, Edge for AI-powered extensions
- **⚙️ Process Monitoring**: Real-time detection of AI desktop applications  
- **🌍 Network Analysis**: Monitors connections to AI service endpoints
- **🖥️ Screen Analysis**: Optional screenshot analysis with OCR for AI interfaces
- **📁 Filesystem Monitoring**: Real-time file system watching for suspicious activities
- **🧠 Behavioral Analysis**: Advanced pattern recognition and threat assessment

### Advanced AI Detection
- **ChatGPT/Claude/Gemini Detection**: Identifies popular AI assistants
- **Code Assistant Detection**: Finds GitHub Copilot, Tabnine, CodeWhisperer
- **Writing Tool Detection**: Detects Grammarly, Jasper, WriteSonic, Copy.ai
- **Stealth AI Detection**: Advanced techniques for hidden AI usage
- **Real-time Monitoring**: Continuous background detection with async processing
- **Smart Whitelisting**: Reduces false positives with intelligent filtering

### Professional GUI (egui-based)
- **Modern Interface**: Fast, native Rust GUI with dark theme
- **Real-time Dashboard**: Live monitoring status and threat indicators
- **Module Configuration**: Easy-to-use detection module settings
- **Comprehensive Logging**: Detailed event logging with filtering
- **Report Generation**: Export capabilities in multiple formats
- **System Tray Integration**: Background operation support

## 📋 System Requirements

### Minimum Requirements
- **Operating System**: Windows 10+, macOS 10.14+, Ubuntu 18.04+
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 500MB free disk space
- **CPU**: x64 processor with SSE2 support
- **Permissions**: Administrator/sudo for comprehensive monitoring

### Recommended Requirements
- **RAM**: 16GB for optimal performance
- **Storage**: 2GB free space for logs and reports
- **Network**: Internet connection for domain resolution
- **Display**: 1920x1080 resolution for optimal GUI experience

## 🔧 Installation

### Prerequisites
1. **Install Rust** (version 1.70.0 or later):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

2. **System Dependencies**:

   **Windows**:
   ```powershell
   # Visual Studio Build Tools required
   # Install from: https://visualstudio.microsoft.com/downloads/
   ```

   **Linux (Ubuntu/Debian)**:
   ```bash
   sudo apt update
   sudo apt install build-essential libssl-dev pkg-config
   sudo apt install libasound2-dev  # For audio monitoring
   sudo apt install libxcb1-dev libxrandr-dev libxss-dev  # For screen capture
   ```

   **macOS**:
   ```bash
   xcode-select --install
   brew install openssl
   ```

### Build from Source
```bash
# Clone the repository
git clone https://github.com/darkraider01/CluelyGuard.git
cd CluelyGuard

# Build in release mode
cargo build --release --features screen-monitoring

# Run the application
./target/release/cluely-guard
```

### Quick Setup Script
```bash
# Make build script executable
chmod +x build.sh

# Run build script
./build.sh
```

## 🖥️ Usage

### Basic Operation
1. Launch the application:
   ```bash
   ./target/release/cluely-guard
   ```

2. **Configure Detection Modules**:
   - Navigate to the "🔧 Modules" tab
   - Enable/disable detection modules as needed
   - Adjust sensitivity levels for each module
   - Configure whitelists and custom patterns

3. **Start Monitoring**:
   - Click "▶️ Start Monitoring" in the toolbar
   - Monitor real-time status in the Dashboard
   - View detection events in the activity feed

4. **Review Results**:
   - Check detailed logs in the "📝 Logs" tab
   - Generate comprehensive reports in the "📈 Reports" tab
   - Export data in multiple formats (HTML, CSV, JSON)

### Command Line Options
```bash
# Start with custom config
cluely-guard --config /path/to/config.toml

# Start minimized to system tray
cluely-guard --minimized

# Enable debug logging
RUST_LOG=debug cluely-guard

# Run specific detection modules only
cluely-guard --modules browser,process,network
```

### Configuration File
Edit `~/.config/CluelyGuard/config.toml`:
```toml
[app]
name = "CluelyGuard"
auto_start_monitoring = false
save_reports = true

[detection.browser_extensions]
scan_chrome = true
scan_firefox = true
scan_edge = true

[detection.process_monitor]
scan_interval_ms = 2000
monitor_command_line = true
monitor_child_processes = true

[detection.network_monitor]
scan_interval_ms = 5000
monitor_dns = true
monitor_websockets = true

[ui]
theme = "dark"
start_minimized = false
show_notifications = true
```

## 🔍 Detection Modules

### Browser Extension Detector
**Capabilities:**
- Chrome, Firefox, Edge extension scanning
- 20+ known AI extensions database
- Web-accessible resource probing
- Permission-based risk analysis
- Real-time installation monitoring

**Detected Extensions:**
- ChatGPT applications and assistants
- Claude AI browser extensions  
- Gemini and Google AI tools
- GitHub Copilot browser integration
- Grammarly and writing assistants
- Custom AI-powered extensions

### Process Monitor
**Capabilities:**
- Real-time process enumeration
- Command-line argument analysis
- Parent-child process tracking
- Pattern-based AI application detection
- Memory and CPU usage monitoring

**Detected Applications:**
- ChatGPT desktop applications
- Claude desktop clients
- AI coding assistants (Copilot, Tabnine)
- Writing tools (Jasper, WriteSonic)
- Stealth and headless AI processes

### Network Monitor  
**Capabilities:**
- Active connection monitoring
- DNS query analysis
- Domain-based AI service detection
- Port-based suspicious activity detection
- WebSocket connection tracking

**Monitored Endpoints:**
- OpenAI (ChatGPT, GPT-4, API)
- Anthropic (Claude)
- Google AI (Gemini, Bard)
- GitHub Copilot services
- Writing assistant APIs
- Custom AI service endpoints

### Screen Monitor (Optional)
**Capabilities:**
- Periodic screenshot capture
- OCR-based text analysis
- AI interface template matching
- Color-based UI detection
- Multi-monitor support

**Detected Interfaces:**
- ChatGPT web interface
- Claude conversation view
- Gemini chat interface
- Code assistant overlays
- Writing tool suggestions

### Filesystem Monitor
**Capabilities:**
- Real-time file system watching
- Suspicious file pattern detection
- Download folder monitoring
- AI-generated content identification
- Temporary file analysis

## 📊 Performance

### Resource Usage
- **CPU**: 2-5% during active monitoring
- **Memory**: 50-100MB typical usage
- **Disk**: <1MB/hour for logs
- **Network**: Minimal, DNS queries only

### Detection Speed
- **Browser Extensions**: <100ms scan time
- **Process Monitoring**: <50ms per scan
- **Network Analysis**: <200ms per scan
- **Real-time Events**: <10ms detection latency

## 🔒 Security & Privacy

### Data Protection
- **100% Local Processing**: No data sent to external servers
- **Encrypted Storage**: Optional log file encryption
- **Secure Memory**: Sensitive data cleared from memory
- **Access Control**: Admin privileges required for full monitoring

### Privacy Features
- **Minimal Data Collection**: Only detection-relevant information
- **User Control**: Full control over monitoring and data retention
- **Audit Trail**: Complete logging of all system activities
- **Data Retention**: Configurable log rotation and deletion

## 🔧 Development

### Project Structure
```
CluelyGuard/
├── Cargo.toml                 # Project configuration
├── src/
│   ├── main.rs               # Application entry point
│   ├── app.rs                # Main application logic
│   ├── config.rs             # Configuration management
│   ├── logging.rs            # Logging setup
│   ├── utils.rs              # Utility functions
│   ├── detection/            # Detection engine
│   │   ├── mod.rs
│   │   ├── engine.rs         # Main detection coordinator
│   │   ├── types.rs          # Common types and structures
│   │   ├── browser_extensions.rs
│   │   ├── process_monitor.rs
│   │   ├── network_monitor.rs
│   │   ├── screen_monitor.rs
│   │   └── filesystem_monitor.rs
│   └── gui/                  # GUI components
│       ├── mod.rs
│       ├── dashboard.rs      # Dashboard tab
│       ├── modules.rs        # Modules configuration tab
│       ├── logs.rs           # Logs viewing tab
│       ├── settings.rs       # Settings tab
│       └── reports.rs        # Reports generation tab
├── assets/                   # Application assets
├── docs/                     # Documentation
└── tests/                    # Test suites
```

### Building
```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Build with screen monitoring
cargo build --release --features screen-monitoring

# Run tests
cargo test

# Generate documentation
cargo doc --open

# Format code
cargo fmt

# Run clippy for linting
cargo clippy
```

### Dependencies
Key Rust crates used:
- **eframe/egui**: Modern immediate-mode GUI
- **tokio**: Async runtime for concurrent operations
- **sysinfo**: System and process monitoring
- **notify**: Filesystem event monitoring
- **serde**: Serialization and configuration
- **tracing**: Structured logging
- **anyhow**: Error handling
- **chrono**: Date and time utilities

## 📈 Benchmarks

### Detection Performance
- **Browser Extensions**: 50+ extensions scanned in <100ms
- **Process Monitoring**: 1000+ processes analyzed in <50ms  
- **Network Connections**: 500+ connections checked in <200ms
- **Filesystem Events**: Real-time processing with <10ms latency

### System Impact
- **CPU Usage**: 2-5% average during active monitoring
- **Memory Footprint**: 50-100MB typical usage
- **Disk I/O**: <1MB/hour logging overhead
- **Network Usage**: Minimal DNS queries only

## 🔄 Updates & Maintenance

### Auto-Updates
- Built-in update checker
- Secure binary verification
- Incremental updates for efficiency
- Rollback capability for safety

### Maintenance Tasks
- Automatic log rotation
- Database cleanup and optimization
- Configuration backup and restore
- Performance monitoring and alerting

## 📞 Support & Troubleshooting

### Common Issues

**Issue**: Permission denied errors
**Solution**: Run with administrator/sudo privileges
```bash
# Linux/macOS
sudo ./target/release/cluely-guard

# Windows (run PowerShell as Administrator)
.	arget
elease\cluely-guard.exe
```

**Issue**: GUI doesn't start
**Solution**: Check system requirements and dependencies
```bash
# Linux - install missing libraries
sudo apt install libxcb1-dev libxrandr-dev libxss-dev

# Update graphics drivers
# Restart the application
```

**Issue**: High CPU usage
**Solution**: Adjust monitoring intervals
```toml
# Edit config.toml
[detection.process_monitor]
scan_interval_ms = 5000  # Increase from default 2000

[detection.network_monitor]  
scan_interval_ms = 10000  # Increase from default 5000
```

**Issue**: False positive detections
**Solution**: Configure whitelists and adjust sensitivity
- Add legitimate processes to whitelist
- Lower sensitivity levels for specific modules
- Review and customize detection patterns

### Logging
Enable debug logging for troubleshooting:
```bash
RUST_LOG=debug ./target/release/cluely-guard
```

Log files location:
- **Linux**: `~/.local/share/CluelyGuard/logs/`
- **macOS**: `~/Library/Application Support/CluelyGuard/logs/`
- **Windows**: `%LOCALAPPDATA%\CluelyGuard\logs\`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make your changes and add tests
4. Run the test suite: `cargo test`
5. Format code: `cargo fmt`
6. Run clippy: `cargo clippy`
7. Commit your changes: `git commit -m "Add new feature"`
8. Push to the branch: `git push origin feature/new-feature`
9. Submit a pull request

### Development Guidelines
- Follow Rust naming conventions
- Write comprehensive tests
- Document public APIs
- Use `tracing` for logging
- Handle errors with `anyhow`
- Keep modules focused and cohesive

## ⚠️ Disclaimer

CluelyGuard is designed for legitimate security and monitoring purposes. Users are responsible for complying with applicable laws and regulations regarding monitoring and privacy. This software should only be used in environments where you have explicit permission to monitor system activities.

---

**CluelyGuard Rust Implementation**  
🛡️ Advanced • ⚡ Fast • 🎯 Accurate • 🔧 Configurable • 🔒 Secure

Built with ❤️ in Rust using egui
