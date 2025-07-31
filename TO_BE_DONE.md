# CluelyGuard Project - Remaining Work and Deferred Tasks

This document outlines the current status of the `CluelyGuard` project, including completed work, current critical issues, and remaining tasks.

## Completed Architectural & Implementation Tasks (Rust)

*   **Unified Monitoring Coordinator**: Centralized monitor management.
*   **Event Bus System**: Coordinate between all monitors using `mpsc` channels.
*   **Correlation Engine**: Cross-reference events and reduce false positives.
*   **Dynamic Configuration System**: Replaced hardcoded values with external configuration.
*   **YAML/TOML Config Files**: External configuration management via `default.yaml`.
*   **Updated `Cargo.toml`**: Added necessary dependencies (`notify`, `regex`, `serde_json`, etc.).

## Current Critical Issues

*   **`daemon.rs` Compilation Errors**: The `daemon.rs` file currently has unresolved compilation errors related to type mismatches when passing `Arc<RwLock<AppConfig>>` and initializing monitor services. This prevents the "Runtime Configuration Updates - Hot-reload capabilities" from being fully functional and integrated into the main daemon logic. These errors need to be addressed before the system can compile and run correctly.

## Remaining Tasks

### Core System Enhancements

*   **Runtime Configuration Updates - Hot-reload capabilities**: (Partially Implemented - Core watcher is in place, but integration with main daemon is blocked by compilation errors). Full integration requires resolving current `daemon.rs` issues.
*   **Async/Await Refactoring**: Convert polling mechanisms in monitors to event-driven approaches where possible.
*   **Resource Limits & Throttling**: Implement mechanisms to prevent system overload and manage resource consumption.
*   **Memory Management**: Ensure proper cleanup and resource handling to avoid memory leaks.

### Build & Deployment

*   **Build Scripts**: Develop scripts for system dependency installation and simplified build processes.
*   **Capability Management**: Implement methods to set required Linux capabilities for privileged operations.
*   **CI/CD Pipeline**: Set up a GitHub Actions workflow for automated testing and deployment.

### Testing & Quality Assurance

*   **Integration Tests**: Develop comprehensive integration tests for the full monitoring pipeline.
*   **Mock Scenarios**: Create realistic AI usage test cases for thorough system validation.
*   **Deferred/Complex Rust Test Implementations**:
    *   **`config.rs` (Load Tests)**: Address persistent issues with environment variable isolation and `config` crate's path resolution.
    *   **`daemon.rs` (Comprehensive Tests)**: Requires significant architectural changes for dependency injection or a specialized integration testing framework.
    *   **`main.rs` (CLI Commands)**: Requires mocking `std::process::Command` and capturing `stdout`/`stderr` programmatically.
    *   **`monitors/bam_realtime.rs` (Full `perform_bam_check` and `start_monitoring` tests)**: Requires complex mocking of `std::process::Command` and `std::fs` functions.
*   **Python Test Implementations**:
    *   **`bam/collect_dataset.py`**: Test `collect()` and `save()` functions.
    *   **`bam/train.py`**: Test `load_data()`, `train_model()`, and `main()` functions.
    *   **Persistent Python Mocking Issues (`bam/bam.py` tests)**: Resolve `AttributeError: module 'bam' has no attribute 'os'` errors.

### Security & Privacy

*   **Privilege Management**: Implement capability-based security to minimize attack surface.
*   **Data Encryption**: Protect sensitive monitoring data at rest and in transit.
*   **Privacy Controls**: Ensure compliance with data privacy regulations (e.g., GDPR/CCPA).