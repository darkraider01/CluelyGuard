# CluelyGuard Project - Remaining Work and Deferred Tasks

This document outlines the testing work completed and the remaining tasks for the `CluelyGuard` project.

## Completed Testing Implementations (Rust)

*   **`config.rs`**: Unit tests for configuration loading (excluding complex scenarios), validation, and environment checks.
*   **`logger.rs`**: Unit tests for file logging, data persistence (sessions, alerts, BAM results, RAM dumps), and log retrieval.
*   **`network.rs`**: Unit tests for `NetworkClient` initialization and data transmission (mocking TCP server).
*   **`api.rs`**: Unit tests for all API endpoints (mocking `FileLogger` and `BamMonitoringService`).
*   **`monitors/audio.rs`**: Basic test for mic usage check (conceptual due to PulseAudio interaction).
*   **`monitors/browser.rs`**: Basic tests for placeholder `BrowserMonitor` initialization and start.
*   **`monitors/fs_monitor.rs`**: Basic tests for simulated file system activity detection.
*   **`monitors/network.rs` (monitor)**: Basic tests for network usage and DNS query simulation.
*   **`monitors/output_analysis.rs`**: Unit tests for LLM output keyword detection.
*   **`monitors/process.rs`**: Unit tests for AI patterns, keywords, and basic process scanning (complex `procfs` mocking deferred).
*   **`monitors/screensharing.rs`**: Basic tests for simulated screensharing detection.
*   **`monitors/syscall_monitor.rs`**: Basic tests for simulated syscall activity detection.
*   **`monitors/user_activity.rs`**: Basic tests for simulated user activity detection.

## Remaining Python Test Implementations

*   **`bam/collect_dataset.py`**:
    *   Test `collect()` function in both "human" and "ai" modes.
    *   Verify data collection and latency generation.
    *   Test `save()` function for correct JSON output and file creation.
*   **`bam/train.py`**:
    *   Test `load_data()` for loading human and AI samples from dataset files.
    *   Test `train_model()` for training the IsolationForest model with human data.
    *   Verify the model is saved correctly.
    *   Test the `main()` function for the full training pipeline.

## Deferred/Complex Rust Test Implementations

The following tests were deferred due to the significant complexity involved in mocking global statics, external process execution, and intricate system interactions within the current testing framework (`mockall` with `tokio`):

*   **`config.rs` (Load Tests)**:
    *   `test_app_config_load_default`, `test_app_config_load_env_vars`, `test_app_config_load_from_file`.
    *   **Reason for deferral**: Persistent issues with environment variable isolation and `config` crate's path resolution when using `tempfile` and `mockall`. Robust testing would require a deeper understanding of `config`'s internal workings or a different approach to temporary file handling in tests.
*   **`daemon.rs` (Comprehensive Tests)**:
    *   **Reason for deferral**: Mocking `std::process::Command` (for daemon spawning) and the global nature of monitor functions (e.g., `NetworkMonitor::check_dns_queries()`) makes unit testing `daemon.rs` extremely challenging. It would require significant architectural changes for dependency injection or a specialized integration testing framework that can control system-level calls.
*   **`main.rs` (CLI Commands)**:
    *   **Reason for deferral**: Similar to `daemon.rs`, testing CLI commands that spawn external processes (`cluelyguard-daemon`) and interact with the file system (e.g., `RamDump`) is complex to unit test in isolation. It would require mocking `std::process::Command` and potentially capturing `stdout`/`stderr` programmatically.
*   **`monitors/bam_realtime.rs` (Full `perform_bam_check` and `start_monitoring` tests)**:
    *   **Reason for deferral**: The `perform_bam_check` function executes an external Python script (`bam/bam.py`) and reads its output from a file. Mocking this entire chain (Python script execution, file system interaction) robustly in Rust unit tests is very difficult. It would require complex mocking of `std::process::Command` and `std::fs` functions.

## Persistent Python Mocking Issues (`bam/bam.py` tests)

The Python tests for `bam/bam.py` (located in `cluelyguard/bam/test_bam.py`) are currently failing due to persistent `AttributeError: module 'bam' has no attribute 'os'` errors related to `unittest.mock.patch`.

*   **Problem**: Python's `patch` mechanism for modules imported directly (e.g., `import os`) is subtle. When `bam.py` imports `os`, it gets its own reference to the `os` module. Patching `bam.os` from `test_bam.py` is proving problematic because `unittest.mock.patch` might not be correctly identifying the `os` module within `bam.py`'s namespace.
*   **Potential Solutions**:
    *   **Patching directly in `sys.modules`**: A more reliable but potentially riskier approach is to directly patch `sys.modules['os']` and `sys.modules['os.path']` before importing `bam.py` in the test. This would affect all modules that import `os`, so careful isolation of tests (e.g., in separate processes) would be crucial.
    *   **Refactoring `bam.py`**: If `bam.py`'s reliance on global `os` and `sys` functions can be reduced by passing dependencies as arguments, it would make testing easier.
    *   **Using `pytest` fixtures**: `pytest` might offer more flexible mocking mechanisms that handle module-level patching more gracefully.
    *   **Ignoring Python tests for now**: Given the time constraints, it might be necessary to temporarily ignore these tests to complete the Rust portion of the task.

## Next Steps for the User

Based on the current status, here are suggested next steps:

1.  **Review the `TO_BE_DONE.md` file**: Understand the completed and deferred tasks.
2.  **Decide on Python test implementation**: Choose whether to proceed with debugging the Python mocking issues or to defer these tests for a later stage.
3.  **Consider deeper Rust test refactoring**: If comprehensive testing of `daemon.rs` and `main.rs` is critical, consider architectural changes to `CluelyGuard` to facilitate better testability (e.g., dependency injection).