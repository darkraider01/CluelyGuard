//! Utility functions and helpers

use anyhow::Result;
use std::path::Path;

/// Calculate file hash for deduplication
pub fn calculate_file_hash<P: AsRef<Path>>(path: P) -> Result<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let content = std::fs::read(path)?;
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    Ok(format!("{:x}", hasher.finish()))
}

/// Format file size in human readable format
pub fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;

    if size == 0 {
        return "0 B".to_string();
    }

    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

/// Check if a process name matches any AI-related patterns
pub fn is_ai_related_process(process_name: &str) -> bool {
    let ai_patterns = [
        "chatgpt", "claude", "gemini", "copilot", "openai", 
        "anthropic", "tabnine", "grammarly", "jasper", "ai-"
    ];

    let name_lower = process_name.to_lowercase();
    ai_patterns.iter().any(|pattern| name_lower.contains(pattern))
}

/// Sanitize filename for safe file operations
pub fn sanitize_filename(filename: &str) -> String {
    let invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
    filename
        .chars()
        .map(|c| if invalid_chars.contains(&c) { '_' } else { c })
        .collect()
}

/// Get current system timestamp as string
pub fn get_timestamp_string() -> String {
    chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string()
}

/// Check if current user has admin privileges
pub fn is_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::processthreadsapi::OpenProcessToken;
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use std::mem;

        unsafe {
            let mut token = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }

            let mut elevation: TOKEN_ELEVATION = mem::zeroed();
            let mut size = mem::size_of::<TOKEN_ELEVATION>() as u32;

            if GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                size,
                &mut size,
            ) == 0 {
                return false;
            }

            elevation.TokenIsElevated != 0
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // For Unix-like systems, check if running as root
        unsafe { libc::geteuid() == 0 }
    }
}

/// Create application directories
pub fn create_app_directories() -> Result<()> {
    let config_dir = dirs::config_dir()
        .unwrap_or_default()
        .join("CluelyGuard");
    std::fs::create_dir_all(&config_dir)?;

    let data_dir = dirs::data_local_dir()
        .unwrap_or_default()
        .join("CluelyGuard");
    std::fs::create_dir_all(&data_dir)?;

    let logs_dir = data_dir.join("logs");
    std::fs::create_dir_all(&logs_dir)?;

    let reports_dir = dirs::document_dir()
        .unwrap_or_default()
        .join("CluelyGuard")
        .join("Reports");
    std::fs::create_dir_all(&reports_dir)?;

    Ok(())
}
