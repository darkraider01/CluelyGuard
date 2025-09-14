//! GUI components and tabs

pub mod dashboard_tab;
pub mod modules_tab;
pub mod tabs;

pub use dashboard_tab::DashboardTab;
pub use modules_tab::ModulesTab;
pub use tabs::{LogsTab, SettingsTab, ReportsTab};