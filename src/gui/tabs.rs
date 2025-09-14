//! Complete GUI Tab Implementations - Logs, Settings, Reports

use eframe::egui;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::detection::{DetectionEvent, ThreatLevel, DetectionModule};

// ========== LOGS TAB ==========
pub struct LogsTab {
    log_entries: Vec<LogEntry>,
    filter_level: ThreatLevel,
    filter_module: Option<DetectionModule>,
    search_text: String,
    auto_scroll: bool,
    max_entries: usize,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: ThreatLevel,
    pub module: DetectionModule,
    pub message: String,
    pub details: String,
}

impl LogsTab {
    pub fn new() -> Self {
        Self {
            log_entries: Vec::new(),
            filter_level: ThreatLevel::Info,
            filter_module: None,
            search_text: String::new(),
            auto_scroll: true,
            max_entries: 1000,
        }
    }

    pub fn add_log_entry(&mut self, event: &DetectionEvent) {
        let entry = LogEntry {
            timestamp: event.timestamp,
            level: event.threat_level.clone(),
            module: event.module.clone(),
            message: event.description.clone(),
            details: format!("{:?}", event.details),
        };

        self.log_entries.insert(0, entry);
        
        // Keep only max_entries
        if self.log_entries.len() > self.max_entries {
            self.log_entries.truncate(self.max_entries);
        }
    }

    pub fn render(&mut self, ui: &mut egui::Ui) {
        ui.heading("📝 Detection Logs");
        ui.separator();

        // Filter controls
        ui.horizontal(|ui| {
            ui.label("Filter by Level:");
            egui::ComboBox::from_label("")
                .selected_text(format!("{:?}", self.filter_level))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.filter_level, ThreatLevel::Critical, "Critical");
                    ui.selectable_value(&mut self.filter_level, ThreatLevel::High, "High");
                    ui.selectable_value(&mut self.filter_level, ThreatLevel::Medium, "Medium");
                    ui.selectable_value(&mut self.filter_level, ThreatLevel::Low, "Low");
                    ui.selectable_value(&mut self.filter_level, ThreatLevel::Info, "Info");
                });

            ui.separator();

            ui.label("Filter by Module:");
            egui::ComboBox::from_label("")
                .selected_text(
                    self.filter_module
                        .as_ref()
                        .map(|m| m.name())
                        .unwrap_or("All")
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.filter_module, None, "All");
                    ui.selectable_value(&mut self.filter_module, Some(DetectionModule::BrowserExtensions), "Browser Extensions");
                    ui.selectable_value(&mut self.filter_module, Some(DetectionModule::ProcessMonitor), "Process Monitor");
                    ui.selectable_value(&mut self.filter_module, Some(DetectionModule::NetworkMonitor), "Network Monitor");
                    ui.selectable_value(&mut self.filter_module, Some(DetectionModule::ScreenMonitor), "Screen Monitor");
                    ui.selectable_value(&mut self.filter_module, Some(DetectionModule::FilesystemMonitor), "Filesystem Monitor");
                });

            ui.separator();

            ui.label("Search:");
            ui.text_edit_singleline(&mut self.search_text);

            ui.separator();

            ui.checkbox(&mut self.auto_scroll, "Auto-scroll");

            if ui.button("🗑️ Clear Logs").clicked() {
                self.log_entries.clear();
            }

            if ui.button("💾 Export Logs").clicked() {
                // Export functionality would go here
            }
        });

        ui.separator();

        // Log entries
        let filtered_entries: Vec<_> = self.log_entries
            .iter()
            .filter(|entry| {
                // Filter by level (show this level and higher)
                let level_match = entry.level >= self.filter_level;
                
                // Filter by module
                let module_match = self.filter_module
                    .as_ref()
                    .map(|m| &entry.module == m)
                    .unwrap_or(true);
                
                // Filter by search text
                let search_match = if self.search_text.is_empty() {
                    true
                } else {
                    entry.message.to_lowercase().contains(&self.search_text.to_lowercase()) ||
                    entry.details.to_lowercase().contains(&self.search_text.to_lowercase())
                };
                
                level_match && module_match && search_match
            })
            .collect();

        ui.label(format!("Showing {} of {} log entries", filtered_entries.len(), self.log_entries.len()));

        egui::ScrollArea::vertical()
            .stick_to_bottom(self.auto_scroll)
            .show(ui, |ui| {
                for entry in filtered_entries {
                    self.render_log_entry(ui, entry);
                }
            });
    }

    fn render_log_entry(&self, ui: &mut egui::Ui, entry: &LogEntry) {
        let (icon, color) = match entry.level {
            ThreatLevel::Critical => ("🚨", egui::Color32::from_rgb(220, 53, 69)),
            ThreatLevel::High => ("⚠️", egui::Color32::from_rgb(253, 126, 20)),
            ThreatLevel::Medium => ("⚡", egui::Color32::from_rgb(255, 193, 7)),
            ThreatLevel::Low => ("ℹ️", egui::Color32::from_rgb(23, 162, 184)),
            ThreatLevel::Info => ("💡", egui::Color32::from_rgb(23, 162, 184)),
            ThreatLevel::Unknown => ("❓", egui::Color32::GRAY),
        };

        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.colored_label(color, icon);
                ui.label(entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string());
                ui.colored_label(color, format!("[{}]", entry.level as u8));
                ui.label(format!("[{}]", entry.module.name()));
            });

            ui.label(&entry.message);

            if ui.small_button("Show Details").clicked() {
                // Toggle details view
            }
        });

        ui.add_space(5.0);
    }
}

// ========== SETTINGS TAB ==========
pub struct SettingsTab {
    temp_config: Config,
    config_modified: bool,
    show_advanced: bool,
}

impl SettingsTab {
    pub fn new(config: Config) -> Self {
        Self {
            temp_config: config.clone(),
            config_modified: false,
            show_advanced: false,
        }
    }

    pub fn render(&mut self, ui: &mut egui::Ui, config: &mut Config) {
        ui.heading("⚙️ Settings");
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Application Settings
            ui.collapsing("🖥️ Application Settings", |ui| {
                ui.horizontal(|ui| {
                    ui.label("Theme:");
                    egui::ComboBox::from_id_source("theme")
                        .selected_text(&self.temp_config.ui.theme)
                        .show_ui(ui, |ui| {
                            if ui.selectable_value(&mut self.temp_config.ui.theme, "dark".to_string(), "Dark").clicked() {
                                self.config_modified = true;
                            }
                            if ui.selectable_value(&mut self.temp_config.ui.theme, "light".to_string(), "Light").clicked() {
                                self.config_modified = true;
                            }
                        });
                });

                if ui.checkbox(&mut self.temp_config.ui.start_minimized, "Start minimized").changed() {
                    self.config_modified = true;
                }

                if ui.checkbox(&mut self.temp_config.ui.show_notifications, "Show notifications").changed() {
                    self.config_modified = true;
                }

                if ui.checkbox(&mut self.temp_config.app.auto_start_monitoring, "Auto-start monitoring").changed() {
                    self.config_modified = true;
                }
            });

            // Detection Settings
            ui.collapsing("🔍 Detection Settings", |ui| {
                if let Some(ref mut detection_config) = self.temp_config.detection {
                    // Browser Extensions
                    ui.group(|ui| {
                        ui.label("🌐 Browser Extensions");
                        if ui.checkbox(&mut detection_config.browser_extensions.scan_chrome, "Scan Chrome").changed() {
                            self.config_modified = true;
                        }
                        if ui.checkbox(&mut detection_config.browser_extensions.scan_firefox, "Scan Firefox").changed() {
                            self.config_modified = true;
                        }
                        if ui.checkbox(&mut detection_config.browser_extensions.scan_edge, "Scan Edge").changed() {
                            self.config_modified = true;
                        }
                    });

                    // Process Monitor
                    ui.group(|ui| {
                        ui.label("⚙️ Process Monitor");
                        ui.horizontal(|ui| {
                            ui.label("Scan Interval (ms):");
                            if ui.add(egui::DragValue::new(&mut detection_config.process_monitor.scan_interval_ms).range(1000..=60000)).changed() {
                                self.config_modified = true;
                            }
                        });

                        if ui.checkbox(&mut detection_config.process_monitor.monitor_command_line, "Monitor Command Line").changed() {
                            self.config_modified = true;
                        }
                    });

                    // Network Monitor
                    ui.group(|ui| {
                        ui.label("🌍 Network Monitor");
                        ui.horizontal(|ui| {
                            ui.label("Scan Interval (ms):");
                            if ui.add(egui::DragValue::new(&mut detection_config.network_monitor.scan_interval_ms).range(1000..=30000)).changed() {
                                self.config_modified = true;
                            }
                        });

                        if ui.checkbox(&mut detection_config.network_monitor.monitor_dns, "Monitor DNS").changed() {
                            self.config_modified = true;
                        }
                    });

                    // Screen Monitor
                    ui.group(|ui| {
                        ui.label("🖥️ Screen Monitor");
                        if ui.checkbox(&mut detection_config.screen_monitor.enabled, "Enable Screen Monitoring").changed() {
                            self.config_modified = true;
                        }

                        if detection_config.screen_monitor.enabled {
                            ui.horizontal(|ui| {
                                ui.label("Capture Interval (ms):");
                                if ui.add(egui::DragValue::new(&mut detection_config.screen_monitor.capture_interval_ms).range(5000..=300000)).changed() {
                                    self.config_modified = true;
                                }
                            });

                            ui.horizontal(|ui| {
                                ui.label("Confidence Threshold:");
                                if ui.add(egui::Slider::new(&mut detection_config.screen_monitor.confidence_threshold, 0.0..=1.0)).changed() {
                                    self.config_modified = true;
                                }
                            });
                        }
                    });
                }
            });

            // Logging Settings
            ui.collapsing("📝 Logging Settings", |ui| {
                ui.horizontal(|ui| {
                    ui.label("Log Level:");
                    egui::ComboBox::from_id_source("log_level")
                        .selected_text(&self.temp_config.logging.level)
                        .show_ui(ui, |ui| {
                            if ui.selectable_value(&mut self.temp_config.logging.level, "error".to_string(), "Error").clicked() {
                                self.config_modified = true;
                            }
                            if ui.selectable_value(&mut self.temp_config.logging.level, "warn".to_string(), "Warn").clicked() {
                                self.config_modified = true;
                            }
                            if ui.selectable_value(&mut self.temp_config.logging.level, "info".to_string(), "Info").clicked() {
                                self.config_modified = true;
                            }
                            if ui.selectable_value(&mut self.temp_config.logging.level, "debug".to_string(), "Debug").clicked() {
                                self.config_modified = true;
                            }
                        });
                });

                if ui.checkbox(&mut self.temp_config.logging.file_enabled, "Enable file logging").changed() {
                    self.config_modified = true;
                }

                ui.horizontal(|ui| {
                    ui.label("Max log files:");
                    if ui.add(egui::DragValue::new(&mut self.temp_config.logging.max_files).range(1..=50)).changed() {
                        self.config_modified = true;
                    }
                });
            });

            ui.add_space(20.0);

            // Save/Reset buttons
            ui.horizontal(|ui| {
                if ui.button("💾 Save Settings").clicked() && self.config_modified {
                    *config = self.temp_config.clone();
                    self.config_modified = false;
                    
                    // Save to file
                    let config_clone = config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = config_clone.save().await {
                            eprintln!("Failed to save config: {}", e);
                        }
                    });
                }

                if ui.button("🔄 Reset to Defaults").clicked() {
                    self.temp_config = Config::default();
                    self.config_modified = true;
                }

                if ui.button("❌ Cancel Changes").clicked() && self.config_modified {
                    self.temp_config = config.clone();
                    self.config_modified = false;
                }
            });

            if self.config_modified {
                ui.colored_label(egui::Color32::from_rgb(255, 193, 7), "⚠️ Settings modified - remember to save!");
            }
        });
    }
}

// ========== REPORTS TAB ==========
pub struct ReportsTab {
    report_data: ReportData,
    report_type: ReportType,
    date_range: DateRange,
    generating_report: bool,
}

#[derive(Debug, Clone)]
pub struct ReportData {
    pub total_detections: usize,
    pub detections_by_level: HashMap<ThreatLevel, usize>,
    pub detections_by_module: HashMap<DetectionModule, usize>,
    pub timeline_data: Vec<TimelineEntry>,
    pub top_threats: Vec<ThreatSummary>,
}

#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct ThreatSummary {
    pub description: String,
    pub count: usize,
    pub threat_level: ThreatLevel,
    pub module: DetectionModule,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReportType {
    Summary,
    Detailed,
    Timeline,
    ModuleBreakdown,
}

#[derive(Debug, Clone)]
pub struct DateRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl Default for DateRange {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            start: now - chrono::Duration::days(7),
            end: now,
        }
    }
}

impl ReportsTab {
    pub fn new() -> Self {
        Self {
            report_data: ReportData::default(),
            report_type: ReportType::Summary,
            date_range: DateRange::default(),
            generating_report: false,
        }
    }

    pub fn update_data(&mut self, events: &[DetectionEvent]) {
        let filtered_events: Vec<_> = events
            .iter()
            .filter(|e| e.timestamp >= self.date_range.start && e.timestamp <= self.date_range.end)
            .collect();

        self.report_data = ReportData::from_events(&filtered_events);
    }

    pub fn render(&mut self, ui: &mut egui::Ui, events: &[DetectionEvent]) {
        ui.heading("📈 Reports & Analytics");
        ui.separator();

        // Report controls
        ui.horizontal(|ui| {
            ui.label("Report Type:");
            egui::ComboBox::from_id_source("report_type")
                .selected_text(format!("{:?}", self.report_type))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.report_type, ReportType::Summary, "Summary");
                    ui.selectable_value(&mut self.report_type, ReportType::Detailed, "Detailed");
                    ui.selectable_value(&mut self.report_type, ReportType::Timeline, "Timeline");
                    ui.selectable_value(&mut self.report_type, ReportType::ModuleBreakdown, "Module Breakdown");
                });

            ui.separator();

            if ui.button("🔄 Refresh Data").clicked() {
                self.update_data(events);
            }

            if ui.button("💾 Export Report").clicked() {
                self.generating_report = true;
                // Export functionality would go here
            }

            if ui.button("📧 Email Report").clicked() {
                // Email functionality would go here
            }
        });

        ui.separator();

        // Update data if needed
        self.update_data(events);

        // Render report content
        match self.report_type {
            ReportType::Summary => self.render_summary_report(ui),
            ReportType::Detailed => self.render_detailed_report(ui),
            ReportType::Timeline => self.render_timeline_report(ui),
            ReportType::ModuleBreakdown => self.render_module_breakdown(ui),
        }
    }

    fn render_summary_report(&self, ui: &mut egui::Ui) {
        ui.heading("📊 Summary Report");

        ui.group(|ui| {
            ui.label(format!("Total Detections: {}", self.report_data.total_detections));
            
            ui.separator();
            
            ui.label("By Threat Level:");
            for (level, count) in &self.report_data.detections_by_level {
                let color = level.color();
                ui.horizontal(|ui| {
                    ui.colored_label(color, level.icon());
                    ui.label(format!("{:?}: {}", level, count));
                });
            }

            ui.separator();
            
            ui.label("By Module:");
            for (module, count) in &self.report_data.detections_by_module {
                ui.horizontal(|ui| {
                    ui.label(module.icon());
                    ui.label(format!("{}: {}", module.name(), count));
                });
            }
        });
    }

    fn render_detailed_report(&self, ui: &mut egui::Ui) {
        ui.heading("📋 Detailed Report");
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            for threat in &self.report_data.top_threats {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(threat.threat_level.color(), threat.threat_level.icon());
                        ui.label(&threat.description);
                        ui.label(format!("({}x)", threat.count));
                    });
                });
            }
        });
    }

    fn render_timeline_report(&self, ui: &mut egui::Ui) {
        ui.heading("📈 Timeline Report");
        ui.label("Timeline chart would be rendered here");
        // Timeline chart implementation would go here
    }

    fn render_module_breakdown(&self, ui: &mut egui::Ui) {
        ui.heading("🔧 Module Breakdown");
        
        for (module, count) in &self.report_data.detections_by_module {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(module.icon());
                    ui.heading(module.name());
                });
                
                ui.label(format!("Total Detections: {}", count));
                
                // Module-specific statistics would go here
            });
        }
    }
}

impl Default for ReportData {
    fn default() -> Self {
        Self {
            total_detections: 0,
            detections_by_level: HashMap::new(),
            detections_by_module: HashMap::new(),
            timeline_data: Vec::new(),
            top_threats: Vec::new(),
        }
    }
}

impl ReportData {
    fn from_events(events: &[&DetectionEvent]) -> Self {
        let mut data = Self::default();
        
        data.total_detections = events.len();
        
        // Count by level
        for event in events {
            *data.detections_by_level.entry(event.threat_level.clone()).or_insert(0) += 1;
            *data.detections_by_module.entry(event.module.clone()).or_insert(0) += 1;
        }
        
        // Generate top threats
        let mut threat_counts: HashMap<String, (usize, ThreatLevel, DetectionModule)> = HashMap::new();
        for event in events {
            let entry = threat_counts.entry(event.description.clone()).or_insert((0, event.threat_level.clone(), event.module.clone()));
            entry.0 += 1;
        }
        
        data.top_threats = threat_counts
            .into_iter()
            .map(|(desc, (count, level, module))| ThreatSummary {
                description: desc,
                count,
                threat_level: level,
                module,
            })
            .collect();
        
        data.top_threats.sort_by(|a, b| b.count.cmp(&a.count));
        data.top_threats.truncate(10); // Top 10 threats
        
        data
    }
}