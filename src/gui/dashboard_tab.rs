//! Dashboard tab for real-time monitoring status

use eframe::egui;
use chrono::{DateTime, Utc};
use crate::detection::{DetectionEvent, ThreatLevel};

#[derive(Clone)]
pub struct DashboardTab {
    // Dashboard state
}

impl DashboardTab {
    pub fn new() -> Self {
        Self {}
    }

    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        monitoring_active: bool,
        start_time: Option<DateTime<Utc>>,
        detection_count: usize,
        recent_events: &[DetectionEvent],
    ) {
        ui.heading("🛡️ CluelyGuard Dashboard");
        ui.separator();

        // Status indicators
        ui.horizontal(|ui| {
            // Monitoring status
            let (status_text, status_color) = if monitoring_active {
                ("🟢 MONITORING ACTIVE", egui::Color32::from_rgb(40, 167, 69))
            } else {
                ("🔴 MONITORING INACTIVE", egui::Color32::from_rgb(220, 53, 69))
            };

            ui.label(egui::RichText::new(status_text).color(status_color).size(18.0));

            ui.separator();

            // Threat counter
            let threat_color = match detection_count {
                0 => egui::Color32::from_rgb(40, 167, 69),
                1..=5 => egui::Color32::from_rgb(255, 193, 7),
                _ => egui::Color32::from_rgb(220, 53, 69),
            };

            ui.label(egui::RichText::new(format!("🚨 {} THREATS DETECTED", detection_count))
                    .color(threat_color)
                    .size(16.0));
        });

        ui.add_space(20.0);

        // System information
        egui::Grid::new("dashboard_grid")
            .num_columns(2)
            .spacing([40.0, 10.0])
            .show(ui, |ui| {
                // Left column - System Status
                ui.vertical(|ui| {
                    ui.heading("System Status");
                    ui.separator();

                    // Uptime
                    let uptime_text = if let Some(start) = start_time {
                        let duration = Utc::now() - start;
                        let hours = duration.num_hours();
                        let minutes = duration.num_minutes() % 60;
                        let seconds = duration.num_seconds() % 60;
                        format!("⏱️ Uptime: {:02}:{:02}:{:02}", hours, minutes, seconds)
                    } else {
                        "⏱️ Uptime: Not running".to_string()
                    };
                    ui.label(uptime_text);

                    // Detection modules status
                    ui.label("🔧 Browser Extensions: Active");
                    ui.label("⚙️ Process Monitor: Active");
                    ui.label("🌍 Network Monitor: Active");
                    ui.label("🖥️ Screen Monitor: Inactive");
                    ui.label("📁 Filesystem Monitor: Active");

                    ui.add_space(10.0);

                    // System resources
                    ui.heading("System Resources");
                    ui.separator();

                    // Get system info
                    let cpu_usage = Self::get_cpu_usage();
                    let memory_usage = Self::get_memory_usage();

                    ui.horizontal(|ui| {
                        ui.label("CPU:");
                        let cpu_bar = egui::ProgressBar::new(cpu_usage / 100.0)
                            .text(format!("{:.1}%", cpu_usage));
                        ui.add(cpu_bar);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Memory:");
                        let mem_bar = egui::ProgressBar::new(memory_usage / 100.0)
                            .text(format!("{:.1}%", memory_usage));
                        ui.add(mem_bar);
                    });
                });

                ui.end_row();

                // Right column - Recent Activity
                ui.vertical(|ui| {
                    ui.heading("Recent Detections");
                    ui.separator();

                    if recent_events.is_empty() {
                        ui.label("✅ No threats detected");
                    } else {
                        egui::ScrollArea::vertical()
                            .max_height(300.0)
                            .show(ui, |ui| {
                                for event in recent_events.iter().take(10) {
                                    self.render_event_summary(ui, event);
                                }
                            });
                    }

                    ui.add_space(20.0);

                    // Quick actions
                    ui.heading("Quick Actions");
                    ui.separator();

                    if ui.button("🔍 Perform Quick Scan").clicked() {
                        // This would trigger a quick scan
                    }

                    if ui.button("📊 View Detailed Report").clicked() {
                        // This would switch to reports tab
                    }

                    if ui.button("⚙️ Configure Modules").clicked() {
                        // This would switch to modules tab
                    }
                });
            });
    }

    fn render_event_summary(&self, ui: &mut egui::Ui, event: &DetectionEvent) {
        ui.horizontal(|ui| {
            // Threat level indicator
            let (icon, color) = match event.threat_level {
                ThreatLevel::Critical => ("🚨", egui::Color32::from_rgb(220, 53, 69)),
                ThreatLevel::High => ("⚠️", egui::Color32::from_rgb(253, 126, 20)),
                ThreatLevel::Medium => ("⚡", egui::Color32::from_rgb(255, 193, 7)),
                ThreatLevel::Low => ("ℹ️", egui::Color32::from_rgb(23, 162, 184)),
                ThreatLevel::Info => ("💡", egui::Color32::from_rgb(23, 162, 184)),
                ThreatLevel::Unknown => ("❓", egui::Color32::GRAY),
            };

            ui.label(egui::RichText::new(icon).color(color));

            ui.vertical(|ui| {
                ui.label(egui::RichText::new(&event.description).strong());
                ui.small(format!("{} - {}", 
                    event.module.name(), 
                    event.timestamp.format("%H:%M:%S")));
            });
        });

        ui.separator();
    }

    fn get_cpu_usage() -> f32 {
        // Placeholder - in a real implementation, this would use sysinfo
        25.0
    }

    fn get_memory_usage() -> f32 {
        // Placeholder - in a real implementation, this would use sysinfo
        45.0
    }
}
