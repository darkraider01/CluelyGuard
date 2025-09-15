//! Dashboard Tab

use eframe::egui;
use chrono::{DateTime, Utc};
use crate::detection::{DetectionEvent, ThreatLevel};
use std::collections::HashMap;

pub struct DashboardTab {
    // Data for dashboard
    pub total_detections: usize,
    pub detections_by_level: HashMap<ThreatLevel, usize>,
    pub recent_events: Vec<DetectionEvent>,
}

impl DashboardTab {
    pub fn new() -> Self {
        Self {
            total_detections: 0,
            detections_by_level: HashMap::new(),
            recent_events: Vec::new(),
        }
    }

    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        monitoring_active: bool,
        start_time: Option<DateTime<Utc>>,
        detection_count: usize,
        recent_events: &Vec<DetectionEvent>,
    ) {
        ui.heading("📊 Dashboard");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(format!("Monitoring Status: {}", if monitoring_active { "Active" } else { "Inactive" }));
            if let Some(start) = start_time {
                ui.label(format!("Started: {}", start.format("%Y-%m-%d %H:%M:%S")));
            }
            ui.label(format!("Total Detections: {}", detection_count));
        });

        ui.add_space(10.0);

        ui.heading("Recent Events");
        egui::ScrollArea::vertical().show(ui, |ui| {
            for event in recent_events {
                ui.label(format!("[{}] {}: {}", event.timestamp.format("%H:%M:%S"), event.detection_type, event.description));
            }
        });
    }
}
