//! Main application state and GUI coordination

use anyhow::Result;
use eframe::egui;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, error};
use chrono::{DateTime, Utc};

use crate::config::Config;
use crate::detection::{DetectionEngine, DetectionEvent, ThreatLevel};
use crate::gui::{ModulesTab, LogsTab, SettingsTab, ReportsTab};
use crate::gui::dashboard_tab::DashboardTab;

pub struct CluelyGuardApp {
    config: Config,
    detection_engine: Arc<RwLock<DetectionEngine>>,

    // GUI State
    current_tab: AppTab,
    monitoring_active: bool,
    start_time: Option<DateTime<Utc>>,
    detection_count: usize,
    recent_events: Vec<DetectionEvent>,
    event_rx: mpsc::Receiver<DetectionEvent>,

    // Tab Components
    dashboard: DashboardTab,
    modules: ModulesTab,
    logs_tab: LogsTab,
    settings_tab: SettingsTab,
    reports_tab: ReportsTab,

    // UI State
    show_settings_modal: bool,
    show_about_modal: bool,
    notification_queue: Vec<Notification>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppTab {
    Dashboard,
    Modules,
    Logs,
    Settings,
    Reports,
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub id: uuid::Uuid,
    pub title: String,
    pub message: String,
    pub level: ThreatLevel,
    pub timestamp: DateTime<Utc>,
    pub shown: bool,
}

impl CluelyGuardApp {
    pub async fn new(
        config: Config,
        detection_engine: Arc<RwLock<DetectionEngine>>,
        event_rx: mpsc::Receiver<DetectionEvent>,
    ) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            detection_engine: detection_engine.clone(),
            current_tab: AppTab::Dashboard,
            monitoring_active: false,
            start_time: None,
            detection_count: 0,
            recent_events: Vec::new(),

            // Initialize tab components
            dashboard: DashboardTab::new(),
            modules: ModulesTab::new(config.clone()),
            logs_tab: LogsTab::new(),
            settings_tab: SettingsTab::new(config.clone()),
            reports_tab: ReportsTab::new(),

            show_settings_modal: false,
            show_about_modal: false,
            notification_queue: Vec::new(),
            event_rx,
        })
    }

    pub fn toggle_monitoring(&mut self) {
        if self.monitoring_active {
            self.stop_monitoring();
        } else {
            self.start_monitoring();
        }
    }

    pub fn start_monitoring(&mut self) {
        self.monitoring_active = true;
        self.start_time = Some(Utc::now());
        self.detection_count = 0;

        // Start detection engine
        let engine = self.detection_engine.clone();
        tokio::spawn(async move {
            if let Err(e) = engine.write().await.start_monitoring().await {
                error!("Failed to start monitoring: {}", e);
            }
        });

        info!("Monitoring started");
        self.add_notification(
            "Monitoring Started".to_string(),
            "CluelyGuard is now actively monitoring for AI usage".to_string(),
            ThreatLevel::Info,
        );
    }

    pub fn stop_monitoring(&mut self) {
        self.monitoring_active = false;

        // Stop detection engine
        let engine = self.detection_engine.clone();
        tokio::spawn(async move {
            engine.write().await.stop_monitoring().await;
        });

        info!("Monitoring stopped");
        self.add_notification(
            "Monitoring Stopped".to_string(),
            "CluelyGuard monitoring has been stopped".to_string(),
            ThreatLevel::Info,
        );
    }

    pub fn add_notification(&mut self, title: String, message: String, level: ThreatLevel) {
        let notification = Notification {
            id: uuid::Uuid::new_v4(),
            title,
            message,
            level,
            timestamp: Utc::now(),
            shown: false,
        };

        self.notification_queue.push(notification);
    }

    pub fn handle_detection_event(&mut self, event: DetectionEvent) {
        self.detection_count += 1;
        
        // Add to logs tab
        self.logs_tab.add_log_entry(&event);
        
        self.recent_events.insert(0, event.clone());

        // Keep only last 50 events
        if self.recent_events.len() > 50 {
            self.recent_events.truncate(50);
        }

        // Create notification
        self.add_notification(
            "Threat Detected!".to_string(),
            format!("{}: {}", event.detection_type, event.description),
            event.threat_level.clone(),
        );

        // Log the event
        match event.threat_level.clone() {
            ThreatLevel::Critical => error!("DETECTION: {}", event.description),
            ThreatLevel::High => warn!("DETECTION: {}", event.description),
            ThreatLevel::Medium => warn!("DETECTION: {}", event.description),
            ThreatLevel::Low => info!("DETECTION: {}", event.description),
            ThreatLevel::Info => info!("DETECTION: {}", event.description),
            _ => info!("DETECTION: {}", event.description),
        }
    }

    fn render_menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::menu::bar(ui, |ui| {
            // File menu
            ui.menu_button("File", |ui| {
                if ui.button("Settings").clicked() {
                    self.current_tab = AppTab::Settings;
                    ui.close_menu();
                }

                ui.separator();

                if ui.button("Exit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });

            // View menu
            ui.menu_button("View", |ui| {
                if ui.button("Dashboard").clicked() {
                    self.current_tab = AppTab::Dashboard;
                    ui.close_menu();
                }
                if ui.button("Detection Modules").clicked() {
                    self.current_tab = AppTab::Modules;
                    ui.close_menu();
                }
                if ui.button("Logs").clicked() {
                    self.current_tab = AppTab::Logs;
                    ui.close_menu();
                }
                if ui.button("Settings").clicked() {
                    self.current_tab = AppTab::Settings;
                    ui.close_menu();
                }
                if ui.button("Reports").clicked() {
                    self.current_tab = AppTab::Reports;
                    ui.close_menu();
                }
            });

            // Tools menu
            ui.menu_button("Tools", |ui| {
                if ui.button("Quick Scan").clicked() {
                    self.perform_quick_scan();
                    ui.close_menu();
                }

                if ui.button("Export Report").clicked() {
                    self.current_tab = AppTab::Reports;
                    ui.close_menu();
                }
            });

            // Help menu
            ui.menu_button("Help", |ui| {
                if ui.button("About").clicked() {
                    self.show_about_modal = true;
                    ui.close_menu();
                }

                if ui.button("Documentation").clicked() {
                    let _ = open::that("https://github.com/darkraider01/CluelyGuard/wiki");
                    ui.close_menu();
                }
            });
        });
    }

    fn render_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Start/Stop monitoring button
            let button_text = if self.monitoring_active {
                "🛑 Stop Monitoring"
            } else {
                "▶️ Start Monitoring"
            };

            let button_color = if self.monitoring_active {
                egui::Color32::from_rgb(220, 53, 69) // Red
            } else {
                egui::Color32::from_rgb(40, 167, 69) // Green
            };

            let button = egui::Button::new(button_text)
                .fill(button_color)
                .min_size(egui::vec2(150.0, 30.0));

            if ui.add(button).clicked() {
                self.toggle_monitoring();
            }

            ui.separator();

            // Quick scan button
            if ui.button("🔍 Quick Scan").clicked() {
                self.perform_quick_scan();
            }

            // Settings button
            if ui.button("⚙️ Settings").clicked() {
                self.current_tab = AppTab::Settings;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Status indicators
                ui.label(format!("Threats: {}", self.detection_count));

                ui.separator();

                let status_text = if self.monitoring_active {
                    "🟢 Active"
                } else {
                    "🔴 Inactive"
                };
                ui.label(status_text);
            });
        });
    }

    fn render_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.current_tab, AppTab::Dashboard, "📊 Dashboard");
            ui.selectable_value(&mut self.current_tab, AppTab::Modules, "🔧 Modules");
            ui.selectable_value(&mut self.current_tab, AppTab::Logs, "📝 Logs");
            ui.selectable_value(&mut self.current_tab, AppTab::Settings, "⚙️ Settings");
            ui.selectable_value(&mut self.current_tab, AppTab::Reports, "📈 Reports");
        });

        ui.separator();
    }

    fn render_tab_content(&mut self, ui: &mut egui::Ui) {
        match self.current_tab {
            AppTab::Dashboard => {
                self.dashboard.render(
                    ui,
                    self.monitoring_active,
                    self.start_time,
                    self.detection_count,
                    &self.recent_events,
                );
            }
            AppTab::Modules => {
                self.modules.render(ui, &mut self.config);
            }
            AppTab::Logs => {
                self.logs_tab.render(ui);
            }
            AppTab::Settings => {
                self.settings_tab.render(ui, &mut self.config);
            }
            AppTab::Reports => {
                self.reports_tab.render(ui, &self.recent_events);
            }
        }
    }

    fn render_modals(&mut self, ctx: &egui::Context) {
        // About modal
        if self.show_about_modal {
            egui::Window::new("About CluelyGuard")
                .collapsible(false)
                .resizable(false)
                .default_size(egui::vec2(400.0, 300.0))
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading("CluelyGuard");
                        ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
                        ui.label("Advanced Anti-LLM Detection System");

                        ui.add_space(20.0);

                        ui.label("Built with Rust and egui");
                        ui.label("© 2025 CluelyGuard Security");

                        ui.add_space(20.0);

                        if ui.button("Close").clicked() {
                            self.show_about_modal = false;
                        }
                    });
                });
        }
    }

    fn render_notifications(&mut self, ctx: &egui::Context) {
        let mut to_remove = Vec::new();

        for (i, notification) in self.notification_queue.iter_mut().enumerate() {
            if !notification.shown {
                let window_id = egui::Id::new(format!("notification_{}", notification.id));

                let mut open = true;
                egui::Window::new(&notification.title)
                    .id(window_id)
                    .collapsible(false)
                    .resizable(false)
                    .default_size(egui::vec2(300.0, 100.0))
                    .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-10.0, 50.0 + i as f32 * 110.0))
                    .open(&mut open)
                    .show(ctx, |ui| {
                        ui.label(&notification.message);

                        ui.horizontal(|ui| {
                            if ui.small_button("Dismiss").clicked() {
                                to_remove.push(i);
                            }

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.small(format!("{}", notification.timestamp.format("%H:%M:%S")));
                            });
                        });
                    });

                if !open {
                    to_remove.push(i);
                }

                notification.shown = true;
            }
        }

        // Remove dismissed notifications
        for &i in to_remove.iter().rev() {
            self.notification_queue.remove(i);
        }

        // Auto-remove old notifications (after 10 seconds)
        let cutoff = Utc::now() - chrono::Duration::seconds(10);
        self.notification_queue.retain(|n| n.timestamp > cutoff);
    }

    fn perform_quick_scan(&mut self) {
        let engine = self.detection_engine.clone();
        tokio::spawn(async move {
            if let Err(e) = engine.write().await.perform_scan().await {
                error!("Quick scan failed: {}", e);
            }
        });

        self.add_notification(
            "Quick Scan Started".to_string(),
            "Performing comprehensive scan of all detection modules".to_string(),
            ThreatLevel::Info,
        );
    }
}

impl eframe::App for CluelyGuardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle detection events from the engine
        // Process incoming detection events
        let mut events_to_process = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events_to_process.push(event);
        }

        for event in events_to_process {
            self.handle_detection_event(event);
        }

        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.render_menu_bar(ui);
        });

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            self.render_toolbar(ui);
        });

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            self.render_tabs(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.render_tab_content(ui);
            });
        });

        // Render modals and notifications
        self.render_modals(ctx);
        self.render_notifications(ctx);

        // Request repaint for animations and real-time updates
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}