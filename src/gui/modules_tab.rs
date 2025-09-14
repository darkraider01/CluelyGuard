//! Detection modules configuration tab

use eframe::egui;
use crate::config::Config;
use crate::detection::DetectionConfig;

#[derive(Clone)]
pub struct ModulesTab {
    detection_config: DetectionConfig,
}

impl ModulesTab {
    pub fn new(config: Config) -> Self {
        Self {
            detection_config: config.detection.unwrap_or_default(),
        }
    }

    pub fn render(&mut self, ui: &mut egui::Ui, config: &mut Config) {
        ui.heading("🔧 Detection Modules");
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Browser Extensions Module
            ui.collapsing("🌐 Browser Extensions", |ui| {
                self.render_browser_extensions_config(ui);
            });

            ui.add_space(10.0);

            // Process Monitor Module
            ui.collapsing("⚙️ Process Monitor", |ui| {
                self.render_process_monitor_config(ui);
            });

            ui.add_space(10.0);

            // Network Monitor Module
            ui.collapsing("🌍 Network Monitor", |ui| {
                self.render_network_monitor_config(ui);
            });

            ui.add_space(10.0);

            // Screen Monitor Module
            ui.collapsing("🖥️ Screen Monitor", |ui| {
                self.render_screen_monitor_config(ui);
            });

            ui.add_space(10.0);

            // Filesystem Monitor Module
            ui.collapsing("📁 Filesystem Monitor", |ui| {
                self.render_filesystem_monitor_config(ui);
            });

            ui.add_space(20.0);

            // Save button
            if ui.button("💾 Save Configuration").clicked() {
                config.detection = Some(self.detection_config.clone());
                let config_clone = config.clone(); // Clone config
                let _ = tokio::spawn(async move {
                  let _ = config_clone.save().await; // Use the cloned config
              });
            }
        });
    }

    #[allow(unused_variables)]
    fn render_browser_extensions_config(&mut self, ui: &mut egui::Ui) {
        let config = &mut self.detection_config.browser_extensions;

        ui.checkbox(&mut config.scan_chrome, "Scan Chrome Extensions");
        ui.checkbox(&mut config.scan_firefox, "Scan Firefox Extensions");
        ui.checkbox(&mut config.scan_edge, "Scan Edge Extensions");

        ui.add_space(10.0);

        ui.label("Known AI Extensions:");
        egui::ScrollArea::vertical()
            .max_height(100.0)
            .show(ui, |ui| {
                let mut to_remove = Vec::new();
                for (i, (id, name)) in config.known_ai_extensions.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(format!("{}: {}", id, name));
                        if ui.small_button("❌").clicked() {
                            to_remove.push(id.clone());
                        }
                    });
                }

                for id in to_remove {
                    config.known_ai_extensions.remove(&id);
                }
            });
    }

    #[allow(unused_variables)]
    fn render_process_monitor_config(&mut self, ui: &mut egui::Ui) {
        let config = &mut self.detection_config.process_monitor;

        ui.horizontal(|ui| {
            ui.label("Scan Interval (ms):");
            ui.add(egui::DragValue::new(&mut config.scan_interval_ms).range(1000..=60000));
        });

        ui.checkbox(&mut config.monitor_command_line, "Monitor Command Line Arguments");
        ui.checkbox(&mut config.monitor_child_processes, "Monitor Child Processes");

        ui.add_space(10.0);

        ui.label("AI Process Patterns:");
        egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(ui, |ui| {
                let mut to_remove = Vec::new();
                for (i, pattern) in config.ai_process_patterns.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(pattern);
                        if ui.small_button("❌").clicked() {
                            to_remove.push(i);
                        }
                    });
                }

                for i in to_remove.into_iter().rev() {
                    config.ai_process_patterns.remove(i);
                }
            });

        ui.add_space(10.0);

        ui.label("Process Whitelist:");
        egui::ScrollArea::vertical()
            .max_height(100.0)
            .show(ui, |ui| {
                let mut to_remove = Vec::new();
                for (i, process) in config.whitelist.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(process);
                        if ui.small_button("❌").clicked() {
                            to_remove.push(i);
                        }
                    });
                }

                for i in to_remove.into_iter().rev() {
                    config.whitelist.remove(i);
                }
            });
    }

    #[allow(unused_variables)]
    fn render_network_monitor_config(&mut self, ui: &mut egui::Ui) {
        let config = &mut self.detection_config.network_monitor;

        ui.horizontal(|ui| {
            ui.label("Scan Interval (ms):");
            ui.add(egui::DragValue::new(&mut config.scan_interval_ms).range(1000..=30000));
        });

        ui.checkbox(&mut config.monitor_dns, "Monitor DNS Queries");
        ui.checkbox(&mut config.monitor_websockets, "Monitor WebSocket Connections");

        ui.add_space(10.0);

        ui.label("AI Domains:");
        egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(ui, |ui| {
                let mut to_remove = Vec::new();
                for (i, domain) in config.ai_domains.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(domain);
                        if ui.small_button("❌").clicked() {
                            to_remove.push(i);
                        }
                    });
                }

                for i in to_remove.into_iter().rev() {
                    config.ai_domains.remove(i);
                }
            });
    }

    fn render_screen_monitor_config(&mut self, ui: &mut egui::Ui) {
        let config = &mut self.detection_config.screen_monitor;

        ui.checkbox(&mut config.enabled, "Enable Screen Monitoring");

        if config.enabled {
            ui.horizontal(|ui| {
                ui.label("Capture Interval (ms):");
                ui.add(egui::DragValue::new(&mut config.capture_interval_ms).range(5000..=300000));
            });

            ui.checkbox(&mut config.ocr_enabled, "Enable OCR Text Detection");

            ui.horizontal(|ui| {
                ui.label("Confidence Threshold:");
                ui.add(egui::Slider::new(&mut config.confidence_threshold, 0.0..=1.0));
            });
        }

        ui.colored_label(
            egui::Color32::from_rgb(255, 193, 7),
            "⚠️ Screen monitoring may impact system performance"
        );
    }

    #[allow(unused_variables)]
    fn render_filesystem_monitor_config(&mut self, ui: &mut egui::Ui) {
        let config = &mut self.detection_config.filesystem_monitor;

        ui.checkbox(&mut config.monitor_downloads, "Monitor Downloads Folder");
        ui.checkbox(&mut config.monitor_temp_files, "Monitor Temporary Files");

        ui.add_space(10.0);

        ui.label("Watch Directories:");
        egui::ScrollArea::vertical()
            .max_height(100.0)
            .show(ui, |ui| {
                let mut to_remove = Vec::new();
                for (i, dir) in config.watch_directories.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(dir);
                        if ui.small_button("❌").clicked() {
                            to_remove.push(i);
                        }
                    });
                }

                for i in to_remove.into_iter().rev() {
                    config.watch_directories.remove(i);
                }
            });

        ui.add_space(10.0);

        ui.label("Suspicious File Extensions:");
        egui::ScrollArea::vertical()
            .max_height(80.0)
            .show(ui, |ui| {
                let mut to_remove = Vec::new();
                for (i, ext) in config.suspicious_extensions.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(ext);
                        if ui.small_button("❌").clicked() {
                            to_remove.push(i);
                        }
                    });
                }

                for i in to_remove.into_iter().rev() {
                    config.suspicious_extensions.remove(i);
                }
            });
    }
}
