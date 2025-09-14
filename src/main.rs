//! CluelyGuard - Advanced Anti-LLM Detection System
//! 
//! A comprehensive GUI application for detecting AI usage and preventing 
//! unauthorized assistance during exams, assessments, and secure environments.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use eframe::egui;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::info;

mod app;
mod config;
mod detection;
mod gui;
mod logging;
mod utils;

use app::CluelyGuardApp;
use detection::DetectionEngine;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    logging::init()?;
    info!("🚀 Starting CluelyGuard v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = config::Config::load().await?;
    info!("✅ Configuration loaded successfully");

    // Create an MPSC channel for detection events
    let (event_tx, event_rx) = mpsc::channel(100);

    // Initialize detection engine
    let detection_engine = Arc::new(RwLock::new(
        DetectionEngine::new(config.clone(), event_tx.clone()).await?
    ));
    info!("✅ Detection engine initialized");

    // Setup native options for the GUI
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("CluelyGuard - Advanced Anti-LLM Detection System")
            .with_icon(load_icon()),
        centered: true,
        follow_system_theme: false,
        default_theme: eframe::Theme::Dark,
        ..Default::default()
    };

    info!("🖥️ Starting GUI application...");

    // Create and run the application
    let app = CluelyGuardApp::new(config, detection_engine, event_rx).await?;

    eframe::run_native(
        "CluelyGuard",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    ).map_err(|e| anyhow::anyhow!("Failed to run GUI: {}", e))
}

fn load_icon() -> egui::IconData {
    // Create a simple default icon if the file doesn't exist
    match std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/icon.png")) {
        Ok(icon_bytes) => {
            match image::load_from_memory(&icon_bytes) {
                Ok(image) => {
                    let rgba_image = image.to_rgba8();
                    let (width, height) = rgba_image.dimensions();
                    egui::IconData {
                        rgba: rgba_image.into_raw(),
                        width: width as u32,
                        height: height as u32,
                    }
                }
                Err(_) => create_fallback_icon(),
            }
        }
        Err(_) => create_fallback_icon(),
    }
}

fn create_fallback_icon() -> egui::IconData {
    // Fallback: create a simple 32x32 blue shield icon
    let size = 32;
    let mut rgba = Vec::with_capacity(size * size * 4);
    for y in 0..size {
        for x in 0..size {
            // Create a simple shield-like pattern
            let center_x = size / 2;
            let center_y = size / 2;
            let dist = ((x as i32 - center_x as i32).pow(2) + (y as i32 - center_y as i32).pow(2)) as f32;
            let max_dist = (size / 2) as f32;
            
            if dist <= max_dist * max_dist {
                // Blue shield
                rgba.extend_from_slice(&[0, 100, 200, 255]);
            } else {
                // Transparent
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    
    egui::IconData {
        rgba,
        width: size as u32,
        height: size as u32,
    }
}