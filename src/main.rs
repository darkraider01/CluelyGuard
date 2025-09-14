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
use crate::detection::engine::DetectionEngine;

mod app;
mod config;
mod detection;
mod gui;
mod logging;
mod utils;

use app::CluelyGuardApp;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    logging::init()?;
    info!("Starting CluelyGuard v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = config::Config::load().await?;

    // Create an MPSC channel for detection events
    let (event_tx, event_rx) = mpsc::channel(100); // Buffer size of 100

    // Initialize detection engine
    let detection_engine = Arc::new(RwLock::new(
        DetectionEngine::new(config.clone(), event_tx.clone()).await?
    ));

    // Setup native options for the GUI
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(load_icon())
            .with_title("CluelyGuard - Anti-LLM Detection System"),
        centered: true,
        follow_system_theme: false,
        default_theme: eframe::Theme::Dark,
        ..Default::default()
    };

    // Create and run the application
    let app = CluelyGuardApp::new(config, detection_engine, event_rx).await?;

    eframe::run_native(
        "CluelyGuard",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    ).map_err(|e| anyhow::anyhow!("Failed to run GUI: {}", e))
}

fn load_icon() -> egui::IconData {
    // Load application icon from embedded bytes or file
    let icon_bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/icon.png"));

    let image = image::load_from_memory(icon_bytes)
        .expect("Failed to load icon")
        .to_rgba8();

    let (width, height) = image.dimensions();
    egui::IconData {
        rgba: image.into_raw(),
        width: width as u32,
        height: height as u32,
    }
}
