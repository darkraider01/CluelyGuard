//! Screen monitoring module for detecting AI interfaces

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use tracing::warn;

use super::{DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel, ScreenMonitorConfig};

#[derive(Clone)]
pub struct ScreenMonitor {
    config: ScreenMonitorConfig,
}

impl ScreenMonitor {
    pub fn new(config: ScreenMonitorConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn scan(&self) -> Result<Vec<DetectionEvent>> {
        let events = Vec::new();

        if !self.config.enabled {
            return Ok(events);
        }

        // Capture screenshot and analyze
        #[cfg(feature = "screen-monitoring")]
        {
            match self.capture_and_analyze_screen().await {
                Ok(detected_events) => events.extend(detected_events),
                Err(e) => {
                    error!("Screen monitoring failed: {}", e);
                }
            }
        }

        Ok(events)
    }

    pub fn update_config(&mut self, config: ScreenMonitorConfig) -> Result<()> {
        self.config = config;
        Ok(())
    }

    #[cfg(feature = "screen-monitoring")]
    async fn capture_and_analyze_screen(&self) -> Result<Vec<DetectionEvent>> {
        use screenshots::Screen;
        use image::ImageFormat;
        use std::io::Cursor;

        let mut events = Vec::new();
        let screens = Screen::all()?;

        for screen in screens {
            let image = screen.capture()?;
            let screenshot_hash = self.calculate_image_hash(&image);

            // Analyze the screenshot for AI interfaces
            let detected_elements = self.detect_ai_interfaces(&image).await?;

            if !detected_elements.is_empty() {
                let confidence = self.calculate_detection_confidence(&detected_elements);

                if confidence >= self.config.confidence_threshold {
                    let ai_interface_type = self.determine_interface_type(&detected_elements);

                    events.push(self.create_screen_event(
                        screenshot_hash,
                        detected_elements,
                        confidence,
                        ai_interface_type,
                    ));
                }
            }
        }

        Ok(events)
    }

    #[cfg(not(feature = "screen-monitoring"))]
    async fn capture_and_analyze_screen(&self) -> Result<Vec<DetectionEvent>> {
        warn!("Screen monitoring feature not enabled");
        Ok(vec![])
    }

    #[cfg(feature = "screen-monitoring")]
    fn calculate_image_hash(&self, image: &image::RgbaImage) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        image.as_raw().hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    #[cfg(feature = "screen-monitoring")]
    async fn detect_ai_interfaces(&self, image: &image::RgbaImage) -> Result<Vec<String>> {
        let mut detected_elements = Vec::new();

        // Simple color-based detection for common AI interface elements
        let ai_interface_colors = [
            (64, 65, 79),   // ChatGPT dark theme
            (52, 53, 65),   // ChatGPT sidebar
            (255, 255, 255), // Claude light theme
            (247, 247, 248), // Claude message background
        ];

        // Convert image to searchable format and look for patterns
        let (width, height) = image.dimensions();
        let mut color_regions = HashMap::new();

        // Analyze color regions (simplified implementation)
        for y in (0..height).step_by(10) {
            for x in (0..width).step_by(10) {
                let pixel = image.get_pixel(x, y);
                let rgb = (pixel[0], pixel[1], pixel[2]);

                for (target_r, target_g, target_b) in &ai_interface_colors {
                    let color_diff = ((rgb.0 as i16 - *target_r as i16).abs() +
                                     (rgb.1 as i16 - *target_g as i16).abs() +
                                     (rgb.2 as i16 - *target_b as i16).abs()) as f32 / 3.0;

                    if color_diff < 30.0 {
                        let color_key = format!("{}_{}_{}",target_r, target_g, target_b);
                        *color_regions.entry(color_key).or_insert(0) += 1;
                    }
                }
            }
        }

        // Check for significant color regions that might indicate AI interfaces
        for (color, count) in color_regions {
            let total_pixels = (width * height) / 100; // We sampled every 10th pixel
            let percentage = count as f32 / total_pixels as f32;

            if percentage > 0.1 { // If more than 10% of sampled pixels match
                detected_elements.push(format!("AI interface color pattern: {}", color));
            }
        }

        // OCR-based text detection (simplified)
        if self.config.ocr_enabled {
            if let Ok(text_elements) = self.perform_ocr_analysis(image).await {
                detected_elements.extend(text_elements);
            }
        }

        Ok(detected_elements)
    }

    #[cfg(feature = "screen-monitoring")]
    async fn perform_ocr_analysis(&self, _image: &image::RgbaImage) -> Result<Vec<String>> {
        // Placeholder for OCR functionality
        // In a real implementation, this would use tesseract or similar OCR library
        let ai_keywords = [
            "ChatGPT", "Claude", "Gemini", "Copilot", "AI Assistant",
            "How can I help", "I'm an AI", "regenerate response", 
            "stop generating", "OpenAI", "Anthropic"
        ];

        let mut detected_text = Vec::new();

        // Simulate OCR detection (replace with actual OCR implementation)
        for keyword in &ai_keywords {
            // This would be replaced with actual OCR text extraction
            // detected_text.push(format!("OCR detected: {}", keyword));
        }

        Ok(detected_text)
    }

    fn calculate_detection_confidence(&self, detected_elements: &[String]) -> f32 {
        if detected_elements.is_empty() {
            return 0.0;
        }

        let mut confidence = 0.0;
        let total_elements = detected_elements.len() as f32;

        for element in detected_elements {
            let element_lower = element.to_lowercase();

            // High confidence indicators
            if element_lower.contains("chatgpt") || 
               element_lower.contains("claude") || 
               element_lower.contains("gemini") {
                confidence += 0.9;
            }
            // Medium confidence indicators  
            else if element_lower.contains("ai interface") || 
                    element_lower.contains("assistant") {
                confidence += 0.7;
            }
            // Low confidence indicators
            else if element_lower.contains("color pattern") {
                confidence += 0.3;
            }
        }

        confidence / total_elements
    }

    fn determine_interface_type(&self, detected_elements: &[String]) -> String {
        for element in detected_elements {
            let element_lower = element.to_lowercase();

            if element_lower.contains("chatgpt") {
                return "ChatGPT".to_string();
            } else if element_lower.contains("claude") {
                return "Claude".to_string();
            } else if element_lower.contains("gemini") {
                return "Gemini".to_string();
            } else if element_lower.contains("copilot") {
                return "GitHub Copilot".to_string();
            }
        }

        "Unknown AI Interface".to_string()
    }

    fn create_screen_event(
        &self,
        screenshot_hash: String,
        detected_elements: Vec<String>,
        confidence: f32,
        ai_interface_type: String,
    ) -> DetectionEvent {
        let threat_level = match confidence {
            c if c >= 0.9 => ThreatLevel::Critical,
            c if c >= 0.7 => ThreatLevel::High,
            c if c >= 0.5 => ThreatLevel::Medium,
            _ => ThreatLevel::Low,
        };

        DetectionEvent {
            id: uuid::Uuid::new_v4(),
            detection_type: "Screen Analysis".to_string(),
            module: DetectionModule::ScreenMonitor,
            threat_level,
            description: format!("AI interface detected on screen: {}", ai_interface_type),
            details: DetectionDetails::Screen {
                screenshot_hash,
                detected_elements,
                confidence,
                ai_interface_type,
            },
            timestamp: Utc::now(),
            source: Some("Screen Monitor".to_string()),
            metadata: HashMap::new(),
        }
    }
}
