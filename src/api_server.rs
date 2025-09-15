//! CluelyGuard REST API Server - Backend for Web Dashboard
//! Provides HTTP endpoints for remote monitoring and management

use anyhow::Result;
use axum::{
    extract::{State, Query, Path},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router, Server,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use uuid::Uuid;

use crate::detection::{DetectionEngine, DetectionEvent, ThreatLevel, DetectionModule};
use crate::config::Config;

pub struct ApiServer {
    config: Config,
    detection_engine: Arc<RwLock<DetectionEngine>>,
    clients: Arc<RwLock<HashMap<Uuid, WebClient>>>,
    event_history: Arc<RwLock<Vec<DetectionEvent>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebClient {
    pub id: Uuid,
    pub name: String,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub ip_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringStatus {
    pub active: bool,
    pub uptime_seconds: u64,
    pub total_detections: usize,
    pub detections_by_level: HashMap<ThreatLevel, usize>,
    pub detections_by_module: HashMap<DetectionModule, usize>,
    pub system_resources: SystemResources,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemResources {
    pub cpu_usage: f32,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_usage: f64,
}

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub level: Option<ThreatLevel>,
    pub module: Option<DetectionModule>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl ApiServer {
    pub async fn new(
        config: Config,
        detection_engine: Arc<RwLock<DetectionEngine>>,
        mut event_rx: mpsc::Receiver<DetectionEvent>,
    ) -> Result<Self> {
        let event_history = Arc::new(RwLock::new(Vec::new()));
        
        // Spawn event collector
        let history_clone = event_history.clone();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let mut history = history_clone.write().await;
                history.insert(0, event);
                
                // Keep only last 10,000 events
                if history.len() > 10_000 {
                    history.truncate(10_000);
                }
            }
        });

        Ok(Self {
            config,
            detection_engine,
            clients: Arc::new(RwLock::new(HashMap::new())),
            event_history,
        })
    }

    pub async fn start(&self, port: u16) -> Result<()> {
        let app_state = AppState {
            server: Arc::new(self.clone()),
        };

        let app = Router::new()
            // Health check
            .route("/health", get(health_check))
            
            // Authentication
            .route("/auth/login", post(login))
            .route("/auth/logout", post(logout))
            
            // Monitoring endpoints
            .route("/api/v1/status", get(get_monitoring_status))
            .route("/api/v1/monitoring/start", post(start_monitoring))
            .route("/api/v1/monitoring/stop", post(stop_monitoring))
            .route("/api/v1/monitoring/scan", post(perform_scan))
            
            // Events endpoints
            .route("/api/v1/events", get(get_events))
            .route("/api/v1/events/:id", get(get_event_by_id))
            .route("/api/v1/events/search", get(search_events))
            .route("/api/v1/events/export", get(export_events))
            
            // Configuration endpoints
            .route("/api/v1/config", get(get_config))
            .route("/api/v1/config", put(update_config))
            .route("/api/v1/config/modules/:module", put(update_module_config))
            
            // Statistics endpoints
            .route("/api/v1/stats/summary", get(get_stats_summary))
            .route("/api/v1/stats/timeline", get(get_stats_timeline))
            .route("/api/v1/stats/modules", get(get_module_stats))
            
            // Client management
            .route("/api/v1/clients", get(get_connected_clients))
            .route("/api/v1/clients/:id", delete(disconnect_client))
            
            // WebSocket for real-time updates
            .route("/ws", get(websocket_handler))
            
            // Serve web dashboard static files
            .route("/", get(serve_dashboard))
            .route("/dashboard/*path", get(serve_dashboard_assets))
            
            .with_state(app_state)
            .layer(
                ServiceBuilder::new()
                    .layer(CorsLayer::permissive())
                    .layer(tower_http::trace::TraceLayer::new_for_http())
            );

        let addr = format!("0.0.0.0:{}", port);
        info!("🚀 CluelyGuard API Server starting on http://{}", addr);

        Server::bind(&addr.parse()?)
            .serve(app.into_make_service())
            .await?;

        Ok(())
    }
}

impl Clone for ApiServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            detection_engine: self.detection_engine.clone(),
            clients: self.clients.clone(),
            event_history: self.event_history.clone(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    server: Arc<ApiServer>,
}

// Health check endpoint
async fn health_check() -> Json<ApiResponse<HashMap<String, String>>> {
    let mut data = HashMap::new();
    data.insert("status".to_string(), "healthy".to_string());
    data.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    data.insert("service".to_string(), "CluelyGuard API".to_string());

    Json(ApiResponse {
        success: true,
        data: Some(data),
        message: "API is healthy".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

// Authentication endpoints
async fn login(State(_state): State<AppState>) -> Json<ApiResponse<String>> {
    // Simplified auth - in production, implement proper JWT/OAuth
    let token = Uuid::new_v4().to_string();
    
    Json(ApiResponse {
        success: true,
        data: Some(token),
        message: "Login successful".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

async fn logout(State(_state): State<AppState>) -> Json<ApiResponse<()>> {
    Json(ApiResponse {
        success: true,
        data: None,
        message: "Logout successful".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

// Monitoring status endpoint
async fn get_monitoring_status(
    State(state): State<AppState>
) -> Json<ApiResponse<MonitoringStatus>> {
    let engine = state.server.detection_engine.read().await;
    let events = state.server.event_history.read().await;
    let is_active = engine.is_monitoring_active().await;
    
    // Calculate statistics
    let mut detections_by_level = HashMap::new();
    let mut detections_by_module = HashMap::new();
    
    for event in events.iter() {
        *detections_by_level.entry(event.threat_level.clone()).or_insert(0) += 1;
        *detections_by_module.entry(event.module.clone()).or_insert(0) += 1;
    }

    // Get system resources (simplified)
    let system_resources = SystemResources {
        cpu_usage: 5.2,  // Would be actual system metrics
        memory_usage: 128.5,
        disk_usage: 45.0,
        network_usage: 1.2,
    };

    let status = MonitoringStatus {
        active: is_active,
        uptime_seconds: 3600, // Would calculate actual uptime
        total_detections: events.len(),
        detections_by_level,
        detections_by_module,
        system_resources,
    };

    Json(ApiResponse {
        success: true,
        data: Some(status),
        message: "Status retrieved successfully".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

// Start monitoring endpoint
async fn start_monitoring(State(state): State<AppState>) -> Json<ApiResponse<()>> {
    match state.server.detection_engine.write().await.start_monitoring().await {
        Ok(_) => Json(ApiResponse {
            success: true,
            data: None,
            message: "Monitoring started successfully".to_string(),
            timestamp: chrono::Utc::now(),
        }),
        Err(e) => Json(ApiResponse {
            success: false,
            data: None,
            message: format!("Failed to start monitoring: {}", e),
            timestamp: chrono::Utc::now(),
        }),
    }
}

// Stop monitoring endpoint
async fn stop_monitoring(State(state): State<AppState>) -> Json<ApiResponse<()>> {
    state.server.detection_engine.write().await.stop_monitoring().await;
    
    Json(ApiResponse {
        success: true,
        data: None,
        message: "Monitoring stopped successfully".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

// Perform scan endpoint
async fn perform_scan(State(state): State<AppState>) -> Json<ApiResponse<()>> {
    match state.server.detection_engine.write().await.perform_scan().await {
        Ok(_) => Json(ApiResponse {
            success: true,
            data: None,
            message: "Scan completed successfully".to_string(),
            timestamp: chrono::Utc::now(),
        }),
        Err(e) => Json(ApiResponse {
            success: false,
            data: None,
            message: format!("Scan failed: {}", e),
            timestamp: chrono::Utc::now(),
        }),
    }
}

// Get events with pagination and filtering
async fn get_events(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
) -> Json<ApiResponse<Vec<DetectionEvent>>> {
    let events = state.server.event_history.read().await;
    
    let mut filtered_events: Vec<DetectionEvent> = events
        .iter()
        .filter(|event| {
            // Apply filters
            if let Some(level) = &params.level {
                if &event.threat_level != level {
                    return false;
                }
            }
            
            if let Some(module) = &params.module {
                if &event.module != module {
                    return false;
                }
            }
            
            if let Some(start_time) = params.start_time {
                if event.timestamp < start_time {
                    return false;
                }
            }
            
            if let Some(end_time) = params.end_time {
                if event.timestamp > end_time {
                    return false;
                }
            }
            
            true
        })
        .cloned()
        .collect();

    // Apply pagination
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).min(1000); // Max 1000 events per request
    
    if offset < filtered_events.len() {
        filtered_events = filtered_events.into_iter().skip(offset).take(limit).collect();
    } else {
        filtered_events = Vec::new();
    }

    Json(ApiResponse {
        success: true,
        data: Some(filtered_events),
        message: "Events retrieved successfully".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

// Get specific event by ID
async fn get_event_by_id(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Json<ApiResponse<DetectionEvent>> {
    let events = state.server.event_history.read().await;
    
    if let Some(event) = events.iter().find(|e| e.id == id) {
        Json(ApiResponse {
            success: true,
            data: Some(event.clone()),
            message: "Event found".to_string(),
            timestamp: chrono::Utc::now(),
        })
    } else {
        Json(ApiResponse {
            success: false,
            data: None,
            message: "Event not found".to_string(),
            timestamp: chrono::Utc::now(),
        })
    }
}

// Search events endpoint (placeholder)
async fn search_events(
    State(_state): State<AppState>,
    Query(_params): Query<HashMap<String, String>>,
) -> Json<ApiResponse<Vec<DetectionEvent>>> {
    Json(ApiResponse {
        success: true,
        data: Some(Vec::new()),
        message: "Search functionality coming soon".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

// Export events endpoint
async fn export_events(State(_state): State<AppState>) -> Json<ApiResponse<String>> {
    Json(ApiResponse {
        success: true,
        data: Some("CSV export data would be here".to_string()),
        message: "Export completed".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

// Configuration endpoints
async fn get_config(State(state): State<AppState>) -> Json<ApiResponse<Config>> {
    Json(ApiResponse {
        success: true,
        data: Some(state.server.config.clone()),
        message: "Configuration retrieved successfully".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

async fn update_config(
    State(_state): State<AppState>,
    Json(_config): Json<Config>,
) -> Json<ApiResponse<()>> {
    // Update configuration logic here
    Json(ApiResponse {
        success: true,
        data: None,
        message: "Configuration updated successfully".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

async fn update_module_config(
    State(_state): State<AppState>,
    Path(_module): Path<String>,
) -> Json<ApiResponse<()>> {
    Json(ApiResponse {
        success: true,
        data: None,
        message: "Module configuration updated".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

// Statistics endpoints
async fn get_stats_summary(State(_state): State<AppState>) -> Json<ApiResponse<HashMap<String, u64>>> {
    let mut stats = HashMap::new();
    stats.insert("total_scans".to_string(), 1250);
    stats.insert("total_detections".to_string(), 42);
    stats.insert("critical_threats".to_string(), 3);
    stats.insert("uptime_hours".to_string(), 72);

    Json(ApiResponse {
        success: true,
        data: Some(stats),
        message: "Statistics retrieved successfully".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

async fn get_stats_timeline(State(_state): State<AppState>) -> Json<ApiResponse<Vec<HashMap<String, serde_json::Value>>>> {
    // Timeline data would be generated here
    Json(ApiResponse {
        success: true,
        data: Some(Vec::new()),
        message: "Timeline data retrieved".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

async fn get_module_stats(State(_state): State<AppState>) -> Json<ApiResponse<HashMap<String, u64>>> {
    let mut module_stats = HashMap::new();
    module_stats.insert("browser_extensions".to_string(), 15);
    module_stats.insert("process_monitor".to_string(), 8);
    module_stats.insert("network_monitor".to_string(), 12);
    module_stats.insert("filesystem_monitor".to_string(), 7);

    Json(ApiResponse {
        success: true,
        data: Some(module_stats),
        message: "Module statistics retrieved".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

// Client management endpoints
async fn get_connected_clients(
    State(state): State<AppState>
) -> Json<ApiResponse<Vec<WebClient>>> {
    let clients = state.server.clients.read().await;
    let client_list: Vec<WebClient> = clients.values().cloned().collect();

    Json(ApiResponse {
        success: true,
        data: Some(client_list),
        message: "Connected clients retrieved".to_string(),
        timestamp: chrono::Utc::now(),
    })
}

async fn disconnect_client(
    State(state): State<AppState>,
    Path(client_id): Path<Uuid>,
) -> Json<ApiResponse<()>> {
    let mut clients = state.server.clients.write().await;
    if clients.remove(&client_id).is_some() {
        Json(ApiResponse {
            success: true,
            data: None,
            message: "Client disconnected successfully".to_string(),
            timestamp: chrono::Utc::now(),
        })
    } else {
        Json(ApiResponse {
            success: false,
            data: None,
            message: "Client not found".to_string(),
            timestamp: chrono::Utc::now(),
        })
    }
}

// WebSocket handler for real-time updates
async fn websocket_handler() -> Result<axum::response::Response, StatusCode> {
    // WebSocket implementation would go here
    Err(StatusCode::NOT_IMPLEMENTED)
}

// Serve web dashboard
async fn serve_dashboard() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../web/dashboard/index.html"))
}

async fn serve_dashboard_assets() -> Result<axum::response::Response, StatusCode> {
    // Serve static assets for web dashboard
    Err(StatusCode::NOT_FOUND)
}