use crate::config::AppConfig;
use crate::logger::FileLogger;
use crate::monitors::bam_realtime::BamMonitoringService;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ApiState {
    pub config: Arc<AppConfig>,
    pub bam_service: Arc<RwLock<BamMonitoringService>>,
    pub file_logger: Arc<FileLogger>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub description: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub status: String,
    pub mic_usage_detected: bool,
    pub suspicious_processes: Vec<String>,
    pub bam_anomaly_score: Option<f64>,
    pub bam_is_ai_like: Option<bool>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlertResponse {
    pub id: String,
    pub session_id: String,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub metadata: serde_json::Value,
    pub created_at: String,
    pub acknowledged_at: Option<String>,
    pub acknowledged_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BamResultResponse {
    pub id: String,
    pub session_id: String,
    pub latencies: Vec<f64>,
    pub mean_latency: f64,
    pub anomaly_score: f64,
    pub is_ai_like: bool,
    pub confidence: f64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub code: u16,
}

pub struct ApiServer {
    state: ApiState,
}

impl ApiServer {
    pub fn new(
        config: Arc<AppConfig>,
        bam_service: Arc<RwLock<BamMonitoringService>>,
        file_logger: Arc<FileLogger>,
    ) -> Self {
        Self {
            state: ApiState {
                config,
                bam_service,
                file_logger,
            },
        }
    }

    pub fn create_router(&self) -> Router {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        Router::new()
            .route("/health", get(Self::health_check))
            .route("/status", get(Self::get_status))
            .route("/sessions", post(Self::create_session))
            .route("/sessions", get(Self::list_sessions))
            .route("/sessions/:session_id", get(Self::get_session))
            .route("/sessions/:session_id", delete(Self::end_session))
            .route("/sessions/:session_id/stats", get(Self::get_session_stats))
            .route("/sessions/:session_id/alerts", get(Self::get_session_alerts))
            .route("/sessions/:session_id/bam-results", get(Self::get_session_bam_results))
            .route("/alerts", get(Self::list_alerts))
            .route("/alerts/:alert_id/acknowledge", put(Self::acknowledge_alert))
            .route("/monitoring/active", get(Self::get_active_monitoring))
            .route("/monitoring/:session_id/start", post(Self::start_monitoring))
            .route("/monitoring/:session_id/stop", post(Self::stop_monitoring))
            .layer(cors)
            .with_state(self.state.clone())
    }

    async fn health_check() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "status": "healthy",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "service": "CluelyGuard API"
        }))
    }

    async fn get_status(
        State(state): State<ApiState>,
    ) -> Json<StatusResponse> {
        let response = StatusResponse {
            status: "operational".to_string(),
            version: state.config.app.version.clone(),
            uptime_seconds: 0, // TODO: Implement uptime tracking
        };

        Json(response)
    }

    async fn create_session(
        State(_state): State<ApiState>,
    ) -> Json<CreateSessionResponse> {
        info!("Creating new monitoring session");
        // In file-based mode, just return a dummy session
        let session_id = Uuid::new_v4().to_string();
        let response = CreateSessionResponse {
            session_id: session_id.clone(),
            status: "active".to_string(),
        };
        info!("Session created: {}", response.session_id);
        Json(response)
    }

    async fn list_sessions(
        State(state): State<ApiState>,
        Query(_params): Query<HashMap<String, String>>,
    ) -> Result<Json<Vec<SessionResponse>>, (StatusCode, Json<ErrorResponse>)> {
        // Read sessions from file logs
        match state.file_logger.get_sessions() {
            Ok(sessions) => {
                let response: Vec<SessionResponse> = sessions.into_iter().map(|session| SessionResponse {
                    id: session.id,
                    started_at: session.started_at.to_rfc3339(),
                    ended_at: session.ended_at.map(|dt| dt.to_rfc3339()),
                    status: session.status,
                    mic_usage_detected: session.mic_usage_detected,
                    suspicious_processes: session.suspicious_processes,
                    bam_anomaly_score: session.bam_anomaly_score,
                    bam_is_ai_like: session.bam_is_ai_like,
                    created_at: session.created_at.to_rfc3339(),
                    updated_at: session.updated_at.to_rfc3339(),
                }).collect();
                Ok(Json(response))
            }
            Err(e) => {
                error!("Failed to read sessions: {}", e);
                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "file_error".to_string(),
                    message: "Failed to read sessions".to_string(),
                    code: 500,
                })))
            }
        }
    }

    async fn get_session(
        State(state): State<ApiState>,
        Path(session_id): Path<String>,
    ) -> Result<Json<SessionResponse>, (StatusCode, Json<ErrorResponse>)> {
        // Read specific session from file logs
        match state.file_logger.get_sessions() {
            Ok(sessions) => {
                if let Some(session) = sessions.into_iter().find(|s| s.id == session_id) {
                    let response = SessionResponse {
                        id: session.id,
                        started_at: session.started_at.to_rfc3339(),
                        ended_at: session.ended_at.map(|dt| dt.to_rfc3339()),
                        status: session.status,
                        mic_usage_detected: session.mic_usage_detected,
                        suspicious_processes: session.suspicious_processes,
                        bam_anomaly_score: session.bam_anomaly_score,
                        bam_is_ai_like: session.bam_is_ai_like,
                        created_at: session.created_at.to_rfc3339(),
                        updated_at: session.updated_at.to_rfc3339(),
                    };
                    Ok(Json(response))
                } else {
                    Err((StatusCode::NOT_FOUND, Json(ErrorResponse {
                        error: "not_found".to_string(),
                        message: format!("Session {} not found", session_id),
                        code: 404,
                    })))
                }
            }
            Err(e) => {
                error!("Failed to read sessions: {}", e);
                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "file_error".to_string(),
                    message: "Failed to read sessions".to_string(),
                    code: 500,
                })))
            }
        }
    }

    async fn end_session(
        State(_state): State<ApiState>,
        Path(_session_id): Path<String>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        // In file-based mode, just return success
        let response = serde_json::json!({
            "status": "ended",
            "message": "Session ended successfully"
        });
        Ok(Json(response))
    }

    async fn get_session_stats(
        State(_state): State<ApiState>,
        Path(_session_id): Path<String>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        // In file-based mode, return dummy stats
        Ok(Json(serde_json::json!({})))
    }

    async fn get_session_alerts(
        State(state): State<ApiState>,
        Path(session_id): Path<String>,
    ) -> Result<Json<Vec<AlertResponse>>, (StatusCode, Json<ErrorResponse>)> {
        // Read alerts for specific session from file logs
        match state.file_logger.get_session_alerts(&session_id) {
            Ok(alerts) => {
                let response: Vec<AlertResponse> = alerts.into_iter().map(|alert| AlertResponse {
                    id: alert.id,
                    session_id: alert.session_id,
                    alert_type: alert.alert_type,
                    severity: alert.severity,
                    message: alert.message,
                    metadata: alert.metadata,
                    created_at: alert.created_at.to_rfc3339(),
                    acknowledged_at: alert.acknowledged_at.map(|dt| dt.to_rfc3339()),
                    acknowledged_by: alert.acknowledged_by,
                }).collect();
                Ok(Json(response))
            }
            Err(e) => {
                error!("Failed to read alerts for session {}: {}", session_id, e);
                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "file_error".to_string(),
                    message: "Failed to read alerts".to_string(),
                    code: 500,
                })))
            }
        }
    }

    async fn get_session_bam_results(
        State(state): State<ApiState>,
        Path(session_id): Path<String>,
    ) -> Result<Json<Vec<BamResultResponse>>, (StatusCode, Json<ErrorResponse>)> {
        // Read BAM results for specific session from file logs
        match state.file_logger.get_session_bam_results(&session_id) {
            Ok(results) => {
                let response: Vec<BamResultResponse> = results.into_iter().map(|result| BamResultResponse {
                    id: result.id,
                    session_id: result.session_id,
                    latencies: result.latencies,
                    mean_latency: result.mean_latency,
                    anomaly_score: result.anomaly_score,
                    is_ai_like: result.is_ai_like,
                    confidence: result.confidence,
                    created_at: result.created_at.to_rfc3339(),
                }).collect();
                Ok(Json(response))
            }
            Err(e) => {
                error!("Failed to read BAM results for session {}: {}", session_id, e);
                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "file_error".to_string(),
                    message: "Failed to read BAM results".to_string(),
                    code: 500,
                })))
            }
        }
    }

    async fn list_alerts(
        State(state): State<ApiState>,
        Query(_params): Query<HashMap<String, String>>,
    ) -> Result<Json<Vec<AlertResponse>>, (StatusCode, Json<ErrorResponse>)> {
        // Read all alerts from file logs
        match state.file_logger.get_alerts() {
            Ok(alerts) => {
                let response: Vec<AlertResponse> = alerts.into_iter().map(|alert| AlertResponse {
                    id: alert.id,
                    session_id: alert.session_id,
                    alert_type: alert.alert_type,
                    severity: alert.severity,
                    message: alert.message,
                    metadata: alert.metadata,
                    created_at: alert.created_at.to_rfc3339(),
                    acknowledged_at: alert.acknowledged_at.map(|dt| dt.to_rfc3339()),
                    acknowledged_by: alert.acknowledged_by,
                }).collect();
                Ok(Json(response))
            }
            Err(e) => {
                error!("Failed to read alerts: {}", e);
                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "file_error".to_string(),
                    message: "Failed to read alerts".to_string(),
                    code: 500,
                })))
            }
        }
    }

    async fn acknowledge_alert(
        State(_state): State<ApiState>,
        Path(_alert_id): Path<String>,
        _headers: HeaderMap,
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        // In file-based mode, just return success
        let response = serde_json::json!({
            "status": "acknowledged",
            "message": "Alert acknowledged"
        });
        Ok(Json(response))
    }

    async fn get_active_monitoring(
        State(_state): State<ApiState>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        // In file-based mode, return dummy data
        Ok(Json(serde_json::json!({ "active_sessions": [] })))
    }

    async fn start_monitoring(
        State(_state): State<ApiState>,
        Path(_session_id): Path<String>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        // In file-based mode, just return success
        let response = serde_json::json!({
            "status": "started",
            "message": "Monitoring started"
        });
        Ok(Json(response))
    }

    async fn stop_monitoring(
        State(_state): State<ApiState>,
        Path(_session_id): Path<String>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        // In file-based mode, just return success
        let response = serde_json::json!({
            "status": "stopped",
            "message": "Monitoring stopped"
        });
        Ok(Json(response))
    }
} 