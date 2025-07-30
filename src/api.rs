use crate::config::AppConfig;
use crate::logger::{FileLogger, SessionLog, AlertLog, BamResultLog};
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use mockall::predicate::*;
    use mockall::*;
    use chrono::{Utc, TimeZone};
    use serde_json::json;

    // Mock for AppConfig
    mock! {
        pub AppConfig {}
        impl AppConfig for AppConfig {
            fn load(path: Option<&PathBuf>) -> Result<Self, config::ConfigError>;
            fn validate(&self) -> Result<(), Vec<String>>;
            fn is_development(&self) -> bool;
            fn is_production(&self) -> bool;
        }
        trait AppConfigTrait {
            fn load(path: Option<&PathBuf>) -> Result<MockAppConfig, config::ConfigError>;
        }
        impl AppConfigTrait for MockAppConfig {
            fn load(path: Option<&PathBuf>) -> Result<MockAppConfig, config::ConfigError> {
                let mut mock = MockAppConfig::new();
                mock.expect_load()
                    .return_once(|_| {
                        Ok(MockAppConfig::default())
                    });
                Ok(mock)
            }
        }
    }

    // Mock for FileLogger
    mock! {
        pub FileLogger {}
        impl FileLogger for FileLogger {
            fn new(config: Arc<AppConfig>) -> Result<Self, std::io::Error>;
            fn append_to_log_file(&self, log_entry: &str) -> Result<(), std::io::Error>;
            fn log_session(&self, session: &SessionLog) -> Result<(), std::io::Error>;
            fn log_alert(&self, alert: &AlertLog) -> Result<(), std::io::Error>;
            fn log_bam_result(&self, result: &BamResultLog) -> Result<(), std::io::Error>;
            fn log_ram_dump(&self, dump: &RamDumpLog) -> Result<(), std::io::Error>;
            fn get_sessions(&self) -> Result<Vec<SessionLog>, std::io::Error>;
            fn get_alerts(&self) -> Result<Vec<AlertLog>, std::io::Error>;
            fn get_bam_results(&self) -> Result<Vec<BamResultLog>, std::io::Error>;
            fn get_ram_dumps(&self) -> Result<Vec<RamDumpLog>, std::io::Error>;
            fn get_session_alerts(&self, session_id: &str) -> Result<Vec<AlertLog>, std::io::Error>;
            fn get_session_bam_results(&self, session_id: &str) -> Result<Vec<BamResultLog>, std::io::Error>;
            fn get_session_ram_dumps(&self, session_id: &str) -> Result<Vec<RamDumpLog>, std::io::Error>;
            fn create_ram_dump(session_id: &str, student_code: &str) -> Result<RamDumpLog, Box<dyn std::error::Error>>;
        }
    }

    // Mock for BamMonitoringService
    mock! {
        pub BamMonitoringService {}
        impl BamMonitoringService for BamMonitoringService {
            fn new(config: Arc<AppConfig>, file_logger: Arc<FileLogger>, ram_dumper: Arc<RamDumpLog>) -> Self;
            fn start_session_monitoring(&mut self, session_id: String) -> Result<(), Box<dyn std::error::Error>>;
            fn stop_session_monitoring(&mut self, session_id: &str);
            fn is_monitoring(&self, session_id: &str) -> bool;
            fn get_active_sessions(&self) -> Vec<String>;
        }
    }

    // Helper to create a test ApiState with mocks
    fn create_test_api_state() -> ApiState {
        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_file_logger = MockFileLogger::new();
        let mut mock_bam_service = MockBamMonitoringService::new();
        mock_bam_service.expect_new().return_once(|_, _, _| MockBamMonitoringService::default());


        ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        }
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = create_test_api_state();
        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["service"], "CluelyGuard API");
        assert!(json["timestamp"].is_string());
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        let state = create_test_api_state();
        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let status_response: StatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(status_response.status, "operational");
        assert_eq!(status_response.version, "1.0.0");
        assert_eq!(status_response.uptime_seconds, 0); // TODO: Implement uptime tracking
    }

    #[tokio::test]
    async fn test_create_session_endpoint() {
        let state = create_test_api_state();
        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"description": "Test session"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let create_session_response: CreateSessionResponse = serde_json::from_slice(&body).unwrap();
        assert!(!create_session_response.session_id.is_empty());
        assert_eq!(create_session_response.status, "active");
    }

    #[tokio::test]
    async fn test_list_sessions_endpoint() {
        let mut mock_file_logger = MockFileLogger::new();
        mock_file_logger.expect_get_sessions()
            .return_once(|| {
                Ok(vec![
                    SessionLog {
                        id: "session1".to_string(),
                        started_at: Utc.timestamp_opt(1678886400, 0).unwrap(),
                        ended_at: None,
                        status: "active".to_string(),
                        mic_usage_detected: false,
                        suspicious_processes: vec![],
                        bam_anomaly_score: None,
                        bam_is_ai_like: None,
                        created_at: Utc.timestamp_opt(1678886400, 0).unwrap(),
                        updated_at: Utc.timestamp_opt(1678886400, 0).unwrap(),
                    },
                    SessionLog {
                        id: "session2".to_string(),
                        started_at: Utc.timestamp_opt(1678886500, 0).unwrap(),
                        ended_at: Some(Utc.timestamp_opt(1678886600, 0).unwrap()),
                        status: "ended".to_string(),
                        mic_usage_detected: true,
                        suspicious_processes: vec!["process_x".to_string()],
                        bam_anomaly_score: Some(0.9),
                        bam_is_ai_like: Some(true),
                        created_at: Utc.timestamp_opt(1678886500, 0).unwrap(),
                        updated_at: Utc.timestamp_opt(1678886600, 0).unwrap(),
                    },
                ])
            });

        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_bam_service = MockBamMonitoringService::new();

        let state = ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        };

        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let sessions_response: Vec<SessionResponse> = serde_json::from_slice(&body).unwrap();
        assert_eq!(sessions_response.len(), 2);
        assert_eq!(sessions_response[0].id, "session1");
        assert_eq!(sessions_response[1].id, "session2");
    }

    #[tokio::test]
    async fn test_get_session_endpoint_success() {
        let mut mock_file_logger = MockFileLogger::new();
        mock_file_logger.expect_get_sessions()
            .return_once(|| {
                Ok(vec![
                    SessionLog {
                        id: "session1".to_string(),
                        started_at: Utc.timestamp_opt(1678886400, 0).unwrap(),
                        ended_at: None,
                        status: "active".to_string(),
                        mic_usage_detected: false,
                        suspicious_processes: vec![],
                        bam_anomaly_score: None,
                        bam_is_ai_like: None,
                        created_at: Utc.timestamp_opt(1678886400, 0).unwrap(),
                        updated_at: Utc.timestamp_opt(1678886400, 0).unwrap(),
                    },
                ])
            });

        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_bam_service = MockBamMonitoringService::new();

        let state = ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        };

        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/sessions/session1").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let session_response: SessionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(session_response.id, "session1");
    }

    #[tokio::test]
    async fn test_get_session_endpoint_not_found() {
        let mut mock_file_logger = MockFileLogger::new();
        mock_file_logger.expect_get_sessions()
            .return_once(|| Ok(vec![])); // Return empty vec for no sessions

        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_bam_service = MockBamMonitoringService::new();

        let state = ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        };

        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/sessions/nonexistent_session").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let error_response: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response.error, "not_found");
        assert!(error_response.message.contains("Session nonexistent_session not found"));
    }

    #[tokio::test]
    async fn test_end_session_endpoint() {
        let state = create_test_api_state();
        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/sessions/some_session_id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ended");
        assert_eq!(json["message"], "Session ended successfully");
    }

    #[tokio::test]
    async fn test_get_session_stats_endpoint() {
        let state = create_test_api_state();
        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/sessions/some_session_id/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_object());
        assert!(json.as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_session_alerts_endpoint() {
        let mut mock_file_logger = MockFileLogger::new();
        mock_file_logger.expect_get_session_alerts()
            .with(eq("session1"))
            .return_once(|_| {
                Ok(vec![
                    AlertLog {
                        id: "alert1".to_string(),
                        session_id: "session1".to_string(),
                        alert_type: "bam_anomaly".to_string(),
                        severity: "high".to_string(),
                        message: "AI detected".to_string(),
                        metadata: json!({}),
                        created_at: Utc.timestamp_opt(1678886400, 0).unwrap(),
                        acknowledged_at: None,
                        acknowledged_by: None,
                    },
                ])
            });

        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_bam_service = MockBamMonitoringService::new();

        let state = ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        };

        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/sessions/session1/alerts").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let alerts_response: Vec<AlertResponse> = serde_json::from_slice(&body).unwrap();
        assert_eq!(alerts_response.len(), 1);
        assert_eq!(alerts_response[0].session_id, "session1");
        assert_eq!(alerts_response[0].alert_type, "bam_anomaly");
    }

    #[tokio::test]
    async fn test_get_session_bam_results_endpoint() {
        let mut mock_file_logger = MockFileLogger::new();
        mock_file_logger.expect_get_session_bam_results()
            .with(eq("session1"))
            .return_once(|_| {
                Ok(vec![
                    BamResultLog {
                        id: "bam_res1".to_string(),
                        session_id: "session1".to_string(),
                        latencies: vec![0.1, 0.2, 0.3],
                        mean_latency: 0.2,
                        anomaly_score: 0.8,
                        is_ai_like: true,
                        confidence: 0.9,
                        created_at: Utc.timestamp_opt(1678886400, 0).unwrap(),
                    },
                ])
            });

        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_bam_service = MockBamMonitoringService::new();

        let state = ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        };

        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/sessions/session1/bam-results").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let bam_results_response: Vec<BamResultResponse> = serde_json::from_slice(&body).unwrap();
        assert_eq!(bam_results_response.len(), 1);
        assert_eq!(bam_results_response[0].session_id, "session1");
        assert_eq!(bam_results_response[0].anomaly_score, 0.8);
    }

    #[tokio::test]
    async fn test_list_alerts_endpoint() {
        let mut mock_file_logger = MockFileLogger::new();
        mock_file_logger.expect_get_alerts()
            .return_once(|| {
                Ok(vec![
                    AlertLog {
                        id: "alert1".to_string(),
                        session_id: "session1".to_string(),
                        alert_type: "bam_anomaly".to_string(),
                        severity: "high".to_string(),
                        message: "AI detected".to_string(),
                        metadata: json!({}),
                        created_at: Utc.timestamp_opt(1678886400, 0).unwrap(),
                        acknowledged_at: None,
                        acknowledged_by: None,
                    },
                ])
            });

        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_bam_service = MockBamMonitoringService::new();

        let state = ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        };

        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/alerts").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let alerts_response: Vec<AlertResponse> = serde_json::from_slice(&body).unwrap();
        assert_eq!(alerts_response.len(), 1);
        assert_eq!(alerts_response[0].id, "alert1");
    }

    #[tokio::test]
    async fn test_acknowledge_alert_endpoint() {
        let state = create_test_api_state();
        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/alerts/alert1/acknowledge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "acknowledged");
        assert_eq!(json["message"], "Alert acknowledged");
    }

    #[tokio::test]
    async fn test_get_active_monitoring_endpoint() {
        let mut mock_bam_service = MockBamMonitoringService::new();
        mock_bam_service.expect_get_active_sessions()
            .return_once(|| vec!["session_active_1".to_string(), "session_active_2".to_string()]);

        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_file_logger = MockFileLogger::new();

        let state = ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        };

        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(Request::builder().uri("/monitoring/active").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["active_sessions"], json!(["session_active_1", "session_active_2"]));
    }

    #[tokio::test]
    async fn test_start_monitoring_endpoint() {
        let mut mock_bam_service = MockBamMonitoringService::new();
        mock_bam_service.expect_start_session_monitoring()
            .with(eq("new_session_id".to_string()))
            .return_once(|_| Ok(()));

        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_file_logger = MockFileLogger::new();

        let state = ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        };

        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/monitoring/new_session_id/start")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "started");
        assert_eq!(json["message"], "Monitoring started");
    }

    #[tokio::test]
    async fn test_stop_monitoring_endpoint() {
        let mut mock_bam_service = MockBamMonitoringService::new();
        mock_bam_service.expect_stop_session_monitoring()
            .with(eq("existing_session_id"));

        let mut mock_config = MockAppConfig::new();
        mock_config.expect_app().return_const(crate::config::AppSettings {
            name: "TestApp".to_string(),
            version: "1.0.0".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            teacher_pc_port: 8081,
        });

        let mock_file_logger = MockFileLogger::new();

        let state = ApiState {
            config: Arc::new(mock_config),
            bam_service: Arc::new(RwLock::new(mock_bam_service)),
            file_logger: Arc::new(mock_file_logger),
        };

        let app = ApiServer { state }.create_router();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/monitoring/existing_session_id/stop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "stopped");
        assert_eq!(json["message"], "Monitoring stopped");
    }

}