use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{error, info};

pub struct NetworkClient {
    teacher_pc_port: u16,
}

impl NetworkClient {
    pub fn new(teacher_pc_port: u16) -> Self {
        Self { teacher_pc_port }
    }

    pub async fn send_data(&self, data: String) -> Result<(), Box<dyn std::error::Error>> {
        let teacher_pc_address = format!("127.0.0.1:{}", self.teacher_pc_port);
        info!("Attempting to connect to teacher PC at {}", teacher_pc_address);
        match TcpStream::connect(&teacher_pc_address).await {
            Ok(mut stream) => {
                info!("Connected to teacher PC. Sending data...");
                stream.write_all(data.as_bytes()).await?;
                info!("Data sent successfully.");
                Ok(())
            }
            Err(e) => {
                error!("Failed to connect to teacher PC or send data: {}", e);
                Err(e.into())
            }
        }
    }
}