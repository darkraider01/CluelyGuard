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
                info!("Connected to teacher PC. Sending data.");
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_network_client_new() {
        let client = NetworkClient::new(8080);
        assert_eq!(client.teacher_pc_port, 8080);
    }

    #[tokio::test]
    async fn test_network_client_send_data_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn a task to act as the server
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            socket.read_to_end(&mut buffer).await.unwrap();
            let received_data = String::from_utf8(buffer).unwrap();
            assert_eq!(received_data, "test data");
        });

        let client = NetworkClient::new(port);
        let result = client.send_data("test data".to_string()).await;
        assert!(result.is_ok(), "Send data failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_network_client_send_data_connection_error() {
        // Use a port that's unlikely to have a server listening
        let client = NetworkClient::new(12345); 
        let result = client.send_data("test data".to_string()).await;
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Connection refused") || error_message.contains("timed out") || error_message.contains("actively refused"), "Unexpected error: {}", error_message);
    }
}