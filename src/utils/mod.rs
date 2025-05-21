mod logger;
mod config;

pub use logger::setup_logger;
pub use config::{Config, ConfigError};

/// 获取应用程序版本
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// 获取应用程序名称
pub fn name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// 获取应用程序描述
pub fn description() -> &'static str {
    env!("CARGO_PKG_DESCRIPTION")
}

/// 生成随机ID
pub fn random_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let id: u64 = rng.gen();
    format!("{:016x}", id)
}

/// 格式化字节大小为可读字符串
pub fn format_bytes(bytes: usize) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let bytes = bytes as f64;
    let base = 1024_f64;
    
    let exponent = (bytes.ln() / base.ln()).floor() as usize;
    let exponent = exponent.min(UNITS.len() - 1);
    
    let value = bytes / base.powi(exponent as i32);
    
    format!("{:.2} {}", value, UNITS[exponent])
}

/// 格式化时间戳为人类可读时间
pub fn format_timestamp(timestamp: u64) -> String {
    let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
    
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// 计算两个地址之间的RTT
pub async fn calculate_rtt(addr: &std::net::SocketAddr) -> Option<std::time::Duration> {
    use tokio::net::UdpSocket;
    use tokio::time::Instant;
    
    // 创建UDP套接字
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return None,
    };
    
    // 设置超时
    let _ = socket.connect(addr).await;
    
    // 发送ping包
    let ping = [0; 1];
    let start = Instant::now();
    
    match socket.send(&ping).await {
        Ok(_) => {},
        Err(_) => return None,
    }
    
    // 等待响应
    let mut buf = [0; 1024];
    match tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buf)).await {
        Ok(Ok(_)) => {
            // 计算RTT
            let rtt = start.elapsed();
            Some(rtt)
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023.00 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }
    
    #[test]
    fn test_random_id() {
        let id1 = random_id();
        let id2 = random_id();
        
        // 两次生成的ID应该不同
        assert_ne!(id1, id2);
        
        // ID长度应该为16个字符
        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
    }
}
