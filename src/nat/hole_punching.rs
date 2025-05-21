use crate::nat::NatError;
use std::net::SocketAddr;
use std::time::Duration;
use log::{debug, info, warn};
// 移除未使用的导入
// use log::error;
use rand::Rng;

/// UDP打洞策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchingStrategy {
    /// 简单打洞：双方向对方已知地址发送数据包
    Simple,
    
    /// 增强打洞：尝试预测对方可能使用的端口
    Enhanced,
    
    /// 激进打洞：使用多个端口同时尝试
    Aggressive,
}

/// 开始UDP打洞过程
pub async fn start_hole_punching(
    local_socket: &tokio::net::UdpSocket,
    peer_addr: SocketAddr,
    strategy: PunchingStrategy,
    timeout: Duration,
) -> Result<(), NatError> {
    match strategy {
        PunchingStrategy::Simple => simple_punching(local_socket, peer_addr, timeout).await,
        PunchingStrategy::Enhanced => enhanced_punching(local_socket, peer_addr, timeout).await,
        PunchingStrategy::Aggressive => aggressive_punching(local_socket, peer_addr, timeout).await,
    }
}

/// 简单打洞策略
async fn simple_punching(
    local_socket: &tokio::net::UdpSocket,
    peer_addr: SocketAddr,
    timeout: Duration,
) -> Result<(), NatError> {
    // 打洞魔数，用于标识打洞包
    let magic = [0xB4, 0xD9, 0xF0, 0x0D]; // "HOLE" in hex
    
    // 创建打洞数据包
    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(&magic);
    packet.extend_from_slice(&[0, 0, 0, 0]); // 预留4字节
    
    // 生成随机值
    let random_value: u32 = rand::thread_rng().gen();
    packet.extend_from_slice(&random_value.to_be_bytes());
    
    info!("Starting simple hole punching to {}", peer_addr);
    
    // 发送几个打洞包
    for i in 0..5 {
        // 更新序列号
        packet[4] = (i & 0xFF) as u8;
        
        // 发送打洞包
        local_socket.send_to(&packet, peer_addr).await
            .map_err(|e| NatError::HolePunchingError(format!("Failed to send hole punching packet: {}", e)))?;
        
        debug!("Sent hole punching packet {} to {}", i, peer_addr);
        
        // 短暂等待，避免过快发送
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    // 等待接收打洞包或超时
    let mut buf = [0u8; 1024];
    let timeout_result = tokio::time::timeout(timeout, async {
        loop {
            match local_socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    // 检查是否来自目标对等点
                    if addr.ip() == peer_addr.ip() {
                        // 检查魔数
                        if len >= 4 && buf[0..4] == magic {
                            debug!("Received hole punching packet from {}", addr);
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    return Err(NatError::HolePunchingError(format!("Failed to receive packet: {}", e)));
                }
            }
        }
    }).await;
    
    match timeout_result {
        Ok(result) => result,
        Err(_) => Err(NatError::Timeout),
    }
}

/// 增强打洞策略
async fn enhanced_punching(
    local_socket: &tokio::net::UdpSocket,
    peer_addr: SocketAddr,
    timeout: Duration,
) -> Result<(), NatError> {
    // 基本的增强打洞：尝试对端口进行预测
    let ip = peer_addr.ip();
    let base_port = peer_addr.port();
    
    // 创建一组可能的目标地址
    let mut target_addrs = Vec::new();
    
    // 添加原始地址
    target_addrs.push(peer_addr);
    
    // 添加附近的端口
    for delta in &[-2, -1, 1, 2] {
        let port = (base_port as i32 + delta) as u16;
        target_addrs.push(SocketAddr::new(ip, port));
    }
    
    // 打洞魔数
    let magic = [0xB4, 0xD9, 0xF0, 0x0D];
    
    // 创建打洞数据包
    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(&magic);
    packet.extend_from_slice(&[0, 0, 0, 0]); // 预留4字节
    
    // 生成随机值
    let random_value: u32 = rand::thread_rng().gen();
    packet.extend_from_slice(&random_value.to_be_bytes());
    
    info!("Starting enhanced hole punching to {} and nearby ports", peer_addr);
    
    // 发送几轮打洞包
    for round in 0..3 {
        for (i, target) in target_addrs.iter().enumerate() {
            // 更新序列号
            packet[4] = round as u8;
            packet[5] = i as u8;
            
            // 发送打洞包
            match local_socket.send_to(&packet, target).await {
                Ok(_) => {
                    debug!("Sent hole punching packet to {}", target);
                }
                Err(e) => {
                    warn!("Failed to send hole punching packet to {}: {}", target, e);
                }
            }
            
            // 短暂等待，避免过快发送
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        
        // 轮次之间的等待
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    
    // 等待接收打洞包或超时
    let mut buf = [0u8; 1024];
    let timeout_result = tokio::time::timeout(timeout, async {
        loop {
            match local_socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    // 检查是否来自目标IP
                    if addr.ip() == peer_addr.ip() {
                        // 检查魔数
                        if len >= 4 && buf[0..4] == magic {
                            debug!("Received hole punching packet from {}", addr);
                            
                            // 连接到成功的地址
                            if addr != peer_addr {
                                info!("Hole punching succeeded with {} (different from original {})", addr, peer_addr);
                            } else {
                                info!("Hole punching succeeded with original address {}", addr);
                            }
                            
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    return Err(NatError::HolePunchingError(format!("Failed to receive packet: {}", e)));
                }
            }
        }
    }).await;
    
    match timeout_result {
        Ok(result) => result,
        Err(_) => Err(NatError::Timeout),
    }
}

/// 激进打洞策略
async fn aggressive_punching(
    local_socket: &tokio::net::UdpSocket,
    peer_addr: SocketAddr,
    timeout: Duration,
) -> Result<(), NatError> {
    // 激进打洞策略：尝试多个端口，使用多个套接字
    // 这在实际环境中很复杂，需要多线程或异步任务
    
    // 为简化示例，这里只实现一个增强版的单套接字打洞
    let ip = peer_addr.ip();
    let base_port = peer_addr.port();
    
    // 创建一组可能的目标地址
    let mut target_addrs = Vec::new();
    
    // 添加原始地址
    target_addrs.push(peer_addr);
    
    // 添加更多附近的端口
    for delta in -5..=5 {
        if delta == 0 {
            continue; // 跳过原始端口，已经添加
        }
        
        let port = (base_port as i32 + delta) as u16;
        target_addrs.push(SocketAddr::new(ip, port));
    }
    
    // 打洞魔数
    let magic = [0xB4, 0xD9, 0xF0, 0x0D];
    
    // 创建打洞数据包
    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(&magic);
    packet.extend_from_slice(&[0, 0, 0, 0]); // 预留4字节
    
    // 生成随机值
    let random_value: u32 = rand::thread_rng().gen();
    packet.extend_from_slice(&random_value.to_be_bytes());
    
    info!("Starting aggressive hole punching to {} and multiple nearby ports", peer_addr);
    
    // 发送多轮打洞包
    for round in 0..5 {
        for (i, target) in target_addrs.iter().enumerate() {
            // 更新序列号
            packet[4] = round as u8;
            packet[5] = i as u8;
            
            // 发送打洞包
            match local_socket.send_to(&packet, target).await {
                Ok(_) => {
                    debug!("Sent hole punching packet to {}", target);
                }
                Err(e) => {
                    warn!("Failed to send hole punching packet to {}: {}", target, e);
                }
            }
            
            // 短暂等待，避免过快发送
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        
        // 轮次之间的等待
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    
    // 等待接收打洞包或超时
    let mut buf = [0u8; 1024];
    let timeout_result = tokio::time::timeout(timeout, async {
        loop {
            match local_socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    // 检查是否来自目标IP
                    if addr.ip() == peer_addr.ip() {
                        // 检查魔数
                        if len >= 4 && buf[0..4] == magic {
                            debug!("Received hole punching packet from {}", addr);
                            
                            // 连接到成功的地址
                            if addr != peer_addr {
                                info!("Hole punching succeeded with {} (different from original {})", addr, peer_addr);
                            } else {
                                info!("Hole punching succeeded with original address {}", addr);
                            }
                            
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    return Err(NatError::HolePunchingError(format!("Failed to receive packet: {}", e)));
                }
            }
        }
    }).await;
    
    match timeout_result {
        Ok(result) => result,
        Err(_) => Err(NatError::Timeout),
    }
}
