use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
// 移除未使用的导入
// use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use thiserror::Error;
use log::{debug, error, info, warn, trace};
use std::collections::VecDeque;
use rand::Rng;

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Connection closed")]
    ConnectionClosed,
    
    #[error("Timeout")]
    Timeout,
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
    
    #[error("Buffer overflow")]
    BufferOverflow,
}

/// 连接类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// 直接连接
    Direct,
    
    /// 中继连接
    Relayed,
    
    /// 通过WebRTC
    WebRTC,
}

/// 连接状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// 正在连接
    Connecting,
    
    /// 已建立连接
    Connected,
    
    /// 已断开连接
    Disconnected,
    
    /// 出错
    Error,
}

/// 流量统计
#[derive(Debug, Clone)]
pub struct TrafficStats {
    /// 接收的字节数
    pub bytes_received: u64,
    
    /// 发送的字节数
    pub bytes_sent: u64,
    
    /// 接收的数据包数
    pub packets_received: u64,
    
    /// 发送的数据包数
    pub packets_sent: u64,
    
    /// 丢失的数据包数
    pub packets_lost: u64,
    
    /// 平均往返时间（毫秒）
    pub average_rtt: f32,
    
    /// 创建时间
    pub created_at: Instant,
    
    /// 最后活动时间
    pub last_activity: Instant,
}

impl TrafficStats {
    /// 创建新的流量统计
    pub fn new() -> Self {
        let now = Instant::now();
        
        Self {
            bytes_received: 0,
            bytes_sent: 0,
            packets_received: 0,
            packets_sent: 0,
            packets_lost: 0,
            average_rtt: 0.0,
            created_at: now,
            last_activity: now,
        }
    }
    
    /// 更新流量统计
    pub fn update_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
        self.last_activity = Instant::now();
    }
    
    /// 更新流量统计
    pub fn update_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += 1;
        self.last_activity = Instant::now();
    }
    
    /// 更新往返时间
    pub fn update_rtt(&mut self, rtt: Duration) {
        let rtt_ms = rtt.as_secs_f32() * 1000.0;
        
        if self.average_rtt == 0.0 {
            self.average_rtt = rtt_ms;
        } else {
            // 使用EWMA（指数加权移动平均）更新RTT
            // EWMA = (1 - α) * 当前值 + α * 新样本值，α = 0.125 (1/8)是常用值
            self.average_rtt = 0.875 * self.average_rtt + 0.125 * rtt_ms;
        }
    }
    
    /// 报告分组丢失
    pub fn report_lost_packet(&mut self) {
        self.packets_lost += 1;
    }
    
    /// 获取分组丢失率
    pub fn loss_rate(&self) -> f32 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        
        self.packets_lost as f32 / self.packets_sent as f32
    }
    
    /// 获取连接持续时间
    pub fn duration(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }
    
    /// 获取空闲时间
    pub fn idle_duration(&self) -> Duration {
        Instant::now().duration_since(self.last_activity)
    }
    
    /// 获取发送速率 (bytes/s)
    pub fn send_rate(&self) -> f32 {
        let duration = self.duration().as_secs_f32();
        if duration > 0.0 {
            self.bytes_sent as f32 / duration
        } else {
            0.0
        }
    }
    
    /// 获取接收速率 (bytes/s)
    pub fn receive_rate(&self) -> f32 {
        let duration = self.duration().as_secs_f32();
        if duration > 0.0 {
            self.bytes_received as f32 / duration
        } else {
            0.0
        }
    }
}

/// P2P连接
#[derive(Clone)]
pub struct Connection {
    /// 套接字
    socket: Arc<UdpSocket>,
    
    /// 远程地址
    remote_addr: SocketAddr,
    
    /// 连接类型
    connection_type: ConnectionType,
    
    /// 连接状态
    state: Arc<RwLock<ConnectionState>>,
    
    /// 流量统计
    stats: Arc<RwLock<TrafficStats>>,
    
    /// 接收缓冲区
    receive_buffer: Arc<RwLock<VecDeque<Vec<u8>>>>,
    
    /// 发送缓冲区
    send_buffer: Arc<RwLock<VecDeque<Vec<u8>>>>,
    
    /// 最大传输单元
    mtu: usize,
    
    /// 保活间隔
    keepalive_interval: Duration,
    
    /// 连接ID
    connection_id: u64,
}

impl Connection {
    /// 创建新的连接
    pub fn new(
        socket: UdpSocket,
        connection_type: ConnectionType,
        mtu: usize,
        keepalive_interval: Duration,
    ) -> Self {
        // 获取远程地址
        let remote_addr = socket.peer_addr().unwrap_or_else(|_| {
            "0.0.0.0:0".parse().unwrap()
        });
        
        // 创建连接ID
        let connection_id = rand::thread_rng().gen();
        
        let connection = Self {
            socket: Arc::new(socket),
            remote_addr,
            connection_type,
            state: Arc::new(RwLock::new(ConnectionState::Connecting)),
            stats: Arc::new(RwLock::new(TrafficStats::new())),
            receive_buffer: Arc::new(RwLock::new(VecDeque::new())),
            send_buffer: Arc::new(RwLock::new(VecDeque::new())),
            mtu,
            keepalive_interval,
            connection_id,
        };
        
        // 启动背景任务
        connection.spawn_background_tasks();
        
        connection
    }
    
    /// 启动背景任务
    fn spawn_background_tasks(&self) {
        self.spawn_receiver_task();
        self.spawn_sender_task();
        self.spawn_keepalive_task();
    }
    
    /// 启动接收任务
    fn spawn_receiver_task(&self) {
        let socket = self.socket.clone();
        let state = self.state.clone();
        let stats = self.stats.clone();
        let receive_buffer = self.receive_buffer.clone();
        let connection_id = self.connection_id;
        
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536]; // 最大UDP数据包大小
            
            loop {
                // 检查连接状态
                if *state.read().await == ConnectionState::Disconnected ||
                   *state.read().await == ConnectionState::Error {
                    break;
                }
                
                // 接收数据
                match socket.recv(&mut buf).await {
                    Ok(n) => {
                        // 更新状态
                        if *state.read().await == ConnectionState::Connecting {
                            let mut state_guard = state.write().await;
                            *state_guard = ConnectionState::Connected;
                            
                            info!("Connection {} established", connection_id);
                        }
                        
                        // 更新统计信息
                        {
                            let mut stats_guard = stats.write().await;
                            stats_guard.update_received(n);
                        }
                        
                        // 复制接收到的数据
                        let data = buf[..n].to_vec();
                        
                        // 将数据添加到接收缓冲区
                        {
                            let mut buffer = receive_buffer.write().await;
                            buffer.push_back(data);
                            
                            // 限制缓冲区大小
                            if buffer.len() > 1000 {
                                buffer.pop_front();
                                warn!("Connection {} receive buffer overflow", connection_id);
                            }
                        }
                    },
                    Err(e) => {
                        // 处理错误
                        error!("Connection {} receiver error: {}", connection_id, e);
                        
                        // 更新状态
                        let mut state_guard = state.write().await;
                        *state_guard = ConnectionState::Error;
                        
                        break;
                    }
                }
            }
            
            debug!("Connection {} receiver task stopped", connection_id);
        });
    }
    
    /// 启动发送任务
    fn spawn_sender_task(&self) {
        let socket = self.socket.clone();
        let state = self.state.clone();
        let stats = self.stats.clone();
        let send_buffer = self.send_buffer.clone();
        let connection_id = self.connection_id;
        
        tokio::spawn(async move {
            loop {
                // 检查连接状态
                if *state.read().await == ConnectionState::Disconnected ||
                   *state.read().await == ConnectionState::Error {
                    break;
                }
                
                // 从发送缓冲区获取数据
                let data = {
                    let mut buffer = send_buffer.write().await;
                    buffer.pop_front()
                };
                
                if let Some(data) = data {
                    // 发送数据
                    match socket.send(&data).await {
                        Ok(n) => {
                            // 更新统计信息
                            let mut stats_guard = stats.write().await;
                            stats_guard.update_sent(n);
                            
                            trace!("Connection {} sent {} bytes", connection_id, n);
                        },
                        Err(e) => {
                            // 处理错误
                            error!("Connection {} sender error: {}", connection_id, e);
                            
                            // 更新状态
                            let mut state_guard = state.write().await;
                            *state_guard = ConnectionState::Error;
                            
                            break;
                        }
                    }
                } else {
                    // 没有数据要发送，等待一段时间
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            
            debug!("Connection {} sender task stopped", connection_id);
        });
    }
    
    /// 启动保活任务
    fn spawn_keepalive_task(&self) {
        let state = self.state.clone();
        let send_buffer = self.send_buffer.clone();
        let keepalive_interval = self.keepalive_interval;
        let connection_id = self.connection_id;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(keepalive_interval);
            
            loop {
                // 等待下一个间隔
                interval.tick().await;
                
                // 检查连接状态
                if *state.read().await == ConnectionState::Disconnected ||
                   *state.read().await == ConnectionState::Error {
                    break;
                }
                
                // 发送保活包
                if *state.read().await == ConnectionState::Connected {
                    // 简单的保活包：一个字节的0
                    let keepalive = vec![0u8];
                    
                    // 添加到发送缓冲区
                    let mut buffer = send_buffer.write().await;
                    buffer.push_back(keepalive);
                    
                    trace!("Connection {} sent keepalive", connection_id);
                }
            }
            
            debug!("Connection {} keepalive task stopped", connection_id);
        });
    }
    
    /// 发送数据
    pub async fn send(&self, data: &[u8]) -> Result<(), ConnectionError> {
        // 检查连接状态
        if *self.state.read().await == ConnectionState::Disconnected ||
           *self.state.read().await == ConnectionState::Error {
            return Err(ConnectionError::ConnectionClosed);
        }
        
        // 检查数据大小
        if data.len() > self.mtu {
            return Err(ConnectionError::BufferOverflow);
        }
        
        // 添加到发送缓冲区
        let mut buffer = self.send_buffer.write().await;
        buffer.push_back(data.to_vec());
        
        // 限制缓冲区大小
        if buffer.len() > 1000 {
            return Err(ConnectionError::BufferOverflow);
        }
        
        Ok(())
    }
    
    /// 接收数据
    pub async fn receive(&self) -> Result<Vec<u8>, ConnectionError> {
        // 检查连接状态
        if *self.state.read().await == ConnectionState::Disconnected ||
           *self.state.read().await == ConnectionState::Error {
            return Err(ConnectionError::ConnectionClosed);
        }
        
        // 从接收缓冲区获取数据
        let data = {
            let mut buffer = self.receive_buffer.write().await;
            buffer.pop_front()
        };
        
        match data {
            Some(data) => Ok(data),
            None => {
                // 没有数据可接收，等待一段时间
                tokio::time::sleep(Duration::from_millis(10)).await;
                Err(ConnectionError::Timeout)
            }
        }
    }
    
    /// 等待数据
    pub async fn wait_for_data(&self, timeout: Duration) -> Result<Vec<u8>, ConnectionError> {
        let start = Instant::now();
        
        loop {
            // 尝试接收数据
            match self.receive().await {
                Ok(data) => return Ok(data),
                Err(ConnectionError::Timeout) => {
                    // 检查是否超时
                    if start.elapsed() >= timeout {
                        return Err(ConnectionError::Timeout);
                    }
                    
                    // 等待一段时间再试
                    tokio::time::sleep(Duration::from_millis(10)).await;
                },
                Err(e) => return Err(e),
            }
        }
    }
    
    /// 断开连接
    pub async fn disconnect(&self) -> Result<(), ConnectionError> {
        // 更新状态
        let mut state_guard = self.state.write().await;
        *state_guard = ConnectionState::Disconnected;
        
        Ok(())
    }
    
    /// 获取连接状态
    pub async fn get_state(&self) -> ConnectionState {
        *self.state.read().await
    }
    
    /// 获取连接类型
    pub fn get_type(&self) -> ConnectionType {
        self.connection_type
    }
    
    /// 获取远程地址
    pub fn get_remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
    
    /// 获取连接统计信息
    pub async fn get_stats(&self) -> TrafficStats {
        self.stats.read().await.clone()
    }
    
    /// 获取MTU
    pub fn get_mtu(&self) -> usize {
        self.mtu
    }
    
    /// 获取连接ID
    pub fn get_id(&self) -> u64 {
        self.connection_id
    }
    
    /// 检查连接是否空闲
    pub async fn is_idle(&self, duration: Duration) -> bool {
        let stats = self.stats.read().await;
        stats.idle_duration() >= duration
    }
    
    /// 创建连接副本
    pub fn clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
            remote_addr: self.remote_addr,
            connection_type: self.connection_type,
            state: self.state.clone(),
            stats: self.stats.clone(),
            receive_buffer: self.receive_buffer.clone(),
            send_buffer: self.send_buffer.clone(),
            mtu: self.mtu,
            keepalive_interval: self.keepalive_interval,
            connection_id: self.connection_id,
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // 在实际应用中，可能需要使用阻塞方式发送关闭消息
        debug!("Connection {} dropped", self.connection_id);
    }
}
