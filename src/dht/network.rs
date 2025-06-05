use crate::dht::protocol::{DhtMessage, RequestContext, MessageRoute};
use crate::dht::KademliaError;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

/// DHT网络传输层
#[derive(Clone)]
pub struct DhtNetwork {
    /// UDP socket用于消息传输
    socket: Arc<UdpSocket>,
    
    /// 本地绑定地址
    local_addr: SocketAddr,
    
    /// 待处理的请求
    pending_requests: Arc<RwLock<HashMap<u64, (oneshot::Sender<DhtMessage>, RequestContext)>>>,
    
    /// 消息ID计数器
    message_id_counter: Arc<RwLock<u64>>,
    
    /// 入站消息通道
    inbound_tx: mpsc::Sender<MessageRoute>,
    
    /// 运行状态
    running: Arc<RwLock<bool>>,
}

impl DhtNetwork {
    /// 创建新的DHT网络实例
    pub async fn new(bind_addr: SocketAddr) -> Result<(Self, mpsc::Receiver<MessageRoute>), KademliaError> {
        // 创建UDP socket
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| KademliaError::OperationFailed(format!("Failed to bind UDP socket: {}", e)))?;
        
        let local_addr = socket.local_addr()
            .map_err(|e| KademliaError::OperationFailed(format!("Failed to get local address: {}", e)))?;
        
        info!("DHT network bound to {}", local_addr);
        
        // 创建消息通道
        let (inbound_tx, inbound_rx) = mpsc::channel(1000);
        
        let network = Self {
            socket: Arc::new(socket),
            local_addr,
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            message_id_counter: Arc::new(RwLock::new(1)),
            inbound_tx,
            running: Arc::new(RwLock::new(false)),
        };
        
        Ok((network, inbound_rx))
    }
    
    /// 启动网络监听
    pub async fn start(&self) -> Result<(), KademliaError> {
        // 标记为运行状态
        {
            let mut running = self.running.write().unwrap();
            *running = true;
        }
        
        // 启动接收任务
        self.spawn_receive_task();
        
        // 启动清理任务
        self.spawn_cleanup_task();
        
        info!("DHT network started on {}", self.local_addr);
        Ok(())
    }
    
    /// 停止网络
    pub async fn stop(&self) -> Result<(), KademliaError> {
        {
            let mut running = self.running.write().unwrap();
            *running = false;
        }
        
        info!("DHT network stopped");
        Ok(())
    }
    
    /// 发送消息并等待响应
    pub async fn send_request(
        &self,
        target_addr: SocketAddr,
        message: DhtMessage,
        timeout_duration: Duration,
    ) -> Result<DhtMessage, KademliaError> {
        let message_id = self.generate_message_id();
        
        // 创建响应通道
        let (response_tx, response_rx) = oneshot::channel();
        
        // 记录待处理请求
        {
            let mut pending = self.pending_requests.write().unwrap();
            let context = RequestContext::new(target_addr, timeout_duration);
            pending.insert(message_id, (response_tx, context));
        }
        
        // 序列化消息
        let message_bytes = message.to_bytes()
            .map_err(|e| KademliaError::OperationFailed(format!("Failed to serialize message: {}", e)))?;
        
        // 发送消息
        self.socket.send_to(&message_bytes, target_addr).await
            .map_err(|e| KademliaError::OperationFailed(format!("Failed to send message: {}", e)))?;
        
        debug!("Sent message {} to {}", message_id, target_addr);
        
        // 等待响应
        match timeout(timeout_duration, response_rx).await {
            Ok(Ok(response)) => {
                debug!("Received response for message {}", message_id);
                Ok(response)
            },
            Ok(Err(_)) => {
                // 通道被关闭
                Err(KademliaError::OperationFailed("Response channel closed".to_string()))
            },
            Err(_) => {
                // 超时
                self.remove_pending_request(message_id);
                Err(KademliaError::OperationFailed(format!("Request {} timed out", message_id)))
            }
        }
    }
    
    /// 发送响应消息（不等待回复）
    pub async fn send_response(
        &self,
        target_addr: SocketAddr,
        message: DhtMessage,
    ) -> Result<(), KademliaError> {
        let message_bytes = message.to_bytes()
            .map_err(|e| KademliaError::OperationFailed(format!("Failed to serialize message: {}", e)))?;
        
        self.socket.send_to(&message_bytes, target_addr).await
            .map_err(|e| KademliaError::OperationFailed(format!("Failed to send response: {}", e)))?;
        
        debug!("Sent response to {}", target_addr);
        Ok(())
    }
    
    /// 获取本地地址
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    
    /// 生成唯一的消息ID
    fn generate_message_id(&self) -> u64 {
        let mut counter = self.message_id_counter.write().unwrap();
        let id = *counter;
        *counter = counter.wrapping_add(1);
        id
    }
    
    /// 移除待处理的请求
    fn remove_pending_request(&self, message_id: u64) {
        let mut pending = self.pending_requests.write().unwrap();
        pending.remove(&message_id);
    }
    
    /// 启动接收任务
    fn spawn_receive_task(&self) {
        let socket = self.socket.clone();
        let pending_requests = self.pending_requests.clone();
        let inbound_tx = self.inbound_tx.clone();
        let running = self.running.clone();
        
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65536]; // 64KB缓冲区
            
            while *running.read().unwrap() {
                match socket.recv_from(&mut buffer).await {
                    Ok((len, addr)) => {
                        let data = &buffer[..len];
                        
                        // 尝试解析消息
                        match DhtMessage::from_bytes(data) {
                            Ok(message) => {
                                let message_id = message.message_id();
                                debug!("Received message {} from {}", message_id, addr);
                                
                                // 检查是否是对待处理请求的响应
                                let is_response = {
                                    let mut pending = pending_requests.write().unwrap();
                                    if let Some((response_tx, _)) = pending.remove(&message_id) {
                                        // 发送响应给等待的请求
                                        let _ = response_tx.send(message.clone());
                                        true
                                    } else {
                                        false
                                    }
                                };
                                
                                // 如果不是响应，则作为新的入站消息处理
                                if !is_response {
                                    let route = MessageRoute::new(addr, socket.local_addr().unwrap(), message);
                                    if let Err(e) = inbound_tx.send(route).await {
                                        warn!("Failed to send inbound message: {}", e);
                                    }
                                }
                            },
                            Err(e) => {
                                warn!("Failed to parse message from {}: {}", addr, e);
                            }
                        }
                    },
                    Err(e) => {
                        if *running.read().unwrap() {
                            error!("Failed to receive message: {}", e);
                        }
                    }
                }
            }
            
            debug!("DHT network receive task stopped");
        });
    }
    
    /// 启动清理任务，定期清理超时的请求
    fn spawn_cleanup_task(&self) {
        let pending_requests = self.pending_requests.clone();
        let running = self.running.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            while *running.read().unwrap() {
                interval.tick().await;
                
                // 清理超时的请求
                let mut to_remove = Vec::new();
                {
                    let pending = pending_requests.read().unwrap();
                    for (&message_id, (_, context)) in pending.iter() {
                        if context.is_expired() {
                            to_remove.push(message_id);
                        }
                    }
                }
                
                if !to_remove.is_empty() {
                    let mut pending = pending_requests.write().unwrap();
                    for message_id in to_remove {
                        pending.remove(&message_id);
                        debug!("Cleaned up expired request {}", message_id);
                    }
                }
            }
            
            debug!("DHT network cleanup task stopped");
        });
    }
}

/// 创建默认的DHT网络配置
pub fn create_default_network_config() -> (SocketAddr, Duration) {
    use std::net::{IpAddr, Ipv4Addr};
    
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0); // 绑定到随机端口
    let timeout = Duration::from_secs(5); // 5秒超时
    
    (bind_addr, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::dht::NodeId;
    use std::net::{IpAddr, Ipv4Addr};
    // use tokio::time::sleep;

    async fn create_test_network() -> (DhtNetwork, mpsc::Receiver<MessageRoute>) {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        DhtNetwork::new(bind_addr).await.unwrap()
    }

    fn create_test_node_info(port: u16) -> NodeInfo {
        let keypair = KeyPair::generate().unwrap();
        let id = NodeId::from_public_key(&keypair.public).unwrap();
        NodeInfo::new_signed(
            id,
            keypair.public,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)],
            1,
            false,
            &keypair.secret,
        ).unwrap()
    }

    #[tokio::test]
    async fn test_network_creation() {
        let (network, _) = create_test_network().await;
        assert!(network.local_addr.port() > 0);
    }

    #[tokio::test]
    async fn test_message_round_trip() {
        // 创建两个网络实例
        let (network1, _inbound1) = create_test_network().await;
        let (network2, mut inbound2) = create_test_network().await;
        
        // 启动网络
        network1.start().await.unwrap();
        network2.start().await.unwrap();
        
        let node1_info = create_test_node_info(network1.local_addr().port());
        let node2_info = create_test_node_info(network2.local_addr().port());
        
        // 发送ping消息
        let ping_message = DhtMessage::Ping {
            sender: node1_info.clone(),
            message_id: 123,
        };
        
        // 从network1发送到network2
        let network1_clone = network1.clone();
        let network2_addr = network2.local_addr();
        
        tokio::spawn(async move {
            // 等待一会儿接收消息
            if let Some(route) = inbound2.recv().await {
                match route.message {
                    DhtMessage::Ping { sender: _, message_id } => {
                        // 发送pong响应
                        let pong = DhtMessage::Pong {
                            sender: node2_info,
                            message_id,
                        };
                        let _ = network1_clone.send_response(route.from, pong).await;
                    },
                    _ => {}
                }
            }
        });
        
        // 发送请求并等待响应
        let result = network1.send_request(
            network2_addr,
            ping_message,
            Duration::from_secs(1)
        ).await;
        
        assert!(result.is_ok());
        match result.unwrap() {
            DhtMessage::Pong { message_id, .. } => {
                assert_eq!(message_id, 123);
            },
            _ => panic!("Expected Pong message"),
        }
        
        // 停止网络
        network1.stop().await.unwrap();
        network2.stop().await.unwrap();
    }
}